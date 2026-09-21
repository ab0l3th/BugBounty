#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / 'results'
STATE_DIR = RESULTS_DIR / '.state'
WORKER_SCRIPT = ROOT / 'automation' / 'worker.py'


def run_worker() -> list[dict]:
    result = subprocess.run(
        [sys.executable, str(WORKER_SCRIPT)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    combined = (result.stdout or '').strip()
    if result.returncode != 0:
        raise RuntimeError(combined or 'Worker failed without output.')
    payload = json.loads(combined)
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return [payload]
    raise RuntimeError('Worker returned an unexpected payload format.')


def save_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding='utf-8')


def merge_result_payloads(previous: dict | None, current: dict) -> dict:
    if not previous:
        return current
    if not isinstance(previous, dict) or not isinstance(current, dict):
        return current

    def merge_assets(rows_a: list[dict], rows_b: list[dict]) -> list[dict]:
        merged: dict[str, dict] = {}
        for row in rows_a + rows_b:
            if not isinstance(row, dict):
                continue
            domain = row.get('domain')
            if not domain:
                continue
            existing = merged.setdefault(domain, {
                'domain': domain,
                'status': row.get('status', 'in_scope'),
                'source': '',
                'sources': [],
                'source_count': 0,
                'evidence': [],
            })
            sources = list(dict.fromkeys((existing.get('sources', []) or []) + (row.get('sources', []) or [])))
            evidence = existing.get('evidence', []) + row.get('evidence', [])
            deduped = {}
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                key = (item.get('source', ''), item.get('url', ''))
                deduped[key] = item
            existing.update({
                'domain': domain,
                'status': row.get('status', existing.get('status', 'in_scope')),
                'source': ', '.join(sources),
                'sources': sources,
                'source_count': len(sources),
                'evidence': list(deduped.values()),
            })
        return [merged[name] for name in sorted(merged)]

    discovered = sorted(set(previous.get('discovered', [])) | set(current.get('discovered', [])))
    targets = list(dict.fromkeys((previous.get('targets', []) or []) + (current.get('targets', []) or [])))
    merged = dict(current)
    merged['discovered'] = discovered
    merged['targets'] = targets
    merged['assets'] = merge_assets(previous.get('assets', []), current.get('assets', []))
    merged['source_count'] = len({source for row in merged['assets'] for source in row.get('sources', [])})
    if not merged.get('job'):
        merged['job'] = previous.get('job', current.get('job'))
    if not merged.get('program'):
        merged['program'] = previous.get('program', current.get('program'))
    return merged


def diff_changed(current: dict, previous: dict) -> bool:
    return current != previous


def send_notification(job: str, payload: dict) -> None:
    webhook = os.environ.get('BUGBOUNTY_WEBHOOK_URL')
    if not webhook:
        print(f'NOTIFY: {job} changed')
        print(json.dumps(payload, indent=2))
        return

    data = json.dumps({
        'event': 'bugbounty_result_change',
        'job': job,
        'payload': payload,
    }).encode('utf-8')

    req = urllib.request.Request(
        webhook,
        data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()


def main() -> None:
    current_jobs = run_worker()
    for current in current_jobs:
        job_name = current.get('job', 'unknown-job')
        result_file = RESULTS_DIR / f'{job_name}.json'
        previous_result = None
        if result_file.exists():
            previous_result = json.loads(result_file.read_text(encoding='utf-8'))
        merged_current = merge_result_payloads(previous_result, current)
        save_json(result_file, merged_current)

        state_file = STATE_DIR / f'{job_name}.json'
        previous = None
        if state_file.exists():
            previous = json.loads(state_file.read_text(encoding='utf-8'))

        if previous is None:
            save_json(state_file, merged_current)
            print(f'Initial state saved for {job_name}.')
            continue

        if diff_changed(merged_current, previous):
            send_notification(job_name, merged_current)
            print(f'Change detected for {job_name}. Notification sent.')
        else:
            print(f'No change detected for {job_name}.')

        save_json(state_file, merged_current)


if __name__ == '__main__':
    main()
