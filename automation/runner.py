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


def run_worker() -> dict:
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
    return payload


def save_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding='utf-8')


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
    current = run_worker()
    job_name = current.get('job', 'unknown-job')
    result_file = RESULTS_DIR / f'{job_name}.json'
    save_json(result_file, current)

    state_file = STATE_DIR / f'{job_name}.json'
    previous = None
    if state_file.exists():
        previous = json.loads(state_file.read_text(encoding='utf-8'))

    if previous is None:
        save_json(state_file, current)
        print(f'Initial state saved for {job_name}.')
        return

    if diff_changed(current, previous):
        send_notification(job_name, current)
        print(f'Change detected for {job_name}. Notification sent.')
    else:
        print(f'No change detected for {job_name}.')

    save_json(state_file, current)


if __name__ == '__main__':
    main()
