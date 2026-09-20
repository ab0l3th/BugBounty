#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from scope_validator import is_in_scope, load_scope

ROOT = Path(__file__).resolve().parent.parent
JOBS_DIR = ROOT / 'jobs'
RESULTS_DIR = ROOT / 'results'
SCOPE_FILE = ROOT / 'programs' / 'american-airlines' / 'scope.md'


def read_scope_file() -> list[str]:
    patterns: list[str] = []
    if SCOPE_FILE.exists():
        for line in SCOPE_FILE.read_text(encoding='utf-8').splitlines():
            value = line.strip()
            if value.startswith('- '):
                patterns.append(value[2:].strip().strip("'\""))
    return patterns


def discover_jobs() -> list[Path]:
    if not JOBS_DIR.exists():
        return []
    return sorted(JOBS_DIR.glob('*.yaml')) + sorted(JOBS_DIR.glob('*.yml'))


def load_job(path: Path) -> dict:
    # A simple YAML-like parser for the repo's current schema; keep this minimal and explicit.
    # In a later step this should be replaced with PyYAML.
    data = {'name': path.stem, 'targets': [], 'type': 'passive'}
    for line in path.read_text(encoding='utf-8').splitlines():
        clean = line.strip()
        if not clean or clean.startswith('#'):
            continue
        if clean.startswith('name:'):
            data['name'] = clean.split(':', 1)[1].strip()
        elif clean.startswith('type:'):
            data['type'] = clean.split(':', 1)[1].strip()
        elif clean.startswith('targets:'):
            continue
        elif clean.startswith('- '):
            data['targets'].append(clean[2:].strip().strip("'\""))
    return data


def run_passive_job(job: dict, allowed_scope: list[str]) -> dict:
    result = {
        'job': job.get('name'),
        'type': job.get('type', 'passive'),
        'targets': [],
        'queued': [],
        'skipped': [],
        'status': 'ok',
    }
    for target in job.get('targets', []):
        if is_in_scope(target, allowed_scope):
            result['targets'].append(target)
            result['queued'].append(target)
        else:
            result['skipped'].append(target)
    if not result['queued']:
        result['status'] = 'no_in_scope_targets'
    return result


def main() -> None:
    allowed_scope = read_scope_file()
    for job_path in discover_jobs():
        job = load_job(job_path)
        result = run_passive_job(job, allowed_scope)
        if not RESULTS_DIR.exists():
            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = RESULTS_DIR / f"{job_path.stem}.json"
        out_path.write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
