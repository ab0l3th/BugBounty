#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scope_validator import is_in_scope, parse_scope_pattern

ROOT = Path(__file__).resolve().parent.parent
JOBS_DIR = ROOT / 'jobs'
RESULTS_DIR = ROOT / 'results'
DEFAULT_PROGRAM = 'american-airlines'


def read_scope_file(program_name: str = DEFAULT_PROGRAM) -> list[str]:
    scope_file = ROOT / 'programs' / program_name / 'scope.md'
    patterns: list[str] = []
    if scope_file.exists():
        for line in scope_file.read_text(encoding='utf-8').splitlines():
            value = line.strip()
            if value.startswith('- '):
                pattern = parse_scope_pattern(value[2:].strip())
                if pattern:
                    patterns.append(pattern)
    return patterns


def discover_jobs() -> list[Path]:
    if not JOBS_DIR.exists():
        return []
    return sorted(JOBS_DIR.glob('*.yaml')) + sorted(JOBS_DIR.glob('*.yml'))


def load_job(path: Path) -> dict:
    data = {'name': path.stem, 'program': DEFAULT_PROGRAM, 'targets': [], 'type': 'passive'}
    for line in path.read_text(encoding='utf-8').splitlines():
        clean = line.strip()
        if not clean or clean.startswith('#'):
            continue
        if clean.startswith('name:'):
            data['name'] = clean.split(':', 1)[1].strip()
        elif clean.startswith('program:'):
            data['program'] = clean.split(':', 1)[1].strip()
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
        'discovered': [],
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

    from passive_discovery import build_job_output
    passive = build_job_output()
    result['discovered'] = passive.get('discovered', [])
    result['status'] = passive.get('status', 'ok')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description='BugBounty passive job worker')
    parser.add_argument('--program', default=None, help='Program folder to use for scope validation')
    args = parser.parse_args()

    jobs = discover_jobs()
    if args.program:
        jobs = [path for path in jobs if load_job(path).get('program') == args.program]

    all_results = []
    for job_path in jobs:
        job = load_job(job_path)
        allowed_scope = read_scope_file(job.get('program', DEFAULT_PROGRAM))
        result = run_passive_job(job, allowed_scope)
        if not RESULTS_DIR.exists():
            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = RESULTS_DIR / f"{job_path.stem}.json"
        out_path.write_text(json.dumps(result, indent=2), encoding='utf-8')
        all_results.append(result)

    print(json.dumps(all_results, indent=2))


if __name__ == '__main__':
    main()
