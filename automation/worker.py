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


def run_passive_job(job: dict, allowed_scope: list[str]) -> dict:
    job_type = (job.get('type', 'passive') or 'passive').lower()
    if job_type in {'github', 'repo', 'monitor'}:
        from github_monitor import github_activity
        repo = (job.get('targets') or [job.get('name', 'ab0l3th/BugBounty')])[0]
        return github_activity(repo)

    result = {
        'job': job.get('name'),
        'program': job.get('program', DEFAULT_PROGRAM),
        'type': job.get('type', 'passive'),
        'targets': [],
        'queued': [],
        'skipped': [],
        'status': 'ok',
        'discovered': [],
        'assets': [],
        'source_count': 0,
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
    from passive_dns_enrichment import passive_dns_enrichment

    legacy = build_job_output()
    passive = passive_dns_enrichment(job.get('program', DEFAULT_PROGRAM))

    merged_assets: dict[str, dict] = {}
    for asset in legacy.get('assets', []):
        domain = asset.get('domain')
        if not domain:
            continue
        merged_assets[domain] = {
            'domain': domain,
            'status': asset.get('status', 'in_scope'),
            'source': asset.get('source', ''),
            'sources': list(dict.fromkeys(asset.get('sources', []))),
            'source_count': int(asset.get('source_count', len(asset.get('sources', [])))),
            'evidence': list(asset.get('evidence', [])),
        }

    for asset in passive.get('assets', []):
        domain = asset.get('domain')
        if not domain:
            continue
        existing = merged_assets.get(domain)
        if existing:
            existing_sources = list(dict.fromkeys(existing.get('sources', []) + asset.get('sources', [])))
            existing_evidence = existing.get('evidence', []) + asset.get('evidence', [])
            merged_assets[domain] = {
                'domain': domain,
                'status': 'in_scope',
                'source': ', '.join(existing_sources),
                'sources': existing_sources,
                'source_count': len(existing_sources),
                'evidence': list({(item.get('source'), item.get('url')): item for item in existing_evidence}.values()),
            }
        else:
            merged_assets[domain] = {
                'domain': domain,
                'status': asset.get('status', 'in_scope'),
                'source': asset.get('source', ''),
                'sources': list(dict.fromkeys(asset.get('sources', []))),
                'source_count': int(asset.get('source_count', len(asset.get('sources', [])))),
                'evidence': list(asset.get('evidence', [])),
            }

    discovered = sorted(merged_assets)
    ordered_assets = [merged_assets[domain] for domain in discovered]
    result.update({
        'enrichment_job': passive.get('job', result['job']),
        'enrichment_program': passive.get('program', result['program']),
        'targets': list(dict.fromkeys((legacy.get('targets', []) or result['targets']) + (passive.get('targets', []) or []))),
        'discovered': discovered,
        'assets': ordered_assets,
        'status': 'ok' if discovered else 'no_new_assets',
        'source_count': len({source for row in ordered_assets for source in row.get('sources', [])}),
    })
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
        previous = None
        if out_path.exists():
            try:
                previous = json.loads(out_path.read_text(encoding='utf-8'))
            except Exception:
                previous = None
        merged_result = merge_result_payloads(previous, result)
        out_path.write_text(json.dumps(merged_result, indent=2), encoding='utf-8')
        all_results.append(merged_result)

    print(json.dumps(all_results, indent=2))


if __name__ == '__main__':
    main()
