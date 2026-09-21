#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

from scope_validator import is_in_scope, parse_scope_pattern

ROOT = Path(__file__).resolve().parent.parent
JOBS_DIR = ROOT / 'jobs'
RESULTS_DIR = ROOT / 'results'
RUNNING_DIR = RESULTS_DIR / '.running'
DEFAULT_PROGRAM = 'american-airlines'
WORKFLOW_SEQUENCE = {
    'aa-passive-discovery': {'step': 1, 'depends_on': []},
    'american-airlines-passive-dns': {'step': 2, 'depends_on': ['aa-passive-discovery']},
    'confirm-live-web-assets': {'step': 3, 'depends_on': ['aa-passive-discovery', 'american-airlines-passive-dns']},
    'service-enumeration-live-hosts': {'step': 4, 'depends_on': ['confirm-live-web-assets']},
}


def job_workflow_dependencies(job_name: str) -> list[str]:
    return list(WORKFLOW_SEQUENCE.get(job_name, {}).get('depends_on', []))


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
    job_paths = list(JOBS_DIR.glob('*.yaml')) + list(JOBS_DIR.glob('*.yml'))
    return sorted(job_paths, key=lambda path: (WORKFLOW_SEQUENCE.get(path.stem, {'step': 99})['step'], path.name))


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
        elif clean.startswith('order:'):
            try:
                data['order'] = int(clean.split(':', 1)[1].strip())
            except ValueError:
                data['order'] = 99
        elif clean.startswith('depends_on:'):
            value = clean.split(':', 1)[1].strip()
            if value:
                parsed = value.strip('[]')
                if parsed:
                    data['depends_on'] = [item.strip().strip("'\"") for item in parsed.split(',') if item.strip()]
                else:
                    data['depends_on'] = []
        elif clean.startswith('targets:'):
            continue
        elif clean.startswith('- '):
            data['targets'].append(clean[2:].strip().strip("'\""))
    if not data.get('depends_on'):
        data['depends_on'] = job_workflow_dependencies(data['name'])
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


def should_run_job(job_path: Path, *, force: bool = False) -> bool:
    if force:
        return True
    result_path = RESULTS_DIR / f'{job_path.stem}.json'
    if not result_path.exists():
        return True
    try:
        payload = json.loads(result_path.read_text(encoding='utf-8'))
    except Exception:
        return True
    status = payload.get('status')
    job_state = payload.get('job_state')
    if status in {'ok', 'no_new_assets', 'no_in_scope_targets', 'waiting_on_dependencies'} or job_state in {'completed', 'queued', 'running', 'waiting_on_dependencies'}:
        return False
    return True


def _http_probe_candidates(host: str) -> list[str]:
    host = host.strip().strip('.')
    if not host:
        return []
    candidates = [f'https://{host}', f'http://{host}']
    for port in (443, 8443, 80, 8080, 8000, 5000):
        if port in {80, 443}:
            continue
        candidates.append(f'https://{host}:{port}')
        candidates.append(f'http://{host}:{port}')
    return list(dict.fromkeys(candidates))


def _command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _run_external_probe_tool(host: str, url: str, tool_name: str) -> dict:
    if tool_name == 'curl':
        cmd = ['curl', '-sS', '-L', '--max-time', '5', '-o', '/dev/null', '-w', '%{http_code}', '--connect-timeout', '5', url]
    elif tool_name == 'nmap':
        cmd = ['nmap', '-Pn', '--top-ports', '20', '-T', 'polite', '-oG', '-', host]
    elif tool_name == 'whatweb':
        cmd = ['whatweb', '--no-errors', '--color=never', '--log-verbose', '-q', url]
    else:
        return {'tool': tool_name, 'ok': False, 'error': 'unsupported'}

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return {
            'tool': tool_name,
            'ok': result.returncode == 0,
            'returncode': result.returncode,
            'stdout': result.stdout.strip(),
            'stderr': result.stderr.strip(),
        }
    except (FileNotFoundError, subprocess.SubprocessError, ValueError) as exc:
        return {'tool': tool_name, 'ok': False, 'error': str(exc)}


def _probe_live_web_assets(hosts: list[str], *, use_external_tools: bool = False) -> dict:
    deduped_hosts = sorted(set(hosts))
    discovered: list[dict] = []
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    headers = {'User-Agent': 'BugBountyPassiveRecon/1.0'}
    max_workers = min(8, max(1, len(deduped_hosts)))

    def probe_host(host: str) -> dict:
        thread_name = threading.current_thread().name
        started = {'thread_id': thread_name, 'host': host, 'status': 'started', 'timestamp': time.time()}
        thread_status.append(started)
        for url in _http_probe_candidates(host):
            info = {
                'thread_id': thread_name,
                'host': host,
                'url': url,
                'status': 'checking',
                'timestamp': time.time(),
            }
            probe_log.append(info)
            try:
                req = urllib_request.Request(url, headers=headers, method='GET')
                with urllib_request.urlopen(req, timeout=8) as resp:
                    code = getattr(resp, 'status', resp.getcode())
                    if code and code < 400:
                        info['status'] = 'live'
                        info['status_code'] = code
                        discovered.append({
                            'domain': host,
                            'status': 'live',
                            'source': 'http-probe',
                            'sources': ['http-probe'],
                            'source_count': 1,
                            'evidence': [{
                                'source': 'http-probe',
                                'url': url,
                                'status_code': code,
                            }],
                        })
                        started['status'] = 'live'
                        started['live_url'] = url
                        started['status_code'] = code
                        thread_status.append({
                            'thread_id': thread_name,
                            'host': host,
                            'status': 'live',
                            'url': url,
                            'timestamp': time.time(),
                        })
                        if use_external_tools:
                            for tool_name in ('curl', 'nmap', 'whatweb'):
                                if _command_exists(tool_name):
                                    extra = _run_external_probe_tool(host, url, tool_name)
                                    info['external_tool'] = tool_name
                                    info['external_result'] = extra
                                    probe_log.append({
                                        'thread_id': thread_name,
                                        'host': host,
                                        'url': url,
                                        'status': 'external_check',
                                        'tool': tool_name,
                                        'external_result': extra,
                                        'timestamp': time.time(),
                                    })
                                    thread_status.append({
                                        'thread_id': thread_name,
                                        'host': host,
                                        'status': 'external_check',
                                        'tool': tool_name,
                                        'url': url,
                                        'timestamp': time.time(),
                                    })
                                    break
                        return {'host': host, 'status': 'live'}
                    info['status'] = 'http_error'
                    info['status_code'] = code
            except (urllib_error.HTTPError, urllib_error.URLError, ValueError, OSError) as exc:
                info['status'] = 'no_response'
                info['error'] = str(exc)
                if use_external_tools:
                    for tool_name in ('curl', 'nmap', 'whatweb'):
                        if not _command_exists(tool_name):
                            continue
                        extra = _run_external_probe_tool(host, url, tool_name)
                        info['external_tool'] = tool_name
                        info['external_result'] = extra
                        probe_log.append({
                            'thread_id': thread_name,
                            'host': host,
                            'url': url,
                            'status': 'external_check',
                            'tool': tool_name,
                            'external_result': extra,
                            'timestamp': time.time(),
                        })
                        thread_status.append({
                            'thread_id': thread_name,
                            'host': host,
                            'status': 'external_check',
                            'tool': tool_name,
                            'url': url,
                            'timestamp': time.time(),
                        })
                        break
        started['status'] = 'no_response'
        thread_status.append({
            'thread_id': thread_name,
            'host': host,
            'status': 'no_response',
            'timestamp': time.time(),
        })
        return {'host': host, 'status': 'no_response'}

    if not deduped_hosts:
        return {'discovered': [], 'probe_log': [], 'thread_status': [], 'assets': []}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(probe_host, host) for host in deduped_hosts]
        for future in as_completed(futures):
            future.result()

    return {
        'discovered': discovered,
        'probe_log': probe_log,
        'thread_status': thread_status,
        'assets': discovered,
        'threads': max_workers,
    }


def _service_enumeration_candidates(host: str) -> list[str]:
    host = host.strip().strip('.')
    if not host:
        return []
    ports = [80, 443, 8080, 8443, 8000, 5000]
    urls: list[str] = []
    for port in ports:
        if port in {80, 443}:
            scheme = 'https' if port == 443 else 'http'
            urls.append(f'{scheme}://{host}')
            continue
        urls.append(f'http://{host}:{port}')
        urls.append(f'https://{host}:{port}')
    return list(dict.fromkeys(urls))


def _classify_service(host: str, probe_rows: list[dict]) -> str:
    host_lower = host.lower()
    if 'api' in host_lower or any('api' in str(row.get('url', '')).lower() for row in probe_rows):
        return 'api-gateway'
    if any('admin' in str(row.get('url', '')).lower() or 'login' in str(row.get('url', '')).lower() for row in probe_rows):
        return 'app-server'
    if any('cloudfront' in str(row.get('server', '')).lower() or 'nginx' in str(row.get('server', '')).lower() or 'envoy' in str(row.get('server', '')).lower() or 'haproxy' in str(row.get('server', '')).lower() for row in probe_rows):
        return 'reverse-proxy'
    return 'static-site'


def _enumerate_live_services(hosts: list[str], *, use_external_tools: bool = False) -> dict:
    deduped_hosts = sorted(set(hosts))
    results: list[dict] = []
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    max_workers = min(8, max(1, len(deduped_hosts)))

    def enumerate_host(host: str) -> dict:
        thread_name = threading.current_thread().name
        rows: list[dict] = []
        for url in _service_enumeration_candidates(host):
            attempt = {
                'thread_id': thread_name,
                'host': host,
                'url': url,
                'status': 'checking',
                'timestamp': time.time(),
            }
            probe_log.append(attempt)
            try:
                req = urllib_request.Request(url, headers={'User-Agent': 'BugBountyPassiveRecon/1.0'}, method='GET')
                with urllib_request.urlopen(req, timeout=8) as resp:
                    code = getattr(resp, 'status', resp.getcode())
                    headers = getattr(resp, 'headers', {})
                    server = headers.get('Server', '') if hasattr(headers, 'get') else ''
                    attempt['status'] = 'open'
                    attempt['status_code'] = code
                    attempt['server'] = str(server)
                    rows.append({
                        'url': url,
                        'port': 443 if url.startswith('https://') and url.count(':') == 5 else 80,
                        'status_code': code,
                        'server': str(server),
                        'service_type': 'http'
                    })
            except Exception as exc:
                attempt['status'] = 'closed'
                attempt['error'] = str(exc)

        if use_external_tools and _command_exists('nmap'):
            try:
                result = subprocess.run(['nmap', '-Pn', '--top-ports', '20', '-T', 'polite', '-sV', host], capture_output=True, text=True, timeout=20)
                if result.stdout.strip():
                    probe_log.append({
                        'thread_id': thread_name,
                        'host': host,
                        'status': 'nmap',
                        'tool': 'nmap',
                        'stdout': result.stdout.strip(),
                        'timestamp': time.time(),
                    })
            except (FileNotFoundError, subprocess.SubprocessError, ValueError):
                pass

        open_ports = sorted({row['port'] for row in rows})
        classification = _classify_service(host, rows)
        service_record = {
            'domain': host,
            'status': 'enumerated',
            'kind': classification,
            'ports': open_ports,
            'alternate_hosts': [],
            'evidence': rows,
        }
        results.append(service_record)
        thread_status.append({
            'thread_id': thread_name,
            'host': host,
            'status': 'enumerated',
            'kind': classification,
            'ports': open_ports,
            'timestamp': time.time(),
        })
        return service_record

    if not deduped_hosts:
        return {'discovered': [], 'services': [], 'probe_log': [], 'thread_status': [], 'assets': []}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(enumerate_host, host) for host in deduped_hosts]
        for future in as_completed(futures):
            future.result()

    return {
        'discovered': [row['domain'] for row in results],
        'services': results,
        'probe_log': probe_log,
        'thread_status': thread_status,
        'assets': results,
        'threads': max_workers,
    }


def run_passive_job(job: dict, allowed_scope: list[str], *, use_external_tools: bool = False) -> dict:
    job_name = (job.get('name') or '').strip()
    job_type = (job.get('type', 'passive') or 'passive').lower()
    if job_type in {'github', 'repo', 'monitor'}:
        from github_monitor import github_activity
        repo = (job.get('targets') or [job.get('name', 'ab0l3th/BugBounty')])[0]
        return github_activity(repo)

    if job_name == 'confirm-live-web-assets':
        required_paths = [
            RESULTS_DIR / 'aa-passive-discovery.json',
            RESULTS_DIR / 'american-airlines-passive-dns.json',
        ]
        if any(not path.exists() for path in required_paths):
            return {
                'job': job_name,
                'program': job.get('program', DEFAULT_PROGRAM),
                'type': 'passive',
                'targets': [],
                'queued': [],
                'skipped': [],
                'status': 'waiting_on_dependencies',
                'job_state': 'waiting_on_dependencies',
                'discovered': [],
                'assets': [],
                'source_count': 0,
                'dependencies': ['aa-passive-discovery', 'american-airlines-passive-dns'],
            }

        merged_candidates: list[str] = []
        for path in required_paths:
            try:
                payload = json.loads(path.read_text(encoding='utf-8'))
            except Exception:
                continue
            discovered = payload.get('discovered', []) or []
            targets = payload.get('targets', []) or []
            merged_candidates.extend(discovered)
            merged_candidates.extend(targets)

        deduped_targets = []
        seen: set[str] = set()
        for host in merged_candidates:
            if not host or host in seen:
                continue
            seen.add(host)
            if is_in_scope(host, allowed_scope):
                deduped_targets.append(host)

        probe_result = _probe_live_web_assets(deduped_targets, use_external_tools=use_external_tools)
        live_assets = probe_result.get('assets', probe_result.get('discovered', [])) if isinstance(probe_result, dict) else probe_result
        deduped = {}
        for asset in live_assets:
            domain = asset['domain']
            existing = deduped.setdefault(domain, {
                'domain': domain,
                'status': 'live',
                'source': 'http-probe',
                'sources': ['http-probe'],
                'source_count': 1,
                'evidence': [],
            })
            existing['evidence'] += asset['evidence']
            existing['sources'] = list(dict.fromkeys(existing['sources'] + asset['sources']))
            existing['source_count'] = len(existing['sources'])
        ordered_assets = [deduped[host] for host in sorted(deduped)]
        response = {
            'job': job_name,
            'program': job.get('program', DEFAULT_PROGRAM),
            'type': 'passive',
            'targets': deduped_targets,
            'queued': deduped_targets,
            'skipped': [host for host in sorted(set(merged_candidates)) if host and host not in deduped_targets],
            'status': 'ok' if ordered_assets else 'no_new_assets',
            'discovered': sorted(deduped),
            'assets': ordered_assets,
            'source_count': sum(len(asset.get('sources', [])) for asset in ordered_assets),
            'depends_on': ['aa-passive-discovery', 'american-airlines-passive-dns'],
        }
        if isinstance(probe_result, dict):
            response['probe_log'] = probe_result.get('probe_log', [])
            response['thread_status'] = probe_result.get('thread_status', [])
            response['probe_threads'] = probe_result.get('threads', 0)
        return response

    if job_name == 'service-enumeration-live-hosts':
        live_assets_path = RESULTS_DIR / 'confirm-live-web-assets.json'
        if not live_assets_path.exists():
            return {
                'job': job_name,
                'program': job.get('program', DEFAULT_PROGRAM),
                'type': 'passive',
                'targets': [],
                'queued': [],
                'skipped': [],
                'status': 'waiting_on_dependencies',
                'job_state': 'waiting_on_dependencies',
                'discovered': [],
                'assets': [],
                'source_count': 0,
                'dependencies': ['confirm-live-web-assets'],
            }

        try:
            payload = json.loads(live_assets_path.read_text(encoding='utf-8'))
        except Exception:
            payload = {}
        live_hosts = payload.get('discovered', []) or payload.get('targets', []) or payload.get('assets', [])
        if isinstance(live_hosts, list) and live_hosts and isinstance(live_hosts[0], dict):
            live_hosts = [row.get('domain') for row in live_hosts if isinstance(row, dict) and row.get('domain')]
        deduped_hosts = sorted({host for host in live_hosts if isinstance(host, str) and host.strip()})
        enum_result = _enumerate_live_services(deduped_hosts, use_external_tools=use_external_tools)
        assets = enum_result.get('assets', [])
        response = {
            'job': job_name,
            'program': job.get('program', DEFAULT_PROGRAM),
            'type': 'passive',
            'targets': deduped_hosts,
            'queued': deduped_hosts,
            'skipped': [],
            'status': 'ok' if assets else 'no_new_assets',
            'discovered': [row.get('domain') for row in assets],
            'assets': assets,
            'source_count': sum(len(asset.get('ports', [])) for asset in assets),
            'depends_on': ['confirm-live-web-assets'],
        }
        response['probe_log'] = enum_result.get('probe_log', [])
        response['thread_status'] = enum_result.get('thread_status', [])
        response['probe_threads'] = enum_result.get('threads', 0)
        return response

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
    parser.add_argument('--force', action='store_true', help='Re-run completed jobs even when result files already exist.')
    parser.add_argument('--external-probes', action='store_true', help='Enable curl/nmap/whatweb checks alongside Python HTTP probes for live asset confirmation.')
    args = parser.parse_args()

    jobs = discover_jobs()
    if args.program:
        jobs = [path for path in jobs if load_job(path).get('program') == args.program]

    all_results = []
    for job_path in jobs:
        job = load_job(job_path)
        dependencies = job_workflow_dependencies(job.get('name'))
        if dependencies:
            pending = []
            for dependency in dependencies:
                dependency_path = RESULTS_DIR / f'{dependency}.json'
                if not dependency_path.exists():
                    pending.append(dependency)
                    continue
                try:
                    payload = json.loads(dependency_path.read_text(encoding='utf-8'))
                except Exception:
                    pending.append(dependency)
                    continue
                state = (payload.get('job_state') or payload.get('status') or '').lower()
                if state not in {'completed', 'ok', 'no_new_assets', 'no_in_scope_targets'}:
                    pending.append(dependency)
            if pending:
                print(json.dumps({'job': job.get('name'), 'status': 'waiting_on_dependencies', 'dependencies': pending}, indent=2))
                continue
        if not args.force and not should_run_job(job_path):
            continue
        RUNNING_DIR.mkdir(parents=True, exist_ok=True)
        lock_path = RUNNING_DIR / f'{job_path.stem}.lock'
        lock_path.write_text(str(time.time()), encoding='utf-8')
        try:
            allowed_scope = read_scope_file(job.get('program', DEFAULT_PROGRAM))
            result = run_passive_job(job, allowed_scope, use_external_tools=args.external_probes)
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
        finally:
            if lock_path.exists():
                lock_path.unlink()

    print(json.dumps(all_results, indent=2))


if __name__ == '__main__':
    main()
