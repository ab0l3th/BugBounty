#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlsplit

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
    'vhost-discovery-shared-infra': {'step': 5, 'depends_on': ['service-enumeration-live-hosts']},
    'directory-enumeration-live-hosts': {'step': 6, 'depends_on': ['service-enumeration-live-hosts', 'vhost-discovery-shared-infra']},
    'application-security-testing': {'step': 7, 'depends_on': ['directory-enumeration-live-hosts']},
    'api-endpoint-testing': {'step': 8, 'depends_on': ['directory-enumeration-live-hosts']},
}

# Jobs that make live connections to targets and must not run in the default passive-only mode.
ACTIVE_JOBS = {'confirm-live-web-assets', 'service-enumeration-live-hosts', 'vhost-discovery-shared-infra', 'directory-enumeration-live-hosts', 'application-security-testing', 'api-endpoint-testing'}

# Statuses that count as a completed job for dependency gating and re-run skipping.
COMPLETED_STATUSES = {'completed', 'ok', 'no_new_assets', 'no_in_scope_targets', 'no_shared_infra', 'no_paths', 'no_findings', 'no_activity'}


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
    if status in (COMPLETED_STATUSES | {'waiting_on_dependencies'}) or job_state in {'completed', 'queued', 'running', 'waiting_on_dependencies'}:
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
                    parts = urlsplit(url)
                    port = parts.port or (443 if parts.scheme == 'https' else 80)
                    source = str(server).strip() or f'{parts.scheme}/{code}'
                    attempt['status'] = 'open'
                    attempt['status_code'] = code
                    attempt['server'] = str(server)
                    attempt['port'] = port
                    attempt['source'] = source
                    rows.append({
                        'url': url,
                        'port': port,
                        'status_code': code,
                        'server': str(server),
                        'service_type': 'http',
                        'source': source,
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
        record_sources = list(dict.fromkeys(
            [classification] + [f'{row["service_type"]}:{row["port"]}' for row in rows]
        ))
        service_record = {
            'domain': host,
            'status': 'enumerated',
            'kind': classification,
            'ports': open_ports,
            'alternate_hosts': [],
            'source': classification,
            'sources': record_sources,
            'source_count': len(open_ports),
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


def _resolve_host_ips(host: str) -> set[str]:
    host = host.strip().strip('.')
    if not host:
        return set()
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError, UnicodeError):
        return set()
    return {info[4][0] for info in infos if info and info[4]}


# Server banners that indicate a CDN/proxy is fronting the host.
_PROXY_BANNERS = ('cloudfront', 'cloudflare', 'akamai', 'fastly', 'nginx', 'envoy', 'haproxy', 'varnish', 'incapsula')


def _asset_is_proxy_fronted(asset: dict) -> bool:
    if str(asset.get('kind', '')).lower() == 'reverse-proxy':
        return True
    for row in asset.get('evidence', []) or []:
        if isinstance(row, dict) and any(b in str(row.get('server', '')).lower() for b in _PROXY_BANNERS):
            return True
    return False


def _select_vhost_candidates(service_assets: list[dict]) -> list[dict]:
    """Only hosts with evidence of shared infrastructure: co-located on one IP, or proxy/CDN fronted."""
    hosts = [a.get('domain') for a in service_assets if isinstance(a, dict) and a.get('domain')]
    ip_to_hosts: dict[str, set[str]] = {}
    host_ips: dict[str, set[str]] = {}
    for host in hosts:
        ips = _resolve_host_ips(host)
        host_ips[host] = ips
        for ip in ips:
            ip_to_hosts.setdefault(ip, set()).add(host)

    proxy_hosts = {a.get('domain') for a in service_assets if isinstance(a, dict) and _asset_is_proxy_fronted(a)}

    candidates: list[dict] = []
    for asset in service_assets:
        if not isinstance(asset, dict):
            continue
        host = asset.get('domain')
        if not host:
            continue
        co_hosted = sorted({
            other
            for ip in host_ips.get(host, set())
            for other in ip_to_hosts.get(ip, set())
            if other != host
        })
        shared_ip = next((ip for ip in host_ips.get(host, set()) if len(ip_to_hosts.get(ip, set())) > 1), None)
        if shared_ip:
            candidates.append({
                'domain': host,
                'reason': 'shared-ip',
                'shared_ip': shared_ip,
                'co_hosted': co_hosted,
            })
        elif host in proxy_hosts:
            candidates.append({
                'domain': host,
                'reason': 'proxy-fronted',
                'shared_ip': None,
                'co_hosted': co_hosted,
            })
    return candidates


def _probe_vhost(ip: str, host_header: str, scheme: str = 'https') -> dict:
    """Request an IP with a specific Host header and return a small response signature."""
    url = f'{scheme}://{ip}'
    req = urllib_request.Request(url, headers={'User-Agent': 'BugBountyPassiveRecon/1.0', 'Host': host_header}, method='GET')
    try:
        with urllib_request.urlopen(req, timeout=8) as resp:
            code = getattr(resp, 'status', resp.getcode())
            body = resp.read(4096)
            headers = getattr(resp, 'headers', {})
            server = headers.get('Server', '') if hasattr(headers, 'get') else ''
            return {
                'host_header': host_header,
                'ip': ip,
                'status_code': code,
                'length': len(body),
                'server': str(server),
                'ok': True,
            }
    except (urllib_error.HTTPError, urllib_error.URLError, ValueError, OSError) as exc:
        return {'host_header': host_header, 'ip': ip, 'ok': False, 'error': str(exc)}


def _run_vhost_discovery(service_assets: list[dict]) -> dict:
    candidates = _select_vhost_candidates(service_assets)
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    assets: list[dict] = []
    max_workers = min(8, max(1, len(candidates)))

    def investigate(candidate: dict) -> dict:
        thread_name = threading.current_thread().name
        host = candidate['domain']
        ip = candidate.get('shared_ip')
        evidence: list[dict] = []
        # For shared-IP candidates, confirm name-based virtual hosting using only in-scope co-hosted names.
        if ip:
            for header_host in [host] + candidate.get('co_hosted', []):
                sig = _probe_vhost(ip, header_host)
                evidence.append(sig)
                probe_log.append({'thread_id': thread_name, 'host': host, 'ip': ip, 'host_header': header_host, 'status': 'checked', 'timestamp': time.time()})
        distinct = len({(row.get('status_code'), row.get('length')) for row in evidence if row.get('ok')})
        record = {
            'domain': host,
            'status': 'vhost_confirmed' if distinct > 1 else 'vhost_candidate',
            'kind': candidate['reason'],
            'shared_ip': ip,
            'co_hosted': candidate.get('co_hosted', []),
            'source': 'vhost',
            'sources': ['vhost'],
            'source_count': 1,
            'evidence': evidence,
        }
        assets.append(record)
        thread_status.append({'thread_id': thread_name, 'host': host, 'status': record['status'], 'reason': candidate['reason'], 'timestamp': time.time()})
        return record

    if not candidates:
        return {'discovered': [], 'assets': [], 'probe_log': [], 'thread_status': [], 'threads': 0, 'candidates': 0}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(investigate, candidate) for candidate in candidates]
        for future in as_completed(futures):
            future.result()

    return {
        'discovered': sorted(row['domain'] for row in assets),
        'assets': sorted(assets, key=lambda r: r['domain']),
        'probe_log': probe_log,
        'thread_status': thread_status,
        'threads': max_workers,
        'candidates': len(candidates),
    }


# Curated app-root paths; targeted, not a broad brute-force wordlist.
DEFAULT_CONTENT_WORDLIST = [
    '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
    '/admin', '/login', '/api', '/api/', '/docs', '/health', '/status',
    '/server-status', '/actuator', '/actuator/health', '/metrics',
    '/backup', '/config', '/.env', '/.git/HEAD', '/swagger.json',
    '/openapi.json', '/graphql', '/wp-admin', '/wp-login.php',
]

# HTTP statuses that indicate a path exists or is worth noting.
_INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}


def _directory_enumeration(hosts: list[str], *, wordlist: list[str] | None = None, use_external_tools: bool = False) -> dict:
    deduped_hosts = sorted(set(hosts))
    paths = list(dict.fromkeys(wordlist or DEFAULT_CONTENT_WORDLIST))
    assets: list[dict] = []
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    max_workers = min(8, max(1, len(deduped_hosts)))
    headers = {'User-Agent': 'BugBountyPassiveRecon/1.0'}

    def scan_host(host: str) -> dict:
        thread_name = threading.current_thread().name
        base = f'https://{host}'
        found: list[dict] = []
        for path in paths:
            url = base + path
            try:
                req = urllib_request.Request(url, headers=headers, method='GET')
                with urllib_request.urlopen(req, timeout=8) as resp:
                    code = getattr(resp, 'status', resp.getcode())
                    body = resp.read(2048)
                    length = len(body) if body else 0
            except urllib_error.HTTPError as exc:
                code = exc.code
                length = 0
            except (urllib_error.URLError, ValueError, OSError):
                continue
            if code in _INTERESTING_STATUS:
                entry = {'path': path, 'status_code': code, 'length': length, 'url': url}
                found.append(entry)
                probe_log.append({'thread_id': thread_name, 'host': host, 'path': path, 'status_code': code, 'status': 'found', 'timestamp': time.time()})
        record = {
            'domain': host,
            'status': 'paths_found' if found else 'no_paths',
            'kind': 'content',
            'ports': [],
            'paths': found,
            'source': 'dir-enum',
            'sources': ['dir-enum'],
            'source_count': len(found),
            'evidence': [{'source': 'dir-enum', 'url': row['url'], 'status_code': row['status_code']} for row in found],
        }
        assets.append(record)
        thread_status.append({'thread_id': thread_name, 'host': host, 'status': record['status'], 'found': len(found), 'timestamp': time.time()})
        return record

    if not deduped_hosts:
        return {'discovered': [], 'assets': [], 'probe_log': [], 'thread_status': [], 'threads': 0}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_host, host) for host in deduped_hosts]
        for future in as_completed(futures):
            future.result()

    hits = [a for a in assets if a['paths']]
    return {
        'discovered': sorted(a['domain'] for a in hits),
        'assets': sorted(assets, key=lambda r: r['domain']),
        'probe_log': probe_log,
        'thread_status': thread_status,
        'threads': max_workers,
    }


def _fetch_headers_body(url: str, *, extra_headers: dict | None = None, method: str = 'GET', data=None, timeout: int = 8) -> tuple[int, dict, str]:
    """Single HTTP fetch returning (status, lowercased-headers, text). Non-destructive."""
    headers = {'User-Agent': 'BugBountyPassiveRecon/1.0'}
    if extra_headers:
        headers.update(extra_headers)
    body_bytes = data.encode('utf-8') if isinstance(data, str) else data
    req = urllib_request.Request(url, data=body_bytes, headers=headers, method=method)
    with urllib_request.urlopen(req, timeout=timeout) as resp:
        code = getattr(resp, 'status', resp.getcode())
        raw = resp.read(8192)
        hdrs: dict = {}
        rh = getattr(resp, 'headers', None)
        if rh is not None and hasattr(rh, 'items'):
            hdrs = {str(k).lower(): str(v) for k, v in rh.items()}
        text = raw.decode('utf-8', 'replace') if isinstance(raw, (bytes, bytearray)) else str(raw)
        return code, hdrs, text


# --- Step 7: application security (non-destructive misconfiguration/exposure detection) ---
_SECURITY_HEADERS = [
    'content-security-policy', 'strict-transport-security', 'x-frame-options',
    'x-content-type-options', 'referrer-policy', 'permissions-policy',
]
_ERROR_SIGNATURES = (
    'traceback (most recent call last)', 'exception in thread', 'java.lang.',
    'sqlstate', 'stack trace', 'syntaxerror', 'fatal error:', 'undefined index',
)


def _application_security_tests(hosts: list[str], *, use_external_tools: bool = False) -> dict:
    deduped_hosts = sorted(set(hosts))
    assets: list[dict] = []
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    max_workers = min(8, max(1, len(deduped_hosts)))

    def test_host(host: str) -> dict:
        thread_name = threading.current_thread().name
        url = f'https://{host}'
        findings: list[dict] = []
        try:
            code, hdrs, body = _fetch_headers_body(url)
        except urllib_error.HTTPError as exc:
            code = exc.code
            hdrs = {str(k).lower(): str(v) for k, v in (exc.headers.items() if exc.headers else [])}
            body = ''
        except (urllib_error.URLError, ValueError, OSError) as exc:
            record = {'domain': host, 'status': 'no_response', 'kind': 'app-test', 'ports': [], 'findings': [], 'source': 'app-test', 'sources': ['app-test'], 'source_count': 0, 'evidence': [], 'error': str(exc)}
            assets.append(record)
            thread_status.append({'thread_id': thread_name, 'host': host, 'status': 'no_response', 'timestamp': time.time()})
            return record

        missing = [h for h in _SECURITY_HEADERS if h not in hdrs]
        if missing:
            findings.append({'type': 'missing_security_headers', 'detail': missing, 'severity': 'low'})
        for header in ('server', 'x-powered-by', 'x-aspnet-version'):
            if hdrs.get(header):
                findings.append({'type': 'tech_disclosure', 'detail': f'{header}: {hdrs[header]}', 'severity': 'info'})
        set_cookie = hdrs.get('set-cookie', '')
        if set_cookie:
            lowered = set_cookie.lower()
            flags = [name for name, token in (('missing Secure', 'secure'), ('missing HttpOnly', 'httponly'), ('missing SameSite', 'samesite')) if token not in lowered]
            if flags:
                findings.append({'type': 'insecure_cookie', 'detail': flags, 'severity': 'low'})
        if any(sig in body.lower() for sig in _ERROR_SIGNATURES):
            findings.append({'type': 'error_disclosure', 'detail': 'stack trace or error signature in response', 'severity': 'medium'})

        # CORS reflection check with an untrusted Origin (read-only).
        try:
            _, cors_hdrs, _ = _fetch_headers_body(url, extra_headers={'Origin': 'https://evil.example'})
            acao = cors_hdrs.get('access-control-allow-origin', '')
            acac = cors_hdrs.get('access-control-allow-credentials', '')
            if acao == 'https://evil.example' or (acao == '*' and acac.lower() == 'true'):
                findings.append({'type': 'cors_misconfig', 'detail': f'ACAO={acao} ACAC={acac}', 'severity': 'medium'})
                probe_log.append({'thread_id': thread_name, 'host': host, 'check': 'cors', 'status': 'misconfig', 'timestamp': time.time()})
        except Exception:
            pass

        record = {
            'domain': host,
            'status': 'findings' if findings else 'no_findings',
            'kind': 'app-test',
            'ports': [],
            'findings': findings,
            'source': 'app-test',
            'sources': ['app-test'],
            'source_count': len(findings),
            'evidence': [{'source': 'app-test', 'url': url, 'detail': f.get('type')} for f in findings],
        }
        assets.append(record)
        thread_status.append({'thread_id': thread_name, 'host': host, 'status': record['status'], 'findings': len(findings), 'timestamp': time.time()})
        return record

    if not deduped_hosts:
        return {'discovered': [], 'assets': [], 'probe_log': [], 'thread_status': [], 'threads': 0}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(test_host, host) for host in deduped_hosts]
        for future in as_completed(futures):
            future.result()

    hits = [a for a in assets if a.get('findings')]
    return {
        'discovered': sorted(a['domain'] for a in hits),
        'assets': sorted(assets, key=lambda r: r['domain']),
        'probe_log': probe_log,
        'thread_status': thread_status,
        'threads': max_workers,
    }


# --- Step 8: API endpoint testing (debug endpoints + unauthenticated data exposure signals) ---
_API_DEBUG_PATHS = [
    '/actuator', '/actuator/env', '/actuator/health', '/actuator/mappings', '/actuator/heapdump',
    '/debug', '/api/debug', '/v2/api-docs', '/v3/api-docs', '/openapi.json',
    '/swagger.json', '/swagger-ui.html', '/graphql', '/trace', '/console', '/__debug__',
]
_GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name}}}"}'


def _looks_like_data(content_type: str, body: str) -> bool:
    if 'json' in content_type.lower():
        return True
    stripped = body.strip()
    return stripped.startswith('{') or stripped.startswith('[')


def _api_endpoint_tests(hosts: list[str], *, use_external_tools: bool = False) -> dict:
    deduped_hosts = sorted(set(hosts))
    assets: list[dict] = []
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    max_workers = min(8, max(1, len(deduped_hosts)))

    def test_host(host: str) -> dict:
        thread_name = threading.current_thread().name
        findings: list[dict] = []
        openapi_paths: list[str] = []
        for path in _API_DEBUG_PATHS:
            url = f'https://{host}{path}'
            try:
                code, hdrs, body = _fetch_headers_body(url)
            except urllib_error.HTTPError as exc:
                code, hdrs, body = exc.code, {}, ''
            except (urllib_error.URLError, ValueError, OSError):
                continue
            if code == 200:
                exposes = _looks_like_data(hdrs.get('content-type', ''), body)
                findings.append({'type': 'debug_endpoint', 'path': path, 'status_code': code, 'exposes_data': bool(exposes), 'severity': 'high' if exposes else 'medium'})
                probe_log.append({'thread_id': thread_name, 'host': host, 'path': path, 'status_code': code, 'status': 'found', 'timestamp': time.time()})
                if path in ('/v2/api-docs', '/v3/api-docs', '/openapi.json', '/swagger.json') and exposes:
                    try:
                        spec = json.loads(body)
                        if isinstance(spec, dict) and isinstance(spec.get('paths'), dict):
                            openapi_paths = list(spec['paths'].keys())
                    except Exception:
                        pass

        # GraphQL introspection (read-only query).
        try:
            code, hdrs, body = _fetch_headers_body(f'https://{host}/graphql', extra_headers={'Content-Type': 'application/json'}, method='POST', data=_GRAPHQL_INTROSPECTION)
            if code == 200 and '__schema' in body:
                findings.append({'type': 'graphql_introspection', 'detail': 'introspection enabled', 'severity': 'medium'})
        except Exception:
            pass

        # Unauthenticated access to documented API endpoints (bounded, read-only GET).
        for doc_path in openapi_paths[:15]:
            if not isinstance(doc_path, str) or not doc_path.startswith('/') or '{' in doc_path:
                continue
            url = f'https://{host}{doc_path}'
            try:
                code, hdrs, body = _fetch_headers_body(url)
            except urllib_error.HTTPError as exc:
                code, hdrs, body = exc.code, {}, ''
            except (urllib_error.URLError, ValueError, OSError):
                continue
            if code == 200 and _looks_like_data(hdrs.get('content-type', ''), body):
                findings.append({'type': 'unauthenticated_endpoint', 'path': doc_path, 'status_code': code, 'severity': 'high'})

        record = {
            'domain': host,
            'status': 'findings' if findings else 'no_findings',
            'kind': 'api-test',
            'ports': [],
            'findings': findings,
            'source': 'api-test',
            'sources': ['api-test'],
            'source_count': len(findings),
            'evidence': [{'source': 'api-test', 'url': f'https://{host}{f.get("path", "")}', 'detail': f.get('type')} for f in findings],
        }
        assets.append(record)
        thread_status.append({'thread_id': thread_name, 'host': host, 'status': record['status'], 'findings': len(findings), 'timestamp': time.time()})
        return record

    if not deduped_hosts:
        return {'discovered': [], 'assets': [], 'probe_log': [], 'thread_status': [], 'threads': 0}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(test_host, host) for host in deduped_hosts]
        for future in as_completed(futures):
            future.result()

    hits = [a for a in assets if a.get('findings')]
    return {
        'discovered': sorted(a['domain'] for a in hits),
        'assets': sorted(assets, key=lambda r: r['domain']),
        'probe_log': probe_log,
        'thread_status': thread_status,
        'threads': max_workers,
    }


def _load_result(name: str) -> dict:
    path = RESULTS_DIR / f'{name}.json'
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return {}


def _hosts_from_result(payload: dict) -> list[str]:
    hosts = list(payload.get('discovered', []) or [])
    if not hosts:
        hosts = [a.get('domain') for a in (payload.get('assets', []) or []) if isinstance(a, dict) and a.get('domain')]
    return [h for h in hosts if isinstance(h, str) and h.strip()]


def _combined_live_hosts() -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for name in ('service-enumeration-live-hosts', 'vhost-discovery-shared-infra'):
        for host in _hosts_from_result(_load_result(name)):
            if host not in seen:
                seen.add(host)
                merged.append(host)
    return merged


_API_PATH_HINTS = ('/api', '/swagger', '/graphql', '/openapi', '/v2/api-docs', '/v3/api-docs', '/actuator')


def _api_candidate_hosts() -> list[str]:
    """API hosts: step 4 api-gateway classifications plus step 6 hosts exposing API-ish paths."""
    candidates: list[str] = []
    seen: set[str] = set()

    for asset in _load_result('service-enumeration-live-hosts').get('assets', []) or []:
        if isinstance(asset, dict) and asset.get('kind') == 'api-gateway' and asset.get('domain'):
            host = asset['domain']
            if host not in seen:
                seen.add(host)
                candidates.append(host)

    for asset in _load_result('directory-enumeration-live-hosts').get('assets', []) or []:
        if not isinstance(asset, dict) or not asset.get('domain'):
            continue
        paths = [p.get('path', '') for p in (asset.get('paths', []) or []) if isinstance(p, dict)]
        if any(any(path.startswith(hint) for hint in _API_PATH_HINTS) for path in paths):
            host = asset['domain']
            if host not in seen:
                seen.add(host)
                candidates.append(host)
    return candidates


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
                'type': 'active',
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
            'type': 'active',
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
                'type': 'active',
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
        live_hosts = payload.get('discovered', []) or payload.get('assets', [])
        if isinstance(live_hosts, list) and live_hosts and isinstance(live_hosts[0], dict):
            live_hosts = [row.get('domain') for row in live_hosts if isinstance(row, dict) and row.get('domain')]
        deduped_hosts = sorted({host for host in live_hosts if isinstance(host, str) and host.strip()})
        enum_result = _enumerate_live_services(deduped_hosts, use_external_tools=use_external_tools)
        assets = enum_result.get('assets', [])
        response = {
            'job': job_name,
            'program': job.get('program', DEFAULT_PROGRAM),
            'type': 'active',
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

    if job_name == 'vhost-discovery-shared-infra':
        service_path = RESULTS_DIR / 'service-enumeration-live-hosts.json'
        if not service_path.exists():
            return {
                'job': job_name,
                'program': job.get('program', DEFAULT_PROGRAM),
                'type': 'active',
                'targets': [],
                'queued': [],
                'skipped': [],
                'status': 'waiting_on_dependencies',
                'job_state': 'waiting_on_dependencies',
                'discovered': [],
                'assets': [],
                'source_count': 0,
                'dependencies': ['service-enumeration-live-hosts'],
            }

        try:
            payload = json.loads(service_path.read_text(encoding='utf-8'))
        except Exception:
            payload = {}
        service_assets = [a for a in (payload.get('assets', []) or []) if isinstance(a, dict) and a.get('domain')]
        evaluated_hosts = sorted({a['domain'] for a in service_assets})
        vhost_result = _run_vhost_discovery(service_assets)
        assets = vhost_result.get('assets', [])
        response = {
            'job': job_name,
            'program': job.get('program', DEFAULT_PROGRAM),
            'type': 'active',
            'targets': evaluated_hosts,
            'queued': evaluated_hosts,
            'skipped': sorted(set(evaluated_hosts) - {row.get('domain') for row in assets}),
            'status': 'ok' if assets else 'no_shared_infra',
            'discovered': vhost_result.get('discovered', []),
            'assets': assets,
            'source_count': vhost_result.get('candidates', 0),
            'depends_on': ['service-enumeration-live-hosts'],
        }
        response['probe_log'] = vhost_result.get('probe_log', [])
        response['thread_status'] = vhost_result.get('thread_status', [])
        response['probe_threads'] = vhost_result.get('threads', 0)
        return response

    if job_name == 'directory-enumeration-live-hosts':
        step4_path = RESULTS_DIR / 'service-enumeration-live-hosts.json'
        step5_path = RESULTS_DIR / 'vhost-discovery-shared-infra.json'
        if not step4_path.exists() or not step5_path.exists():
            missing = [name for name, p in (
                ('service-enumeration-live-hosts', step4_path),
                ('vhost-discovery-shared-infra', step5_path),
            ) if not p.exists()]
            return {
                'job': job_name,
                'program': job.get('program', DEFAULT_PROGRAM),
                'type': 'active',
                'targets': [],
                'queued': [],
                'skipped': [],
                'status': 'waiting_on_dependencies',
                'job_state': 'waiting_on_dependencies',
                'discovered': [],
                'assets': [],
                'source_count': 0,
                'dependencies': missing,
            }

        combined: list[str] = []
        for path in (step4_path, step5_path):
            try:
                payload = json.loads(path.read_text(encoding='utf-8'))
            except Exception:
                continue
            hosts = payload.get('discovered', []) or []
            if not hosts:
                hosts = [a.get('domain') for a in (payload.get('assets', []) or []) if isinstance(a, dict) and a.get('domain')]
            combined.extend(hosts)

        deduped_hosts: list[str] = []
        seen: set[str] = set()
        for host in combined:
            if not host or host in seen:
                continue
            seen.add(host)
            if is_in_scope(host, allowed_scope):
                deduped_hosts.append(host)

        enum_result = _directory_enumeration(deduped_hosts, use_external_tools=use_external_tools)
        assets = enum_result.get('assets', [])
        response = {
            'job': job_name,
            'program': job.get('program', DEFAULT_PROGRAM),
            'type': 'active',
            'targets': deduped_hosts,
            'queued': deduped_hosts,
            'skipped': [host for host in sorted(set(combined)) if host and host not in deduped_hosts],
            'status': 'ok' if enum_result.get('discovered') else 'no_paths',
            'discovered': enum_result.get('discovered', []),
            'assets': assets,
            'source_count': sum(len(a.get('paths', [])) for a in assets),
            'depends_on': ['service-enumeration-live-hosts', 'vhost-discovery-shared-infra'],
        }
        response['probe_log'] = enum_result.get('probe_log', [])
        response['thread_status'] = enum_result.get('thread_status', [])
        response['probe_threads'] = enum_result.get('threads', 0)
        return response

    if job_name == 'application-security-testing':
        dep_path = RESULTS_DIR / 'directory-enumeration-live-hosts.json'
        if not dep_path.exists():
            return {
                'job': job_name, 'program': job.get('program', DEFAULT_PROGRAM), 'type': 'active',
                'targets': [], 'queued': [], 'skipped': [], 'status': 'waiting_on_dependencies',
                'job_state': 'waiting_on_dependencies', 'discovered': [], 'assets': [], 'source_count': 0,
                'dependencies': ['directory-enumeration-live-hosts'],
            }
        hosts = _combined_live_hosts()
        deduped_hosts = [h for h in hosts if is_in_scope(h, allowed_scope)]
        test_result = _application_security_tests(deduped_hosts, use_external_tools=use_external_tools)
        assets = test_result.get('assets', [])
        response = {
            'job': job_name, 'program': job.get('program', DEFAULT_PROGRAM), 'type': 'active',
            'targets': deduped_hosts, 'queued': deduped_hosts, 'skipped': [],
            'status': 'ok' if test_result.get('discovered') else 'no_findings',
            'discovered': test_result.get('discovered', []), 'assets': assets,
            'source_count': sum(len(a.get('findings', [])) for a in assets),
            'depends_on': ['directory-enumeration-live-hosts'],
        }
        response['probe_log'] = test_result.get('probe_log', [])
        response['thread_status'] = test_result.get('thread_status', [])
        response['probe_threads'] = test_result.get('threads', 0)
        return response

    if job_name == 'api-endpoint-testing':
        dep_path = RESULTS_DIR / 'directory-enumeration-live-hosts.json'
        if not dep_path.exists():
            return {
                'job': job_name, 'program': job.get('program', DEFAULT_PROGRAM), 'type': 'active',
                'targets': [], 'queued': [], 'skipped': [], 'status': 'waiting_on_dependencies',
                'job_state': 'waiting_on_dependencies', 'discovered': [], 'assets': [], 'source_count': 0,
                'dependencies': ['directory-enumeration-live-hosts'],
            }
        api_hosts = [h for h in _api_candidate_hosts() if is_in_scope(h, allowed_scope)]
        test_result = _api_endpoint_tests(api_hosts, use_external_tools=use_external_tools)
        assets = test_result.get('assets', [])
        response = {
            'job': job_name, 'program': job.get('program', DEFAULT_PROGRAM), 'type': 'active',
            'targets': api_hosts, 'queued': api_hosts, 'skipped': [],
            'status': 'ok' if test_result.get('discovered') else 'no_findings',
            'discovered': test_result.get('discovered', []), 'assets': assets,
            'source_count': sum(len(a.get('findings', [])) for a in assets),
            'depends_on': ['directory-enumeration-live-hosts'],
        }
        response['probe_log'] = test_result.get('probe_log', [])
        response['thread_status'] = test_result.get('thread_status', [])
        response['probe_threads'] = test_result.get('threads', 0)
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
    parser.add_argument('--job', default=None, help='Run only this single job (by job name or file stem) instead of the whole pipeline.')
    parser.add_argument('--force', action='store_true', help='Re-run completed jobs even when result files already exist.')
    parser.add_argument('--allow-active', action='store_true', help='Permit jobs that make live connections to targets (steps 3 and 4). Off by default for passive-only safety.')
    parser.add_argument('--external-probes', action='store_true', help='Enable curl/nmap/whatweb checks alongside Python HTTP probes for live asset confirmation.')
    args = parser.parse_args()

    # External probes are inherently active, so they imply active mode.
    allow_active = args.allow_active or args.external_probes

    jobs = discover_jobs()
    if args.program:
        jobs = [path for path in jobs if load_job(path).get('program') == args.program]
    if args.job:
        jobs = [path for path in jobs if path.stem == args.job or load_job(path).get('name') == args.job]

    all_results = []
    for job_path in jobs:
        job = load_job(job_path)
        if job.get('name') in ACTIVE_JOBS and not allow_active:
            lock_path = RUNNING_DIR / f'{job_path.stem}.lock'
            if lock_path.exists():
                lock_path.unlink()
            print(json.dumps({'job': job.get('name'), 'status': 'skipped_active', 'reason': 'requires --allow-active'}, indent=2))
            continue
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
                if state not in (COMPLETED_STATUSES | {'completed'}):
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
