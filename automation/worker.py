#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import json
import os
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
REPORTS_DIR = RESULTS_DIR / 'reports'
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
    'port-scan-live-hosts': {'step': 9, 'depends_on': ['vhost-discovery-shared-infra', 'directory-enumeration-live-hosts', 'application-security-testing']},
}

# Jobs that make live connections to targets and must not run in the default passive-only mode.
ACTIVE_JOBS = {'confirm-live-web-assets', 'service-enumeration-live-hosts', 'vhost-discovery-shared-infra', 'directory-enumeration-live-hosts', 'application-security-testing', 'api-endpoint-testing', 'port-scan-live-hosts'}

# Statuses that count as a completed job for dependency gating and re-run skipping.
COMPLETED_STATUSES = {'completed', 'ok', 'no_new_assets', 'no_in_scope_targets', 'no_shared_infra', 'no_paths', 'no_findings', 'no_activity'}


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, '').strip())
        return value if value > 0 else default
    except (ValueError, TypeError):
        return default


# Resource guards to keep active runs from exhausting memory on large host sets. Tunable via env.
MAX_WORKERS = _env_int('BUGBOUNTY_MAX_WORKERS', 8)
MAX_HOSTS_PER_RUN = _env_int('BUGBOUNTY_MAX_HOSTS', 500)
MAX_LOG_ENTRIES = _env_int('BUGBOUNTY_MAX_LOG', 4000)


def _bounded_workers(count: int) -> int:
    return min(MAX_WORKERS, max(1, count))


def _cap_hosts(hosts: list[str]) -> tuple[list[str], bool]:
    """Bound the number of hosts processed in a single run to avoid runaway memory use."""
    if MAX_HOSTS_PER_RUN and len(hosts) > MAX_HOSTS_PER_RUN:
        return hosts[:MAX_HOSTS_PER_RUN], True
    return list(hosts), False


def _cap_log(entries: list) -> list:
    return entries[:MAX_LOG_ENTRIES] if MAX_LOG_ENTRIES and len(entries) > MAX_LOG_ENTRIES else entries


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.tmp')
    temporary.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    temporary.replace(path)


def _emit_progress(progress, snapshot: dict) -> None:
    if progress is None:
        return
    try:
        progress(snapshot)
    except Exception:
        pass


def _drain_futures(futures, log: list | None = None) -> None:
    """Consume thread futures, swallowing per-task exceptions so one failure isn't fatal."""
    for future in as_completed(futures):
        try:
            future.result()
        except Exception as exc:
            if log is not None:
                log.append({'status': 'error', 'error': str(exc), 'timestamp': time.time()})


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


def _result_for_write(job_name: str | None, previous: dict | None, current: dict) -> dict:
    """Active steps replace prior results; passive discovery accumulates across runs."""
    if job_name in ACTIVE_JOBS:
        return current
    return merge_result_payloads(previous, current)


def _lock_is_active(job_stem: str) -> bool:
    """True only if a lock exists and its PID is alive; stale locks are removed."""
    lock_path = RUNNING_DIR / f'{job_stem}.lock'
    if not lock_path.exists():
        return False
    try:
        content = lock_path.read_text(encoding='utf-8').strip()
    except OSError:
        return False
    try:
        pid = int(content)
    except ValueError:
        pid = None
    if pid and pid > 0:
        if pid == os.getpid():
            return True
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            _remove_lock(lock_path)
            return False
        except PermissionError:
            return True
        except OSError:
            return False
    try:
        age = time.time() - lock_path.stat().st_mtime
    except OSError:
        return False
    if age > 1800:
        _remove_lock(lock_path)
        return False
    return True


def _remove_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink()
    except OSError:
        pass


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
    # Only skip genuinely completed jobs; queued/waiting jobs should be picked up so the
    # pipeline can auto-advance once dependencies finish. Active in-flight runs are guarded
    # separately by a live lock check.
    if status in COMPLETED_STATUSES or job_state == 'completed':
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


def _response_final_url(resp, fallback: str) -> str:
    geturl = getattr(resp, 'geturl', None)
    if callable(geturl):
        try:
            return str(geturl())
        except Exception:
            pass
    return fallback


def _response_text(resp, limit: int) -> str:
    reader = getattr(resp, 'read', None)
    if not callable(reader):
        return ''
    try:
        body = reader(limit)
    except Exception:
        return ''
    return body.decode('utf-8', 'replace') if isinstance(body, (bytes, bytearray)) else str(body)


def _probe_live_web_assets(hosts: list[str], *, use_external_tools: bool = False, progress=None) -> dict:
    deduped_hosts = sorted(set(hosts))
    discovered: list[dict] = []
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    headers = {'User-Agent': 'BugBountyPassiveRecon/1.0'}
    max_workers = _bounded_workers(len(deduped_hosts))

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
                    final_url = _response_final_url(resp, url)
                    body_text = _response_text(resp, 2048)
                    if code and code < 400 and not _is_login_redirect(url, final_url, body_text):
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
                        _emit_progress(progress, {'targets': list(deduped_hosts), 'assets': list(discovered), 'discovered': [row['domain'] for row in discovered], 'probe_log': list(probe_log), 'thread_status': list(thread_status), 'threads': max_workers})
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
        _drain_futures(futures, probe_log)

    return {
        'discovered': discovered,
        'probe_log': _cap_log(probe_log),
        'thread_status': _cap_log(thread_status),
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


def _enumerate_live_services(hosts: list[str], *, use_external_tools: bool = False, progress=None) -> dict:
    deduped_hosts = sorted(set(hosts))
    results: list[dict] = []
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    max_workers = _bounded_workers(len(deduped_hosts))

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
                    body_text = _response_text(resp, 2048)
                    final_url = _response_final_url(resp, url)
                    if _is_login_redirect(url, final_url, body_text):
                        attempt['status'] = 'login_redirect'
                        continue
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
        _emit_progress(progress, {'targets': list(deduped_hosts), 'assets': list(results), 'discovered': [row['domain'] for row in results], 'probe_log': list(probe_log), 'thread_status': list(thread_status), 'threads': max_workers})
        return service_record

    if not deduped_hosts:
        return {'discovered': [], 'services': [], 'probe_log': [], 'thread_status': [], 'assets': []}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(enumerate_host, host) for host in deduped_hosts]
        _drain_futures(futures, probe_log)

    return {
        'discovered': [row['domain'] for row in results],
        'services': results,
        'probe_log': _cap_log(probe_log),
        'thread_status': _cap_log(thread_status),
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
    # IPv6 literals must be bracketed to form a valid URL authority.
    authority = f'[{ip}]' if ':' in ip and not ip.startswith('[') else ip
    url = f'{scheme}://{authority}'
    req = urllib_request.Request(url, headers={'User-Agent': 'BugBountyPassiveRecon/1.0', 'Host': host_header}, method='GET')
    try:
        with urllib_request.urlopen(req, timeout=8) as resp:
            code = getattr(resp, 'status', resp.getcode())
            body = resp.read(4096)
            headers = getattr(resp, 'headers', {})
            server = headers.get('Server', '') if hasattr(headers, 'get') else ''
            final_url = _response_final_url(resp, url)
            body_text = body.decode('utf-8', 'replace') if isinstance(body, (bytes, bytearray)) else str(body)
            if _is_login_redirect(url, final_url, body_text):
                return {'host_header': host_header, 'ip': ip, 'source': f'{host_header} (login redirect)', 'url': url, 'ok': False, 'status': 'login_redirect'}
            return {
                'host_header': host_header,
                'ip': ip,
                'status_code': code,
                'length': len(body),
                'server': str(server),
                'source': f'{host_header} → {code}',
                'url': url,
                'ok': True,
            }
    except (urllib_error.HTTPError, urllib_error.URLError, ValueError, OSError, http.client.HTTPException) as exc:
        return {'host_header': host_header, 'ip': ip, 'source': f'{host_header} (no response)', 'url': url, 'ok': False, 'error': str(exc)}


def _run_vhost_discovery(service_assets: list[dict], *, progress=None) -> dict:
    candidates = _select_vhost_candidates(service_assets)
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    assets: list[dict] = []
    max_workers = _bounded_workers(len(candidates))

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
        _emit_progress(progress, {'targets': [item['domain'] for item in candidates], 'assets': list(assets), 'discovered': [row['domain'] for row in assets], 'probe_log': list(probe_log), 'thread_status': list(thread_status), 'threads': max_workers})
        return record

    if not candidates:
        return {'discovered': [], 'assets': [], 'probe_log': [], 'thread_status': [], 'threads': 0, 'candidates': 0}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(investigate, candidate) for candidate in candidates]
        for future in as_completed(futures):
            # A single probe failure must never abort the whole run.
            try:
                future.result()
            except Exception as exc:
                probe_log.append({'status': 'error', 'error': str(exc), 'timestamp': time.time()})

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


def _directory_enumeration(hosts: list[str], *, wordlist: list[str] | None = None, use_external_tools: bool = False, progress=None) -> dict:
    deduped_hosts = sorted(set(hosts))
    paths = list(dict.fromkeys(wordlist or DEFAULT_CONTENT_WORDLIST))
    assets: list[dict] = []
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    max_workers = _bounded_workers(len(deduped_hosts))
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
                    body = resp.read(2048) if callable(getattr(resp, 'read', None)) else b''
                    length = len(body) if body else 0
                    final_url = _response_final_url(resp, url)
            except urllib_error.HTTPError as exc:
                code = exc.code
                length = 0
                body = b''
                final_url = url
            except (urllib_error.URLError, ValueError, OSError):
                continue
            body_text = body.decode('utf-8', 'replace') if isinstance(body, (bytes, bytearray)) else str(body)
            if code in _INTERESTING_STATUS and not _is_login_redirect(url, final_url, body_text):
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
        _emit_progress(progress, {'targets': list(deduped_hosts), 'assets': list(assets), 'discovered': [row['domain'] for row in assets if row.get('paths')], 'probe_log': list(probe_log), 'thread_status': list(thread_status), 'threads': max_workers})
        return record

    if not deduped_hosts:
        return {'discovered': [], 'assets': [], 'probe_log': [], 'thread_status': [], 'threads': 0}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_host, host) for host in deduped_hosts]
        _drain_futures(futures, probe_log)

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
        # Record the final URL so callers can detect redirects (e.g. to a login page).
        geturl = getattr(resp, 'geturl', None)
        if callable(geturl):
            try:
                hdrs['x-final-url'] = str(geturl())
            except Exception:
                pass
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


def _reproduction_steps(finding: dict, host: str) -> dict:
    """Exact manual steps a human can follow to confirm a finding. Non-destructive only."""
    url = f'https://{host}'
    ftype = finding.get('type')
    detail = finding.get('detail')
    if ftype == 'missing_security_headers':
        headers = detail if isinstance(detail, list) else [str(detail)]
        return {
            'title': 'Missing security headers',
            'steps': [
                f'Open a terminal and run: <code>curl -sSI {url}</code>',
                'Read the response headers printed by curl.',
                'Confirm these headers are NOT present: <code>' + ', '.join(headers) + '</code>',
            ],
            'expected': 'The listed headers do not appear in the response.',
            'impact': 'Depending on which are missing: clickjacking (X-Frame-Options), MIME sniffing (X-Content-Type-Options), weaker XSS/isolation defenses (CSP), or downgrade attacks (HSTS).',
            'remediation': 'Set the missing headers at the application or edge/proxy layer.',
        }
    if ftype == 'cors_misconfig':
        return {
            'title': 'CORS misconfiguration (untrusted origin reflected)',
            'steps': [
                f"Run: <code>curl -sS -I -H 'Origin: https://evil.example' {url}</code>",
                'Inspect the <code>Access-Control-Allow-Origin</code> and <code>Access-Control-Allow-Credentials</code> response headers.',
                'Confirm the server reflects <code>https://evil.example</code> (or returns <code>*</code> together with credentials true).',
                f'Observed by the scanner: <code>{detail}</code>',
            ],
            'expected': 'Access-Control-Allow-Origin echoes the untrusted origin, indicating cross-origin reads may be possible.',
            'impact': 'A malicious site could read authenticated responses on behalf of a logged-in user.',
            'remediation': 'Restrict allowed origins to an explicit allowlist; never reflect arbitrary Origins with credentials enabled.',
        }
    if ftype == 'tech_disclosure':
        return {
            'title': 'Technology/version disclosure',
            'steps': [
                f'Run: <code>curl -sSI {url}</code>',
                'Look at the <code>Server</code> / <code>X-Powered-By</code> headers.',
                f'Confirm the disclosure: <code>{detail}</code>',
            ],
            'expected': 'The response advertises server or framework version details.',
            'impact': 'Version disclosure helps an attacker target known CVEs for that stack.',
            'remediation': 'Suppress or genericize version banners at the app/proxy layer.',
        }
    if ftype == 'insecure_cookie':
        flags = detail if isinstance(detail, list) else [str(detail)]
        return {
            'title': 'Insecure cookie flags',
            'steps': [
                f'Run: <code>curl -sSI {url}</code>',
                'Inspect the <code>Set-Cookie</code> header(s).',
                'Confirm the following are missing: <code>' + ', '.join(flags) + '</code>',
            ],
            'expected': 'Session/other cookies are set without one or more of Secure, HttpOnly, SameSite.',
            'impact': 'Cookies may be exposed over plaintext, readable by scripts, or sent cross-site (CSRF).',
            'remediation': 'Set Secure, HttpOnly, and an appropriate SameSite on sensitive cookies.',
        }
    if ftype == 'error_disclosure':
        return {
            'title': 'Verbose error / stack trace disclosure',
            'steps': [
                f'Browse to <code>{url}</code> (or the specific request that errored).',
                'Observe the response body returned by the server.',
                'Confirm a stack trace or framework error message is shown to the client.',
            ],
            'expected': 'A server-side stack trace or detailed error is rendered in the response.',
            'impact': 'Leaks internal paths, dependencies, and logic useful for further attacks.',
            'remediation': 'Return generic error pages; log details server-side only.',
        }
    return {
        'title': ftype or 'Finding',
        'steps': [f'Manually review <code>{url}</code> for: {ftype}'],
        'expected': 'Analyst confirmation required.',
        'impact': 'See finding type.',
        'remediation': 'Review and remediate per finding type.',
    }


def _render_finding_report_html(host: str, findings: list[dict], job_name: str) -> str:
    from html import escape
    generated = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
    sections = []
    for idx, finding in enumerate(findings, start=1):
        repro = _reproduction_steps(finding, host)
        severity = escape(str(finding.get('severity', 'info')))
        steps_html = '\n'.join(f'<li>{step}</li>' for step in repro['steps'])
        sections.append(f'''
      <section class="finding sev-{severity}">
        <h2>{idx}. {escape(repro['title'])} <span class="sev">{severity}</span></h2>
        <p><strong>Affected asset:</strong> <code>https://{escape(host)}</code></p>
        <h3>Steps to Reproduce</h3>
        <ol>{steps_html}</ol>
        <p><strong>Expected evidence:</strong> {escape(repro['expected'])}</p>
        <p><strong>Impact:</strong> {escape(repro['impact'])}</p>
        <p><strong>Remediation:</strong> {escape(repro['remediation'])}</p>
      </section>''')
    body = '\n'.join(sections)
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Findings write-up: {escape(host)}</title>
<style>
  body {{ font-family: Arial, sans-serif; background:#0f172a; color:#e5e7eb; margin:0; padding:32px; }}
  h1 {{ margin-bottom:4px; }} .meta {{ color:#94a3b8; margin-bottom:24px; }}
  .finding {{ background:#1f2937; border-left:4px solid #38bdf8; border-radius:8px; padding:16px 20px; margin-bottom:20px; }}
  .finding.sev-high {{ border-left-color:#ef4444; }} .finding.sev-medium {{ border-left-color:#f59e0b; }}
  .finding.sev-low {{ border-left-color:#3b82f6; }} .finding.sev-info {{ border-left-color:#64748b; }}
  .sev {{ font-size:12px; text-transform:uppercase; background:#0b1120; padding:2px 8px; border-radius:999px; margin-left:8px; }}
  code {{ background:#0b1120; padding:2px 6px; border-radius:4px; }}
  ol li {{ margin-bottom:6px; }}
  .disclaimer {{ color:#94a3b8; font-size:13px; margin-top:24px; border-top:1px solid #334155; padding-top:12px; }}
</style></head><body>
  <h1>Potential findings: {escape(host)}</h1>
  <div class="meta">Job: {escape(job_name)} &nbsp;|&nbsp; Generated: {generated} &nbsp;|&nbsp; {len(findings)} finding(s)</div>
  {body}
  <p class="disclaimer">These are automated, non-destructive detection signals. Manually reproduce and confirm each item before reporting. Stay within the approved program scope and rules.</p>
</body></html>'''


def _write_finding_report(job_name: str, host: str, findings: list[dict]) -> str | None:
    if not findings:
        return None
    out_dir = REPORTS_DIR / job_name
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f'{host}.html').write_text(_render_finding_report_html(host, findings, job_name), encoding='utf-8')
    return f'/reports/{job_name}/{host}'


def _application_security_tests(hosts: list[str], *, use_external_tools: bool = False, progress=None) -> dict:
    deduped_hosts = sorted(set(hosts))
    assets: list[dict] = []
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    max_workers = _bounded_workers(len(deduped_hosts))

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
            _emit_progress(progress, {'targets': list(deduped_hosts), 'assets': list(assets), 'discovered': [row['domain'] for row in assets if row.get('findings')], 'probe_log': list(probe_log), 'thread_status': list(thread_status), 'threads': max_workers})
            return record

        if _is_login_redirect(url, hdrs.get('x-final-url', url), body):
            record = {'domain': host, 'status': 'no_findings', 'kind': 'app-test', 'ports': [], 'findings': [], 'source': 'app-test', 'sources': ['app-test'], 'source_count': 0, 'evidence': []}
            assets.append(record)
            thread_status.append({'thread_id': thread_name, 'host': host, 'status': 'login_redirect', 'timestamp': time.time()})
            _emit_progress(progress, {'targets': list(deduped_hosts), 'assets': list(assets), 'discovered': [], 'probe_log': list(probe_log), 'thread_status': list(thread_status), 'threads': max_workers})
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
        report_url = _write_finding_report('application-security-testing', host, findings)
        if report_url:
            record['report_url'] = report_url
        assets.append(record)
        thread_status.append({'thread_id': thread_name, 'host': host, 'status': record['status'], 'findings': len(findings), 'timestamp': time.time()})
        _emit_progress(progress, {'targets': list(deduped_hosts), 'assets': list(assets), 'discovered': [row['domain'] for row in assets if row.get('findings')], 'probe_log': list(probe_log), 'thread_status': list(thread_status), 'threads': max_workers})
        return record

    if not deduped_hosts:
        return {'discovered': [], 'assets': [], 'probe_log': [], 'thread_status': [], 'threads': 0}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(test_host, host) for host in deduped_hosts]
        _drain_futures(futures, probe_log)

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


_LOGIN_URL_MARKERS = ('login', 'signin', 'sign-in', 'sso', 'oauth', 'auth/realms', 'account/login', 'session/new', 'adfs', 'saml', 'idp')
_LOGIN_BODY_MARKERS = (
    'type="password"', "type='password'", 'name="password"', 'id="password"',
    '<title>login', '<title>sign in', 'login required', 'please sign in',
    'authentication required', 'name="username"', "name='username'",
)


def _is_login_redirect(requested_url: str, final_url: str, body: str) -> bool:
    """True when a 200 response is really a login/auth page, often reached via redirect."""
    final = (final_url or '').lower()
    redirected = bool(final) and final.rstrip('/') != (requested_url or '').lower().rstrip('/')
    url_login = any(marker in final for marker in _LOGIN_URL_MARKERS)
    body_login = any(marker in body.lower() for marker in _LOGIN_BODY_MARKERS)
    return (redirected and url_login) or body_login


def _api_endpoint_tests(hosts: list[str], *, use_external_tools: bool = False, progress=None) -> dict:
    deduped_hosts = sorted(set(hosts))
    assets: list[dict] = []
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    max_workers = _bounded_workers(len(deduped_hosts))

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
                # A redirect/landing on a login page is not a real debug exposure.
                if not exposes and _is_login_redirect(url, hdrs.get('x-final-url', url), body):
                    probe_log.append({'thread_id': thread_name, 'host': host, 'path': path, 'status_code': code, 'status': 'login_redirect', 'timestamp': time.time()})
                    continue
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
        _emit_progress(progress, {'targets': list(deduped_hosts), 'assets': list(assets), 'discovered': [row['domain'] for row in assets if row.get('findings')], 'probe_log': list(probe_log), 'thread_status': list(thread_status), 'threads': max_workers})
        return record

    if not deduped_hosts:
        return {'discovered': [], 'assets': [], 'probe_log': [], 'thread_status': [], 'threads': 0}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(test_host, host) for host in deduped_hosts]
        _drain_futures(futures, probe_log)

    hits = [a for a in assets if a.get('findings')]
    return {
        'discovered': sorted(a['domain'] for a in hits),
        'assets': sorted(assets, key=lambda r: r['domain']),
        'probe_log': probe_log,
        'thread_status': thread_status,
        'threads': max_workers,
    }


# Ports that should not be exposed on a public web endpoint. Web ports 80/443 are
# expected and never flagged. Value is (service, severity).
_UNEXPECTED_PORTS: dict[int, tuple[str, str]] = {
    21: ('ftp', 'high'),
    22: ('ssh', 'medium'),
    23: ('telnet', 'high'),
    25: ('smtp', 'low'),
    1433: ('mssql', 'critical'),
    2375: ('docker-api', 'critical'),
    2376: ('docker-tls', 'high'),
    3306: ('mysql', 'critical'),
    3389: ('rdp', 'high'),
    5432: ('postgresql', 'critical'),
    5601: ('kibana', 'high'),
    5900: ('vnc', 'high'),
    5984: ('couchdb', 'high'),
    6379: ('redis', 'critical'),
    8000: ('http-dev', 'low'),
    8080: ('http-alt', 'low'),
    8443: ('https-alt', 'low'),
    8888: ('http-alt', 'low'),
    9000: ('dev-service', 'medium'),
    9200: ('elasticsearch', 'critical'),
    11211: ('memcached', 'high'),
    15672: ('rabbitmq-mgmt', 'medium'),
    27017: ('mongodb', 'critical'),
}


def _tcp_port_open(ip: str, port: int, timeout: float = 1.5) -> bool:
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def _port_scan_tests(hosts: list[str], *, use_external_tools: bool = False, progress=None) -> dict:
    """Resolve the IP(s) behind each live host and flag unexpected open ports."""
    deduped_hosts = sorted(set(hosts))
    assets: list[dict] = []
    probe_log: list[dict] = []
    thread_status: list[dict] = []
    max_workers = _bounded_workers(len(deduped_hosts))

    def scan_host(host: str) -> dict:
        thread_name = threading.current_thread().name
        findings: list[dict] = []
        open_ports: list[int] = []
        for ip in sorted(_resolve_host_ips(host)):
            for port, (service, severity) in sorted(_UNEXPECTED_PORTS.items()):
                attempt = {'thread_id': thread_name, 'host': host, 'ip': ip, 'port': port, 'status': 'checking', 'timestamp': time.time()}
                probe_log.append(attempt)
                if _tcp_port_open(ip, port):
                    attempt['status'] = 'open'
                    open_ports.append(port)
                    findings.append({'type': 'open_port', 'ip': ip, 'port': port, 'service': service, 'severity': severity})
                else:
                    attempt['status'] = 'closed'

        record = {
            'domain': host,
            'status': 'findings' if findings else 'no_findings',
            'kind': 'port-scan',
            'ports': sorted(set(open_ports)),
            'findings': findings,
            'source': ', '.join(f"{f['ip']}:{f['port']} {f['service']}" for f in findings) if findings else 'port-scan',
            'sources': [f"{f['ip']}:{f['port']} {f['service']}" for f in findings] or ['port-scan'],
            'source_count': len(findings),
            'evidence': [],
        }
        assets.append(record)
        thread_status.append({'thread_id': thread_name, 'host': host, 'status': record['status'], 'open_ports': record['ports'], 'timestamp': time.time()})
        _emit_progress(progress, {'assets': list(assets), 'discovered': [row['domain'] for row in assets if row.get('findings')], 'probe_log': list(probe_log), 'thread_status': list(thread_status), 'threads': max_workers})
        return record

    if not deduped_hosts:
        return {'discovered': [], 'assets': [], 'probe_log': [], 'thread_status': [], 'threads': 0}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_host, host) for host in deduped_hosts]
        _drain_futures(futures, probe_log)

    hits = [a for a in assets if a.get('findings')]
    return {
        'discovered': sorted(a['domain'] for a in hits),
        'assets': sorted(hits, key=lambda r: r['domain']),
        'probe_log': _cap_log(probe_log),
        'thread_status': _cap_log(thread_status),
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


def run_passive_job(job: dict, allowed_scope: list[str], *, use_external_tools: bool = False, progress=None) -> dict:
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

        deduped_targets, _truncated = _cap_hosts(deduped_targets)
        probe_result = _probe_live_web_assets(deduped_targets, use_external_tools=use_external_tools, progress=progress)
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
        deduped_hosts, _truncated = _cap_hosts(deduped_hosts)
        enum_result = _enumerate_live_services(deduped_hosts, use_external_tools=use_external_tools, progress=progress)
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
        vhost_result = _run_vhost_discovery(service_assets, progress=progress)
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

        deduped_hosts, _truncated = _cap_hosts(deduped_hosts)
        enum_result = _directory_enumeration(deduped_hosts, use_external_tools=use_external_tools, progress=progress)
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
        deduped_hosts, _truncated = _cap_hosts(deduped_hosts)
        test_result = _application_security_tests(deduped_hosts, use_external_tools=use_external_tools, progress=progress)
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
        api_hosts, _truncated = _cap_hosts(api_hosts)
        test_result = _api_endpoint_tests(api_hosts, use_external_tools=use_external_tools, progress=progress)
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

    if job_name == 'port-scan-live-hosts':
        dep_path = RESULTS_DIR / 'service-enumeration-live-hosts.json'
        if not dep_path.exists():
            return {
                'job': job_name, 'program': job.get('program', DEFAULT_PROGRAM), 'type': 'active',
                'targets': [], 'queued': [], 'skipped': [], 'status': 'waiting_on_dependencies',
                'job_state': 'waiting_on_dependencies', 'discovered': [], 'assets': [], 'source_count': 0,
                'dependencies': ['service-enumeration-live-hosts'],
            }
        hosts = _combined_live_hosts()
        deduped_hosts = [h for h in hosts if is_in_scope(h, allowed_scope)]
        deduped_hosts, _truncated = _cap_hosts(deduped_hosts)
        test_result = _port_scan_tests(deduped_hosts, use_external_tools=use_external_tools, progress=progress)
        assets = test_result.get('assets', [])
        response = {
            'job': job_name, 'program': job.get('program', DEFAULT_PROGRAM), 'type': 'active',
            'targets': deduped_hosts, 'queued': deduped_hosts, 'skipped': [],
            'status': 'ok' if test_result.get('discovered') else 'no_findings',
            'discovered': test_result.get('discovered', []), 'assets': assets,
            'source_count': sum(len(a.get('findings', [])) for a in assets),
            'depends_on': ['service-enumeration-live-hosts'],
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
            print(json.dumps({'job': job.get('name'), 'status': 'skipped_active', 'reason': 'requires --allow-active'}, indent=2), file=sys.stderr)
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
                print(json.dumps({'job': job.get('name'), 'status': 'waiting_on_dependencies', 'dependencies': pending}, indent=2), file=sys.stderr)
                continue
        if not args.force and _lock_is_active(job_path.stem):
            print(json.dumps({'job': job.get('name'), 'status': 'busy', 'reason': 'another run holds the lock'}, indent=2), file=sys.stderr)
            continue
        if not args.force and not should_run_job(job_path):
            continue
        RUNNING_DIR.mkdir(parents=True, exist_ok=True)
        lock_path = RUNNING_DIR / f'{job_path.stem}.lock'
        lock_path.write_text(str(os.getpid()), encoding='utf-8')
        out_path = RESULTS_DIR / f"{job_path.stem}.json"
        progress_lock = threading.Lock()
        running_payload = {
            'job': job.get('name'),
            'program': job.get('program', DEFAULT_PROGRAM),
            'type': job.get('type', 'passive'),
            'targets': job.get('targets', []),
            'queued': job.get('targets', []),
            'skipped': [],
            'status': 'running',
            'job_state': 'running',
            'discovered': [],
            'assets': [],
            'source_count': 0,
            'depends_on': job_workflow_dependencies(job.get('name')),
            'probe_log': [],
            'thread_status': [],
            'probe_threads': 0,
        }
        _atomic_write_json(out_path, running_payload)

        def checkpoint(snapshot: dict) -> None:
            assets = snapshot.get('assets', []) or []
            payload = dict(running_payload)
            targets = snapshot.get('targets', running_payload['targets']) or running_payload['targets']
            payload.update({
                'targets': targets,
                'queued': targets,
                'discovered': snapshot.get('discovered', []),
                'assets': assets,
                'source_count': sum(len(asset.get('findings', [])) for asset in assets if isinstance(asset, dict)),
                'probe_log': _cap_log(snapshot.get('probe_log', []) or []),
                'thread_status': _cap_log(snapshot.get('thread_status', []) or []),
                'probe_threads': snapshot.get('threads', 0),
            })
            with progress_lock:
                _atomic_write_json(out_path, payload)

        try:
            allowed_scope = read_scope_file(job.get('program', DEFAULT_PROGRAM))
            result = run_passive_job(job, allowed_scope, use_external_tools=args.external_probes, progress=checkpoint)
            if not RESULTS_DIR.exists():
                RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            previous = None
            if out_path.exists():
                try:
                    previous = json.loads(out_path.read_text(encoding='utf-8'))
                except Exception:
                    previous = None
            # Active steps derive targets/results from the current run only; merging would
            # carry stale targets forward. Passive discovery still accumulates across runs.
            merged_result = _result_for_write(job.get('name'), previous, result)
            _atomic_write_json(out_path, merged_result)
            all_results.append(merged_result)
        finally:
            if lock_path.exists():
                lock_path.unlink()

    print(json.dumps(all_results, indent=2))


if __name__ == '__main__':
    main()
