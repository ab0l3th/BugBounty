from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from urllib import error, request
from urllib.parse import urlsplit

from program_builder import ROOT, active_approved, auto_run_policy, load_scope_partitions, partition_job_name, read_guidelines
from scope_validator import is_in_scope, parse_scope_pattern
from stages import STAGES, ACTIVE_STAGES, job_name_for
from vhost_transport import vhost_opener
from shopify_policy import apply_finding_eligibility, url_allowed
from job_control import check_stop, is_stopped, job_execution, mark_stopped_result


PUBLIC_DISCOVERY_HOSTS = {'api.certspotter.com', 'api.hackertarget.com', 'crt.sh', 'dns.google'}


class AutoRunGuard:
    def __init__(self, slug: str, *, root: Path = ROOT, open_request=None,
                 sleep_fn=time.sleep, monotonic_fn=time.monotonic, queue='automatic'):
        self.slug = slug
        self.root = root
        rules, self.digest = read_guidelines(slug, root=root)
        configuration = json.loads((root / 'programs' / slug / '.auto-run.json').read_text(encoding='utf-8'))
        self.policy = auto_run_policy(rules)
        self.scope_digest = configuration.get('scope_sha256')
        self.expected_configuration = configuration
        self.partitions = load_scope_partitions(slug, root=root)
        self.queue = queue
        selected = [asset for asset in self.partitions.get(queue, []) if asset.get('scope_kind') and not asset.get('query_present') and not asset.get('fragment_present')] if self.partitions is not None else []
        self.domain_scope = sorted({asset['pattern'] for asset in selected if asset.get('scope_kind') in {'host_pattern', 'exact_host'}})
        self.url_assets = [asset for asset in selected if asset.get('scope_kind') == 'exact_url' and not asset.get('query_present')]
        if configuration.get('enabled') is not True or configuration.get('guidelines_sha256') != self.digest:
            raise PermissionError('Auto-run configuration is stale or disabled')
        self.check_approval()
        self.stage = None
        self.current_job = None
        self.last_request = None
        self.sleep = sleep_fn
        self.monotonic = monotonic_fn
        self.lock = threading.RLock()
        self.network_slots = threading.BoundedSemaphore(8)
        self.ip_owners = {}
        self.scope = []
        self.resolve_original = None
        self.tcp_original = None
        guard = self

        class ScopedRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, response, code, message, headers, destination):
                count = getattr(req, '_auto_redirect_count', 0) + 1
                parsed = urlsplit(destination)
                if (count > 3 or re.search(r'(?:^|[./_-])(?:login|log-in|signin|sign-in|sso|oauth|auth|authorize|accounts?)(?:[./_-]|$)',
                                          (parsed.hostname or '') + parsed.path, re.IGNORECASE)):
                    raise error.URLError('Login or excessive redirect skipped')
                if urlsplit(req.full_url).scheme == 'https' and parsed.scheme != 'https':
                    raise error.URLError('HTTPS downgrade redirect skipped')
                redirected = super().redirect_request(req, response, code, message, headers, destination)
                if redirected is not None:
                    if parsed.hostname != urlsplit(req.full_url).hostname:
                        redirected.remove_header('Host')
                    elif getattr(req, '_vhost_connect_ip', None):
                        redirected._vhost_connect_ip = req._vhost_connect_ip
                    redirected._auto_redirect_count = count
                    guard.before_http(redirected)
                return redirected

        self.open_request = open_request or vhost_opener(ScopedRedirect()).open

    def check_approval(self):
        _, digest = read_guidelines(self.slug, root=self.root)
        scope_digest = hashlib.sha256((self.root / 'programs' / self.slug / 'scope.md').read_bytes()).hexdigest()
        current = json.loads((self.root / 'programs' / self.slug / '.auto-run.json').read_text(encoding='utf-8'))
        if current.get('partitions_sha256'):
            actual = hashlib.sha256((self.root / 'programs' / self.slug / '.scope-partitions.json').read_bytes()).hexdigest()
            if actual != current['partitions_sha256']:
                raise PermissionError('Asset partitions changed; run stopped')
        if (digest != self.digest or scope_digest != self.scope_digest or current != self.expected_configuration
                or not active_approved(self.slug, root=self.root)):
            raise PermissionError('Approval, guidelines, scope, or auto-run configuration changed; run stopped')

    def wait(self):
        with self.lock:
            if self.last_request is not None:
                delay = 1 / self.policy['requests_per_second'] - (self.monotonic() - self.last_request)
                if delay > 0:
                    self.sleep(delay)
            if self.current_job:
                check_stop(self.root, self.current_job)
            self.check_approval()
            self.last_request = self.monotonic()

    def permits_url(self, url):
        try:
            parsed = urlsplit(url)
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        except ValueError:
            return False
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
            return False
        if not url_allowed(url, self.slug, self.root):
            return False
        if self.partitions is None:
            return is_in_scope(parsed.hostname, self.scope)
        for asset in self.partitions['excluded']:
            pattern = asset.get('pattern') or parse_scope_pattern(asset['identifier'])
            if pattern and is_in_scope(parsed.hostname, [pattern]):
                return False
            try:
                blocked = urlsplit(asset['identifier'])
                if blocked.hostname == parsed.hostname and blocked.scheme in {'http', 'https'}:
                    boundary = blocked.path or '/'
                    if (parsed.path or '/') == boundary or (parsed.path or '/').startswith(boundary.rstrip('/') + '/'):
                        return False
            except ValueError:
                continue
        exact = any(parsed.hostname == asset['host'] and parsed.scheme == asset['scheme'] and port == (asset['port'] or (443 if asset['scheme'] == 'https' else 80))
                    and (parsed.path or '/') == asset['path'] and not parsed.query for asset in self.url_assets)
        if self.queue == 'automatic':
            for asset in self.partitions['manual']:
                pattern = asset.get('pattern') or parse_scope_pattern(asset['identifier'])
                if pattern and is_in_scope(parsed.hostname, [pattern]):
                    return False
                if asset.get('scope_kind') == 'exact_url' and parsed.hostname == asset['host']:
                    if (parsed.path or '/') == asset['path'] or (parsed.path or '/').startswith(asset['path'].rstrip('/') + '/'):
                        return False
        if exact:
            return True
        return is_in_scope(parsed.hostname, self.domain_scope)

    def permits_host(self, host):
        return self.permits_url(f'https://{host}/') or any(asset['host'] == host and self.permits_url(asset['identifier']) for asset in self.url_assets)

    def before_http(self, req):
        parsed = urlsplit(req.full_url)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
            raise error.URLError('Invalid scoped HTTP target')
        host = parsed.hostname
        header_host = req.get_header('Host')
        allowed = self.permits_url(req.full_url)
        pinned_origin = getattr(req, '_vhost_connect_ip', None)
        if pinned_origin and not (self.stage == 'vhost-discovery' and self.ip_owners.get(pinned_origin)):
            raise error.URLError('Vhost origin was not resolved from approved program scope')
        if header_host:
            virtual_url = parsed._replace(netloc=header_host + (f':{parsed.port}' if parsed.port else '')).geturl()
            allowed = self.permits_url(virtual_url) and is_in_scope(header_host, self.domain_scope if self.partitions is not None else self.scope) and (host == header_host or header_host in self.ip_owners.get(host, set())
                                                               or self.stage == 'vhost-discovery' and bool(self.ip_owners.get(host)))
        if self.stage not in ACTIVE_STAGES and host in PUBLIC_DISCOVERY_HOSTS and (not header_host or header_host == host):
            allowed = True
        if not allowed:
            raise error.URLError('Target is outside approved program scope')
        self.wait()

    def urlopen(self, target, data=None, timeout=8, **kwargs):
        req = target if isinstance(target, request.Request) else request.Request(target, data=data)
        with self.network_slots:
            self.before_http(req)
            return self.open_request(req, timeout=min(timeout, 8))

    def resolve(self, host):
        if not is_in_scope(host, self.scope) or not self.permits_host(host):
            return set()
        self.wait()
        addresses = self.resolve_original(host)
        with self.lock:
            if self.partitions is None or is_in_scope(host, self.domain_scope):
                for address in addresses:
                    self.ip_owners.setdefault(address, set()).add(host)
            return addresses

    def tcp(self, address, port, timeout=1.5):
        if address not in self.ip_owners or self.stage != 'port-scan':
            return False
        self.wait()
        return self.tcp_original(address, port, timeout)

    @contextmanager
    def installed(self, worker):
        original_http = request.urlopen
        original_workers = worker.MAX_WORKERS
        self.runtime_workers = original_workers
        self.resolve_original = worker._resolve_host_ips
        self.tcp_original = worker._tcp_port_open
        original_result_name = worker.result_name_for
        original_result_path = worker.result_path_for
        import passive_dns_enrichment
        original_dns = passive_dns_enrichment.passive_dns_enrichment
        if self.partitions is not None:
            worker.result_name_for = lambda program, stage: partition_job_name(program, stage, self.queue) if program == self.slug else original_result_name(program, stage)
            worker.result_path_for = lambda program, stage: self.root / 'results' / f'{worker.result_name_for(program, stage)}.json'
            passive_dns_enrichment.passive_dns_enrichment = lambda program: original_dns(program, allowed_patterns=self.domain_scope) if program == self.slug else original_dns(program)
        request.urlopen = self.urlopen
        worker._resolve_host_ips = self.resolve
        worker._tcp_port_open = self.tcp
        worker.MAX_WORKERS = min(original_workers, self.policy['max_workers'])
        try:
            yield
        finally:
            request.urlopen = original_http
            worker.MAX_WORKERS = original_workers
            worker._resolve_host_ips = self.resolve_original
            worker._tcp_port_open = self.tcp_original
            worker.result_name_for = original_result_name
            worker.result_path_for = original_result_path
            passive_dns_enrichment.passive_dns_enrichment = original_dns


def _run_url_stage(guard, worker, stage, progress):
    assets = []
    discovered = set()
    for asset in guard.url_assets:
        target = asset['identifier']
        host = asset['host']
        record = {'domain': host, 'url': target, 'scope_kind': 'exact_url', 'path': asset['path'],
                  'status': 'in_scope', 'findings': [], 'source': 'exact URL scope', 'sources': ['uploaded URL'], 'evidence': []}

        def fetch(url, *, extra_headers=None, method='GET', data=None, **kwargs):
            parsed = urlsplit(url)
            permitted_root = stage == 'application-testing' and (parsed.path or '/') == '/'
            if parsed.hostname != host or not ((parsed.path or '/') == asset['path'] or permitted_root):
                raise error.URLError('Outside selected exact URL scope')
            req = request.Request(target, headers=extra_headers or {'User-Agent': 'BugBountyScopeCheck/1.0'},
                                  method=method, data=data.encode() if isinstance(data, str) else data)
            with guard.urlopen(req) as response:
                headers = {key.lower(): value for key, value in dict(response.headers or {}).items()}
                headers['x-final-url'] = response.geturl() if hasattr(response, 'geturl') else target
                body = response.read(65536).decode('utf-8', errors='replace') if method != 'HEAD' else ''
                return response.getcode(), headers, body

        if stage == 'passive-web-discovery':
            discovered.add(host)
        elif stage == 'passive-dns-discovery':
            record['ips'] = sorted(guard.resolve(host))
            discovered.add(host)
        elif stage in {'confirm-live-web-assets', 'service-enumeration', 'directory-enumeration'}:
            try:
                code, headers, body = fetch(target, method='GET' if stage == 'directory-enumeration' else 'HEAD')
                record['status'] = 'live' if code < 400 and not worker._is_login_redirect(target, headers['x-final-url'], body) else 'no_response'
                record['evidence'] = [{'url': target, 'status_code': code}]
                record['ports'] = [asset['port'] or (443 if asset['scheme'] == 'https' else 80)]
                if stage == 'directory-enumeration':
                    record.update({'paths': [{'path': asset['path'], 'url': target, 'status_code': code}], 'checked_paths': 1, 'total_paths': 1})
                if record['status'] == 'live':
                    discovered.add(host)
            except (error.URLError, error.HTTPError, OSError, ValueError) as exc:
                record['status'] = 'no_response'
                record['error'] = type(exc).__name__
        elif stage in {'application-testing', 'api-testing'}:
            if stage == 'application-testing':
                checked = worker._application_security_tests([host], fetch=fetch, write_reports=False, workers=1)
            else:
                checked = worker._api_endpoint_tests([host], fetch=fetch, wordlist=[asset['path']], prefixes=[], workers=1)
            for observed in checked.get('assets', []):
                observed.update({'url': target, 'path': asset['path'], 'scope_kind': 'exact_url'})
                for finding in observed.get('findings', []):
                    finding.update({'path': asset['path'], 'url': target})
                for evidence in observed.get('evidence', []):
                    evidence['url'] = target
                assets.append(observed)
            discovered.update(checked.get('discovered', []))
            continue
        else:
            record['status'] = 'not_applicable'
            record['source'] = 'Exact URL scope does not authorize vhost or full TCP scans'
        assets.append(record)
        progress({'assets': list(assets), 'discovered': sorted(discovered)})
    return {'assets': assets, 'discovered': sorted(discovered), 'targets': sorted({asset['host'] for asset in guard.url_assets}), 'status': 'ok'}


def run_auto_pipeline(slug: str, *, root: Path = ROOT, job_name=None, force=False,
                      open_request=None, sleep_fn=time.sleep, monotonic_fn=time.monotonic, queue='automatic') -> list[dict]:
    import worker
    if queue == 'manual' and not job_name:
        raise PermissionError('Manual asset stages require an explicit job start')
    guard = AutoRunGuard(slug, root=root, open_request=open_request, sleep_fn=sleep_fn, monotonic_fn=monotonic_fn, queue=queue)
    guard.scope = worker.read_scope_file(slug) if guard.partitions is None else sorted({*guard.domain_scope, *(asset['host'] for asset in guard.url_assets)})
    if guard.partitions is not None:
        for queue_name in ('excluded', 'manual') if queue == 'automatic' else ('excluded',):
            denied_patterns = [parse_scope_pattern(asset['identifier']) for asset in guard.partitions[queue_name] if parse_scope_pattern(asset['identifier'])]
            guard.scope = [pattern for pattern in guard.scope if pattern.startswith('*.') or not is_in_scope(pattern, denied_patterns)]
    if guard.partitions is None:
        guard.domain_scope = guard.scope
    if not guard.scope:
        return []
    running = root / 'results' / '.running'
    running.mkdir(parents=True, exist_ok=True)
    program_lock = running / f'auto-program-{slug}.lock'
    if worker._lock_is_active(f'auto-program-{slug}'):
        return []
    try:
        descriptor = os.open(program_lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return []
    with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
        handle.write(str(os.getpid()))
    results = []
    try:
        with guard.installed(worker):
            for stage in STAGES:
                name = partition_job_name(slug, stage['stage'], queue)
                if job_name and name != job_name:
                    continue
                output = root / 'results' / f'{name}.json'
                if is_stopped(root, name):
                    mark_stopped_result(root, name)
                    continue
                guard.check_approval()
                if stage['stage'] not in guard.policy['allowed_stages']:
                    payload = {'job': name, 'program': slug, 'type': stage['type'], 'status': 'blocked_by_guidelines',
                               'job_state': 'blocked', 'reason': guard.policy['blocked_stages'][stage['stage']],
                               'assets': [], 'discovered': [], 'targets': [], 'auto_run': True,
                               'execution_queue': queue, 'manual_only': queue == 'manual',
                               'queue_asset_count': len(guard.partitions.get(queue, [])) if guard.partitions else 0}
                    worker._atomic_write_json(output, payload)
                    results.append(payload)
                    continue
                dependencies = [root / 'results' / f'{partition_job_name(slug, dependency, queue)}.json' for dependency in stage['depends_on']]
                completed = True
                for path in dependencies:
                    try:
                        payload = json.loads(path.read_text(encoding='utf-8'))
                        completed = completed and payload.get('guidelines_sha256') == guard.digest and payload.get('scope_sha256') == guard.scope_digest and payload.get('job_state') == 'completed'
                    except (OSError, ValueError):
                        completed = False
                if not completed:
                    payload = {'job': name, 'program': slug, 'type': stage['type'], 'status': 'waiting_on_dependencies',
                               'job_state': 'waiting_on_dependencies', 'assets': [], 'discovered': [], 'targets': [], 'auto_run': True,
                               'execution_queue': queue, 'manual_only': queue == 'manual',
                               'queue_asset_count': len(guard.partitions.get(queue, [])) if guard.partitions else 0}
                    worker._atomic_write_json(output, payload)
                    results.append(payload)
                    continue
                job_path = root / 'jobs' / 'generated' / f'{name}.yaml'
                if not force and not worker.should_run_job(job_path):
                    previous = json.loads(output.read_text(encoding='utf-8'))
                    if previous.get('guidelines_sha256') == guard.digest and previous.get('scope_sha256') == guard.scope_digest:
                        results.append(previous)
                        continue
                job = worker.load_job(job_path) if queue == 'automatic' else {'name': name, 'program': slug, 'stage': stage['stage'], 'type': stage['type'], 'targets': guard.scope}
                job['targets'] = guard.domain_scope if guard.partitions is not None else [target for target in job.get('targets', []) if is_in_scope(target, guard.scope)]
                guard.stage = stage['stage']
                worker.MAX_WORKERS = min(guard.runtime_workers, guard.policy['discovery_workers'] if stage['stage'] in {'vhost-discovery', 'directory-enumeration'} else guard.policy['max_workers'])
                guard.current_job = name
                job_lock = running / f'{name}.lock'
                job_lock.write_text(str(os.getpid()), encoding='utf-8')
                progress_path = root / 'results' / '.scan-progress' / f'{name}.json'
                payload = {'job': name, 'program': slug, 'type': stage['type'], 'status': 'running', 'job_state': 'running',
                           'assets': [], 'discovered': [], 'targets': job['targets'], 'auto_run': True,
                           'guidelines_sha256': guard.digest, 'scope_sha256': guard.scope_digest,
                           'execution_queue': queue, 'manual_only': queue == 'manual', 'queue_asset_count': len(guard.partitions.get(queue, [])) if guard.partitions else 0,
                           'requests_per_second': guard.policy['requests_per_second']}
                payload['rate_scope'] = 'program'
                payload['max_workers'] = worker.MAX_WORKERS
                progress_lock = threading.Lock()

                def progress(snapshot):
                    check_stop(root, name)
                    with progress_lock:
                        updated = {**payload, **snapshot, 'status': 'running', 'job_state': 'running'}
                        for field in ('probe_log', 'thread_status'):
                            if field in updated:
                                updated[field] = worker._cap_log(updated[field])
                        worker._atomic_write_json(output, updated)

                try:
                    worker._atomic_write_json(output, payload)
                    scan_progress = {}
                    if not force and progress_path.exists():
                        saved = json.loads(progress_path.read_text(encoding='utf-8'))
                        if saved.get('guidelines_sha256') == guard.digest and saved.get('scope_sha256') == guard.scope_digest:
                            scan_progress = saved
                    while True:
                        with job_execution(root, name, slug, worker=worker):
                            if guard.domain_scope:
                                result = worker.run_passive_job(job, guard.domain_scope, use_external_tools=False, progress=progress, scan_progress=scan_progress)
                            else:
                                result = {'job': name, 'program': slug, 'type': stage['type'], 'status': 'ok', 'assets': [], 'discovered': [], 'targets': []}
                            if guard.url_assets:
                                exact = _run_url_stage(guard, worker, stage['stage'], progress)
                                result['assets'] = [*result.get('assets', []), *exact['assets']]
                                result['discovered'] = sorted(set(result.get('discovered', [])) | set(exact['discovered']))
                                result['targets'] = sorted(set(result.get('targets', [])) | set(exact['targets']))
                        if guard.partitions is not None:
                            selected_hosts = {host for host in result.get('discovered', []) if guard.permits_host(host)}
                            result['discovered'] = sorted(selected_hosts)
                            result['assets'] = [asset for asset in result.get('assets', []) if asset.get('domain') and guard.permits_host(asset['domain'])]
                        guard.check_approval()
                        result = worker._result_for_write(name, None, result)
                        result = apply_finding_eligibility(result, root)
                        result['job_state'] = ('running' if result.get('remaining_count') else
                                               'completed' if result.get('status') in worker.COMPLETED_STATUSES else
                                               result.get('job_state', result.get('status', 'stopped')))
                        result.update({'auto_run': True, 'guidelines_sha256': guard.digest, 'scope_sha256': guard.scope_digest,
                                       'execution_queue': queue, 'manual_only': queue == 'manual', 'queue_asset_count': payload['queue_asset_count'],
                                       'requests_per_second': guard.policy['requests_per_second']})
                        worker._atomic_write_json(output, result)
                        if stage['stage'] != 'confirm-live-web-assets' or not result.get('remaining_count'):
                            break
                        next_progress = {'processed_hosts': result.get('processed_hosts', []), 'assets': result.get('assets', []),
                                         'guidelines_sha256': guard.digest, 'scope_sha256': guard.scope_digest}
                        if len(next_progress['processed_hosts']) <= len(scan_progress.get('processed_hosts', [])):
                            raise RuntimeError('Auto-run scan made no progress')
                        scan_progress = next_progress
                        worker._atomic_write_json(progress_path, scan_progress)
                    results.append(result)
                except Exception as exc:
                    try:
                        partial = json.loads(output.read_text(encoding='utf-8'))
                    except (OSError, ValueError):
                        partial = payload
                    stopped = {**partial, 'status': 'stopped', 'job_state': 'stopped', 'reason': str(exc)}
                    worker._atomic_write_json(output, stopped)
                    results.append(stopped)
                    break
                finally:
                    job_lock.unlink(missing_ok=True)
    finally:
        program_lock.unlink(missing_ok=True)
    return results