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

from program_builder import ROOT, active_approved, auto_run_policy, read_guidelines
from scope_validator import is_in_scope
from stages import STAGES, ACTIVE_STAGES, job_name_for


PUBLIC_DISCOVERY_HOSTS = {'api.certspotter.com', 'api.hackertarget.com', 'crt.sh', 'dns.google'}


class AutoRunGuard:
    def __init__(self, slug: str, *, root: Path = ROOT, open_request=None,
                 sleep_fn=time.sleep, monotonic_fn=time.monotonic):
        self.slug = slug
        self.root = root
        rules, self.digest = read_guidelines(slug, root=root)
        configuration = json.loads((root / 'programs' / slug / '.auto-run.json').read_text(encoding='utf-8'))
        self.policy = auto_run_policy(rules)
        self.scope_digest = configuration.get('scope_sha256')
        self.expected_configuration = configuration
        if configuration.get('enabled') is not True or configuration.get('guidelines_sha256') != self.digest:
            raise PermissionError('Auto-run configuration is stale or disabled')
        self.check_approval()
        self.stage = None
        self.last_request = None
        self.sleep = sleep_fn
        self.monotonic = monotonic_fn
        self.lock = threading.RLock()
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
                    redirected._auto_redirect_count = count
                    guard.before_http(redirected)
                return redirected

        self.open_request = open_request or request.build_opener(ScopedRedirect()).open

    def check_approval(self):
        _, digest = read_guidelines(self.slug, root=self.root)
        scope_digest = hashlib.sha256((self.root / 'programs' / self.slug / 'scope.md').read_bytes()).hexdigest()
        current = json.loads((self.root / 'programs' / self.slug / '.auto-run.json').read_text(encoding='utf-8'))
        if (digest != self.digest or scope_digest != self.scope_digest or current != self.expected_configuration
                or not active_approved(self.slug, root=self.root)):
            raise PermissionError('Approval, guidelines, scope, or auto-run configuration changed; run stopped')

    def wait(self):
        with self.lock:
            if self.last_request is not None:
                delay = 1 / self.policy['requests_per_second'] - (self.monotonic() - self.last_request)
                if delay > 0:
                    self.sleep(delay)
            self.check_approval()
            self.last_request = self.monotonic()

    def before_http(self, req):
        parsed = urlsplit(req.full_url)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
            raise error.URLError('Invalid scoped HTTP target')
        host = parsed.hostname
        header_host = req.get_header('Host')
        allowed = is_in_scope(host, self.scope)
        if header_host:
            allowed = is_in_scope(header_host, self.scope) and (host == header_host or header_host in self.ip_owners.get(host, set()))
        if self.stage not in ACTIVE_STAGES and host in PUBLIC_DISCOVERY_HOSTS and (not header_host or header_host == host):
            allowed = True
        if not allowed:
            raise error.URLError('Target is outside approved program scope')
        self.wait()

    def urlopen(self, target, data=None, timeout=8, **kwargs):
        req = target if isinstance(target, request.Request) else request.Request(target, data=data)
        with self.lock:
            self.before_http(req)
            return self.open_request(req, timeout=min(timeout, 8))

    def resolve(self, host):
        if not is_in_scope(host, self.scope):
            return set()
        with self.lock:
            self.wait()
            addresses = self.resolve_original(host)
            for address in addresses:
                self.ip_owners.setdefault(address, set()).add(host)
            return addresses

    def tcp(self, address, port, timeout=1.5):
        if address not in self.ip_owners or self.stage != 'port-scan':
            return False
        with self.lock:
            self.wait()
            return self.tcp_original(address, port, timeout)

    @contextmanager
    def installed(self, worker):
        original_http = request.urlopen
        original_workers = worker.MAX_WORKERS
        self.resolve_original = worker._resolve_host_ips
        self.tcp_original = worker._tcp_port_open
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


def run_auto_pipeline(slug: str, *, root: Path = ROOT, job_name=None, force=False,
                      open_request=None, sleep_fn=time.sleep, monotonic_fn=time.monotonic) -> list[dict]:
    import worker
    guard = AutoRunGuard(slug, root=root, open_request=open_request, sleep_fn=sleep_fn, monotonic_fn=monotonic_fn)
    guard.scope = worker.read_scope_file(slug)
    if not guard.scope:
        raise PermissionError('No valid domain/wildcard scope for auto-run')
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
                name = job_name_for(slug, stage['stage'])
                if job_name and name != job_name:
                    continue
                output = root / 'results' / f'{name}.json'
                guard.check_approval()
                if stage['stage'] not in guard.policy['allowed_stages']:
                    payload = {'job': name, 'program': slug, 'type': stage['type'], 'status': 'blocked_by_guidelines',
                               'job_state': 'blocked', 'reason': guard.policy['blocked_stages'][stage['stage']],
                               'assets': [], 'discovered': [], 'targets': [], 'auto_run': True}
                    worker._atomic_write_json(output, payload)
                    results.append(payload)
                    continue
                dependencies = [root / 'results' / f'{job_name_for(slug, dependency)}.json' for dependency in stage['depends_on']]
                completed = True
                for path in dependencies:
                    try:
                        payload = json.loads(path.read_text(encoding='utf-8'))
                        completed = completed and payload.get('guidelines_sha256') == guard.digest and payload.get('scope_sha256') == guard.scope_digest and payload.get('job_state') == 'completed'
                    except (OSError, ValueError):
                        completed = False
                if not completed:
                    payload = {'job': name, 'program': slug, 'type': stage['type'], 'status': 'waiting_on_dependencies',
                               'job_state': 'waiting_on_dependencies', 'assets': [], 'discovered': [], 'targets': [], 'auto_run': True}
                    worker._atomic_write_json(output, payload)
                    results.append(payload)
                    continue
                job_path = root / 'jobs' / 'generated' / f'{name}.yaml'
                if not force and not worker.should_run_job(job_path):
                    previous = json.loads(output.read_text(encoding='utf-8'))
                    if previous.get('guidelines_sha256') == guard.digest and previous.get('scope_sha256') == guard.scope_digest:
                        results.append(previous)
                        continue
                job = worker.load_job(job_path)
                guard.stage = stage['stage']
                job_lock = running / f'{name}.lock'
                job_lock.write_text(str(os.getpid()), encoding='utf-8')
                progress_path = root / 'results' / '.scan-progress' / f'{name}.json'
                payload = {'job': name, 'program': slug, 'type': stage['type'], 'status': 'running', 'job_state': 'running',
                           'assets': [], 'discovered': [], 'targets': job['targets'], 'auto_run': True,
                           'guidelines_sha256': guard.digest, 'scope_sha256': guard.scope_digest,
                           'requests_per_second': guard.policy['requests_per_second']}
                progress_lock = threading.Lock()

                def progress(snapshot):
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
                        result = worker.run_passive_job(job, guard.scope, use_external_tools=False, progress=progress, scan_progress=scan_progress)
                        guard.check_approval()
                        result = worker._result_for_write(name, None, result)
                        result['job_state'] = ('running' if result.get('remaining_count') else
                                               'completed' if result.get('status') in worker.COMPLETED_STATUSES else
                                               result.get('job_state', result.get('status', 'stopped')))
                        result.update({'auto_run': True, 'guidelines_sha256': guard.digest, 'scope_sha256': guard.scope_digest,
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