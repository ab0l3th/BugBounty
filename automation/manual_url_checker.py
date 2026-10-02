#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from program_builder import active_approved, load_manual_analysis, read_guidelines

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / 'results'
MAX_URLS_PER_RUN = 500
MAX_REQUESTS_PER_SECOND = 1


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ApprovedScopeClient:
    def __init__(self, slug, *, root=ROOT, open_request=None, sleep_fn=time.sleep,
                 monotonic_fn=time.monotonic):
        if not active_approved(slug, root=root):
            raise PermissionError('Current program guidelines must be approved')
        self.slug = slug
        self.root = root
        _, self.digest = read_guidelines(slug, root=root)
        self.analysis = load_manual_analysis(slug, root=root)
        policy = self.analysis['policy']
        if policy['automated_requests'] != 'manual_approval_required':
            raise PermissionError(policy['reason'])
        self.rate = min(MAX_REQUESTS_PER_SECOND, policy['stated_max_requests_per_second'])
        self.open_request = open_request or urllib.request.build_opener(NoRedirect()).open
        self.sleep = sleep_fn
        self.monotonic = monotonic_fn
        self.last_request = None
        self.lock = threading.Lock()
        self.ip_owners = {}

    def allows(self, url, host_header=None):
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            return False
        if parsed.scheme not in {'http', 'https'} or parsed.username or parsed.password or parsed.query or parsed.fragment:
            return False
        if port is not None and not 1 <= port <= 65535:
            return False
        hostname = parsed.hostname
        if host_header:
            if hostname != host_header and hostname not in self.ip_owners:
                return False
            hostname = host_header
        for asset in self.analysis['assets']:
            if asset['query_present'] or hostname != asset['host']:
                continue
            if asset['scope_kind'] == 'exact_host':
                return True
            expected_port = asset['port'] or (443 if asset['scheme'] == 'https' else 80)
            if (parsed.scheme == asset['scheme'] and (port or (443 if parsed.scheme == 'https' else 80)) == expected_port
                    and (parsed.path or '/') == asset['path']):
                return True
        return False

    def check_approval(self):
        _, digest = read_guidelines(self.slug, root=self.root)
        if digest != self.digest or not active_approved(self.slug, root=self.root):
            raise PermissionError('Approval revoked or guidelines changed; no further requests sent')

    def wait(self):
        if self.last_request is not None:
            delay = 1 / self.rate - (self.monotonic() - self.last_request)
            if delay > 0:
                self.sleep(delay)
        self.check_approval()
        self.last_request = self.monotonic()

    def request(self, url, *, method='HEAD', headers=None, read_body=False, data=None):
        with self.lock:
            visited = set()
            redirects = []
            target = url
            target_headers = dict(headers or {'User-Agent': 'BugBountyScopeCheck/1.0'})
            while True:
                if not self.allows(target, target_headers.get('Host')):
                    return {'status': None, 'error': 'OutsideExactScope', 'headers': {}, 'body': '', 'final_url': url, 'redirects': redirects}
                self.wait()
                visited.add(target)
                body_data = data.encode('utf-8') if isinstance(data, str) else data
                request = urllib.request.Request(target, headers=target_headers, method=method, data=body_data)
                try:
                    response = self.open_request(request, timeout=8)
                except urllib.error.HTTPError as exc:
                    response = exc
                except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
                    return {'status': None, 'error': type(exc).__name__, 'headers': {}, 'body': '', 'final_url': target, 'redirects': redirects}
                try:
                    code = response.getcode()
                    response_headers = dict(getattr(response, 'headers', {}) or {})
                    normalized = {key.lower(): value for key, value in response_headers.items()}
                    location = normalized.get('location')
                    body = response.read(65536).decode('utf-8', errors='replace') if read_body and method != 'HEAD' and not location else ''
                finally:
                    close = getattr(response, 'close', None)
                    if close:
                        close()
                result = {'status': code, 'headers': normalized, 'body': body, 'final_url': target, 'redirects': redirects}
                if code not in {301, 302, 303, 307, 308} or not location:
                    return result
                try:
                    destination = urljoin(target, location)
                    parsed = urlsplit(destination)
                    safe = _safe_location(destination)
                except ValueError:
                    result['redirect_stop'] = 'invalid_redirect'
                    return result
                redirects.append(safe)
                redirect_headers = dict(target_headers)
                if parsed.hostname != urlsplit(target).hostname:
                    redirect_headers.pop('Host', None)
                auth = re.search(r'(?:^|[./_-])(?:login|log-in|signin|sign-in|sso|oauth|authorize|auth|accounts?)(?:[./_-]|$)',
                                 (parsed.hostname or '') + (parsed.path or '/'), re.IGNORECASE)
                reason = ('login_redirect' if auth else 'outside_scope' if not self.allows(destination, redirect_headers.get('Host'))
                          else 'https_downgrade' if urlsplit(target).scheme == 'https' and parsed.scheme == 'http'
                          else 'redirect_loop' if destination in visited else 'redirect_limit' if len(redirects) > 3 else None)
                if reason:
                    result['redirect_stop'] = reason
                    return result
                target = destination
                target_headers = redirect_headers


def _safe_location(value: str) -> dict:
    parsed = urlsplit(value)
    return {'host': parsed.hostname or '', 'path': parsed.path or '/', 'query_present': bool(parsed.query)}


def run_url_check(slug: str, *, root: Path = ROOT, open_request=None,
                  sleep_fn=time.sleep, monotonic_fn=time.monotonic) -> dict:
    client = ApprovedScopeClient(slug, root=root, open_request=open_request,
                                 sleep_fn=sleep_fn, monotonic_fn=monotonic_fn)
    analysis = client.analysis
    rate = client.rate

    checkable = [asset for asset in analysis['assets'] if not asset['query_present']]
    skipped_query = len(analysis['assets']) - len(checkable)
    urls = checkable[:MAX_URLS_PER_RUN]
    output_path = root / 'results' / f'manual-url-check-{slug}.json'
    results: list[dict] = []
    stopped_reason = None

    def save_progress() -> dict:
        payload = {
            'program': slug,
            'method': 'HEAD',
            'requests_per_second': rate,
            'automated_requests': 'operator-approved exact URL checks',
            'total_urls': len(analysis['assets']),
            'checked': len(results),
            'remaining': len(checkable) - len(results),
            'skipped_query_urls': skipped_query,
            'invalid_urls': analysis['invalid_urls'],
            'complete': len(results) == len(checkable),
            'state': 'stopped' if stopped_reason else ('complete' if len(results) == len(checkable) else 'running'),
            'stopped_reason': stopped_reason,
            'results': results,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = output_path.with_name(f'.{output_path.name}.{os.getpid()}.tmp')
        temporary.write_text(json.dumps(payload, indent=2), encoding='utf-8')
        temporary.replace(output_path)
        return payload

    payload = save_progress()
    for asset in urls:
        target = f"{asset['scheme'] or 'https'}://{asset['host']}"
        if asset.get('port'):
            target += f":{asset['port']}"
        target += asset['path']
        try:
            response = client.request(target)
        except (PermissionError, OSError, ValueError) as exc:
            stopped_reason = str(exc)
            return save_progress()
        response_headers = response['headers']
        result = {'host': asset['host'], 'path': asset['path'], 'category': asset['category'],
                  'method': 'HEAD', 'url': target, 'status': response['status'],
                  'server': response_headers.get('server', ''), 'content_type': response_headers.get('content-type', ''),
                  'redirect': response['redirects'][-1] if response['redirects'] else None,
                  'redirects': response['redirects'], 'redirect_stop': response.get('redirect_stop'),
                  'final_url': response['final_url']}
        if response.get('error'):
            result['error'] = response['error']
        results.append(result)
        payload = save_progress()
    if len(results) < len(checkable):
        stopped_reason = 'Per-run URL limit reached'
        payload = save_progress()
    return payload


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit('usage: manual_url_checker.py <program-slug>')
    slug = sys.argv[1]
    lock_path = RESULTS_DIR / '.running' / f'manual-program-{slug}.lock'
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise SystemExit('URL check already running')
    with os.fdopen(descriptor, 'w', encoding='utf-8') as lock:
        lock.write(str(os.getpid()))
    try:
        result = run_url_check(slug)
        print(json.dumps({'program': result['program'], 'checked': result['checked'],
                          'remaining': result['remaining'], 'complete': result['complete']}))
    finally:
        try:
            if lock_path.read_text(encoding='utf-8').strip() == str(os.getpid()):
                lock_path.unlink()
        except OSError:
            pass


if __name__ == '__main__':
    main()