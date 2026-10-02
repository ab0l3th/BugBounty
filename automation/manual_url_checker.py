#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from program_builder import active_approved, load_manual_analysis, read_guidelines

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / 'results'
MAX_URLS_PER_RUN = 500
MAX_REQUESTS_PER_SECOND = 1


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _safe_location(value: str) -> dict:
    parsed = urlsplit(value)
    return {'host': parsed.hostname or '', 'path': parsed.path or '/', 'query_present': bool(parsed.query)}


def run_url_check(slug: str, *, root: Path = ROOT, open_request=None,
                  sleep_fn=time.sleep, monotonic_fn=time.monotonic) -> dict:
    if not active_approved(slug, root=root):
        raise PermissionError('Current program guidelines must be reviewed and approved first')
    _, approved_digest = read_guidelines(slug, root=root)
    analysis = load_manual_analysis(slug, root=root)
    policy = analysis['policy']
    if policy.get('automated_requests') != 'manual_approval_required' or not policy.get('stated_max_requests_per_second'):
        raise PermissionError('Guidelines do not permit the bounded URL check')
    rate = min(MAX_REQUESTS_PER_SECOND, int(policy['stated_max_requests_per_second']))
    interval = 1 / rate
    if open_request is None:
        opener = urllib.request.build_opener(NoRedirect())
        open_request = opener.open

    checkable = [asset for asset in analysis['assets'] if not asset['query_present']]
    skipped_query = len(analysis['assets']) - len(checkable)
    urls = checkable[:MAX_URLS_PER_RUN]
    output_path = root / 'results' / f'manual-url-check-{slug}.json'
    results: list[dict] = []
    last_request = None
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
        if last_request is not None:
            delay = interval - (monotonic_fn() - last_request)
            if delay > 0:
                sleep_fn(delay)
        try:
            _, current_digest = read_guidelines(slug, root=root)
            permitted = current_digest == approved_digest and active_approved(slug, root=root)
        except (OSError, ValueError):
            permitted = False
        if not permitted:
            stopped_reason = 'Approval revoked or guidelines changed; no further requests sent'
            return save_progress()
        request = urllib.request.Request(target, headers={'User-Agent': 'BugBountyScopeCheck/1.0'}, method='HEAD')
        last_request = monotonic_fn()
        result = {'host': asset['host'], 'path': asset['path'], 'category': asset['category'],
                  'method': 'HEAD', 'url': target, 'status': None, 'server': '', 'content_type': '',
                  'redirect': None}
        try:
            with open_request(request, timeout=8) as response:
                result['status'] = getattr(response, 'status', response.getcode())
                response_headers = getattr(response, 'headers', {})
                result['server'] = response_headers.get('Server', '')
                result['content_type'] = response_headers.get('Content-Type', '')
        except urllib.error.HTTPError as exc:
            result['status'] = exc.code
            response_headers = exc.headers or {}
            result['server'] = response_headers.get('Server', '')
            result['content_type'] = response_headers.get('Content-Type', '')
            location = response_headers.get('Location')
            if location:
                result['redirect'] = _safe_location(location)
            exc.close()
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            result['error'] = type(exc).__name__
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
    lock_path = RESULTS_DIR / '.running' / f'manual-url-check-{slug}.lock'
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