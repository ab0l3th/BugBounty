from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen


def build_plan(shop: str, organization: str, *, owned_confirmed=False, alias_confirmed=False,
               store_kind='unknown', include_billing=False) -> dict:
    shop = shop.strip().lower().rstrip('.')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}\.myshopify\.com', shop) or shop == 'your-store.myshopify.com':
        raise ValueError('Use an actual owned myshopify.com hostname')
    if not organization.isdigit() or store_kind not in {'unknown', 'development', 'production'}:
        raise ValueError('Invalid organization or store kind')
    slug = shop.split('.')[0]
    developer = f'https://dev.shopify.com/dashboard/{organization}'
    admin = f'https://admin.shopify.com/store/{slug}'
    targets = [
        {'name': 'development_apps', 'url': developer + '/apps', 'expected': {'owner': 'allowed', 'appdev': 'allowed'}},
        {'name': 'development_stores', 'url': developer + '/stores', 'expected': {'owner': 'allowed', 'appdev': 'allowed'}},
        {'name': 'owned_store_admin', 'url': admin,
         'expected': {'owner': 'allowed', 'appdev': 'denied' if store_kind == 'production' else 'unknown'}},
    ]
    if include_billing:
        targets.append({'name': 'owned_store_billing', 'url': admin + '/settings/billing',
                        'expected': {'owner': 'allowed', 'appdev': 'denied'}})
    return {'shop': shop, 'organization': organization, 'owned_confirmed': owned_confirmed,
            'hackerone_alias_confirmed': alias_confirmed, 'store_kind': store_kind,
            'roles': ['owner', 'appdev'], 'requests_per_second': 1, 'mutations_enabled': False, 'targets': targets}


def validate_plan(plan: dict) -> None:
    if plan.get('owned_confirmed') is not True or plan.get('hackerone_alias_confirmed') is not True:
        raise ValueError('Confirm owned-shop and required HackerOne-alias setup before account checks')
    canonical = build_plan(plan.get('shop', ''), str(plan.get('organization', '')),
                           store_kind=plan.get('store_kind', 'unknown'), include_billing=True)
    allowed = {target['url'] for target in canonical['targets']}
    canonical_targets = {target['url']: target for target in canonical['targets']}
    targets = plan.get('targets', [])
    if not targets or len(targets) > len(allowed) or any(target.get('url') not in allowed for target in targets):
        raise ValueError('Target must be a selected route in this owned shop/organization')
    if plan.get('mutations_enabled') is not False:
        raise ValueError('This runner does not support mutations')
    if plan.get('roles') != ['owner', 'appdev'] or plan.get('requests_per_second') != 1:
        raise ValueError('Use the fixed isolated owner/appdev matrix at one request per second')
    if len({target['url'] for target in targets}) != len(targets) or any(target != canonical_targets[target['url']] for target in targets):
        raise ValueError('Target labels and role expectations must match the canonical matrix')


def private_write(path: Path, payload: dict | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError('Refuse symlink output')
    descriptor, filename = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            if isinstance(payload, str):
                handle.write(payload)
            else:
                json.dump(payload, handle, indent=2)
        os.replace(filename, path)
    finally:
        Path(filename).unlink(missing_ok=True)


def private_read(path: Path) -> dict:
    info = path.stat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise ValueError('Plan/session files must be owner-only regular files')
    if info.st_size > 5 * 1024 * 1024:
        raise ValueError('Plan/session file is too large')
    return json.loads(path.read_text(encoding='utf-8'))


def read_only_request(method: str, url: str, post_data=None) -> bool:
    if re.search(r'(?:^|/)(?:delete|destroy|remove|uninstall|logout|signout|reset)(?:/|$)', urlsplit(url).path, re.IGNORECASE):
        return False
    if method in {'GET', 'HEAD', 'OPTIONS'}:
        if 'graphql' in urlsplit(url).path.lower():
            parameters = parse_qs(urlsplit(url).query)
            if 'extensions' in parameters or any(re.search(r'\bmutation\b|\bsubscription\b', query) for query in parameters.get('query', [])):
                return False
        return True
    if method != 'POST' or 'graphql' not in urlsplit(url).path.lower() or not post_data:
        return False
    try:
        data = json.loads(post_data)
    except (ValueError, TypeError):
        return False
    operations = data if isinstance(data, list) else [data]
    if not operations:
        return False
    for operation in operations:
        if isinstance(operation, dict) and isinstance(operation.get('extensions'), dict) and operation['extensions'].get('persistedQuery'):
            return False
        query = operation.get('query', '') if isinstance(operation, dict) else ''
        if not isinstance(query, str) or not query.strip().startswith(('query ', 'query(', 'query\n', '{')):
            return False
        if re.search(r'\bmutation\b|\bsubscription\b', query):
            return False
    return True


def navigation_allowed(url: str, plan: dict, *, allow_login=True) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port not in {None, 443}:
        return False
    for key, values in parse_qs(parsed.query).items():
        if key.lower() in {'shop', 'store', 'shop_domain', 'store_domain'} and any(value not in {plan['shop'], plan['shop'].split('.')[0]} for value in values):
            return False
        if key.lower() in {'organization', 'organization_id', 'organizationid'} and any(value != plan['organization'] for value in values):
            return False
    prefix = '/dashboard/' + plan['organization']
    if parsed.hostname == 'dev.shopify.com' and (parsed.path == prefix or parsed.path.startswith(prefix + '/')):
        return True
    prefix = '/store/' + plan['shop'].split('.')[0]
    if parsed.hostname == 'admin.shopify.com' and (parsed.path == prefix or parsed.path.startswith(prefix + '/')):
        return True
    return allow_login and parsed.hostname in {'accounts.shopify.com', 'accounts.shopifycloud.com'}


def resource_allowed(url: str, plan: dict) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port not in {None, 443}:
        return False
    if parsed.hostname in {'cdn.shopify.com', 'cdn.shopifycdn.net'}:
        return True
    if parsed.hostname == plan['shop']:
        return not parsed.query
    if parsed.hostname in {'dev.shopify.com', 'admin.shopify.com'}:
        if parsed.path.startswith(('/dashboard/', '/store/')):
            return navigation_allowed(url, plan, allow_login=False)
        return parsed.path.startswith(('/assets/', '/static/'))
    return False


def classify_observation(status: int | None, final_url: str, text: str, expected: str,
                         *, blocked_requests=0, navigation_error=False) -> dict:
    lowered = text.lower()
    host = urlsplit(final_url).hostname or ''
    login = host in {'accounts.shopify.com', 'accounts.shopifycloud.com'} or any(marker in lowered for marker in ('log in to shopify', 'sign in to shopify', 'enter your email to continue'))
    denied = status in {401, 403} or any(marker in lowered for marker in ('you do not have permission', "you don't have permission", 'access denied', 'not authorized to access'))
    if login:
        observed = 'login_required'
    elif navigation_error or blocked_requests or status is None:
        observed = 'inconclusive'
    elif status == 404:
        observed = 'route_unavailable'
    elif denied:
        observed = 'denied'
    else:
        observed = 'reachable_unverified'
    review = expected == 'denied' and observed == 'reachable_unverified'
    return {'observed': observed, 'expected': expected, 'manual_review_required': review,
            'confirmed_vulnerability': False,
            'reason': 'A reachable admin shell is not proof of protected-data access' if review else 'Read-only observation; permissions require independent confirmation'}


def _ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError('Refuse symlink profile directory')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('Profile directory must be owned by the current user')
    os.chmod(path, 0o700)


def _state_fingerprint(state: dict) -> str:
    return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()


def _edge_binary() -> str:
    mac_edge = Path('/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge')
    if mac_edge.is_file() and os.access(mac_edge, os.X_OK):
        return str(mac_edge)
    for name in ('msedge', 'microsoft-edge'):
        executable = shutil.which(name)
        if executable:
            return executable
    raise RuntimeError('Microsoft Edge executable not found')


def _edge_launch_args(binary: str, profile_dir: Path, port: int, start_url: str) -> list[str]:
    return [binary, f'--user-data-dir={profile_dir}', '--remote-debugging-address=127.0.0.1',
            f'--remote-debugging-port={port}', '--no-first-run', '--no-default-browser-check',
            '--disable-background-mode', start_url]


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def _clear_stale_edge_locks(profile_dir: Path) -> None:
    commands = subprocess.run(['ps', '-axo', 'command'], capture_output=True, text=True, check=False).stdout
    profile_arg = f'--user-data-dir={profile_dir.resolve()}'
    if profile_arg in commands:
        raise RuntimeError('The selected Edge profile is already open; close it before running checks')
    for name in ('SingletonLock', 'SingletonCookie', 'SingletonSocket'):
        marker = profile_dir / name
        try:
            info = marker.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            raise RuntimeError('Unexpected directory in Edge profile lock location')
        marker.unlink()


def _wait_for_edge_debugger(endpoint: str, process: subprocess.Popen, timeout=20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('Microsoft Edge exited before its local debugger was ready')
        try:
            with urlopen(endpoint + '/json/version', timeout=0.5):
                return
        except Exception:
            time.sleep(0.1)
    raise TimeoutError('Microsoft Edge local debugger did not become ready')


def _launch_edge(profile_dir: Path, start_url: str) -> tuple[subprocess.Popen, str]:
    _clear_stale_edge_locks(profile_dir)
    port = _free_loopback_port()
    endpoint = f'http://127.0.0.1:{port}'
    process = subprocess.Popen(_edge_launch_args(_edge_binary(), profile_dir, port, start_url),
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        _wait_for_edge_debugger(endpoint, process)
    except Exception:
        _stop_edge(process)
        raise
    return process, endpoint


def _connect_edge(playwright, endpoint: str):
    if not endpoint.startswith('http://127.0.0.1:'):
        raise ValueError('Edge debugger endpoint must be loopback-only')
    browser = playwright.chromium.connect_over_cdp(endpoint, timeout=10000)
    if not browser.contexts:
        browser.close()
        raise RuntimeError('Edge has no browser context')
    return browser, browser.contexts[0]


def _stop_edge(process: subprocess.Popen, browser=None) -> None:
    if browser is not None:
        try:
            browser.close()
        except Exception:
            pass
    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass


def capture_session(plan: dict, role: str, directory: Path, *, browser_name='edge') -> None:
    validate_plan(plan)
    if role not in plan['roles']:
        raise ValueError('Unsupported account role')
    if browser_name != 'edge':
        raise ValueError('Only ordinary Microsoft Edge is supported for account authentication')
    _ensure_private_directory(directory)
    profile_root = directory / browser_name
    _ensure_private_directory(profile_root)
    profile_dir = profile_root / role
    _ensure_private_directory(profile_dir)
    process, endpoint = _launch_edge(profile_dir, f'https://dev.shopify.com/dashboard/{plan["organization"]}')
    try:
        print(f'Log in directly in the standalone Microsoft Edge window as {role}. Do not paste credentials into this terminal or chat.')
        input('After confirming the requested account/role in Microsoft Edge, press Enter to save its private profile: ')
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = None
            try:
                browser, context = _connect_edge(playwright, endpoint)
                pages = context.pages
                page = next((item for item in pages if navigation_allowed(item.url, plan, allow_login=False)), None)
                if page is None or urlsplit(page.url).hostname != 'dev.shopify.com':
                    print('Session not saved: return to the selected developer organization after login, then capture again.')
                    return
                fingerprint = _state_fingerprint(context.storage_state())
                other_role = 'appdev' if role == 'owner' else 'owner'
                other_metadata = profile_root / f'{other_role}.metadata.json'
                if other_metadata.exists() and private_read(other_metadata).get('profile_fingerprint') == fingerprint:
                    print('Session not saved: this profile matches the other role; sign in with the separate account.')
                    return
                private_write(profile_root / f'{role}.metadata.json', {'role': role, 'shop': plan['shop'],
                                                                      'organization': plan['organization'], 'browser': browser_name,
                                                                      'role_confirmation': 'user_attestation',
                                                                      'profile_fingerprint': fingerprint,
                                                                      'captured_at': int(time.time())})
                print(f'{role} {browser_name} profile saved privately. Never share these files or commit them.')
            finally:
                _stop_edge(process, browser)
    finally:
        if process.poll() is None:
            _stop_edge(process)


def _profile_pair(plan: dict, directory: Path, browser_name: str) -> dict:
    profile_root = directory / browser_name
    for path in (directory, profile_root):
        info = path.stat()
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError('Profile directories must be owner-only regular directories')
    profiles = {}
    fingerprints = set()
    for role in plan['roles']:
        profile_dir = profile_root / role
        metadata = private_read(profile_root / f'{role}.metadata.json')
        info = profile_dir.stat()
        if profile_dir.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError('Each role needs a private, owner-only browser profile')
        if (metadata.get('role') != role or metadata.get('shop') != plan['shop'] or
                metadata.get('organization') != plan['organization'] or metadata.get('browser') != browser_name):
            raise ValueError('Browser profile belongs to a different role/shop/organization/browser')
        fingerprint = metadata.get('profile_fingerprint')
        if not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint) or fingerprint in fingerprints:
            raise ValueError('Owner and appdev must have distinct captured sessions')
        fingerprints.add(fingerprint)
        profiles[role] = profile_dir
    return profiles


def run_checks(plan: dict, directory: Path, *, browser_name='edge', progress=None) -> dict:
    validate_plan(plan)
    profiles = _profile_pair(plan, directory, browser_name)
    from playwright.sync_api import sync_playwright
    rows = []
    last_main = None
    last_first_party = [None]
    with sync_playwright() as playwright:
        for role in plan['roles']:
            process, endpoint = _launch_edge(profiles[role], 'about:blank')
            browser = None
            try:
                browser, context = _connect_edge(playwright, endpoint)
                blocked = {'count': 0}

                def block_websocket(socket):
                    blocked['count'] += 1
                    socket.close()

                context.route_web_socket('**/*', block_websocket)

                def guard(route):
                    req = route.request
                    if not req.is_navigation_request():
                        if not read_only_request(req.method, req.url, req.post_data):
                            blocked['count'] += 1
                        route.abort()
                        return
                    if req.is_navigation_request() and not navigation_allowed(req.url, plan):
                        blocked['count'] += 1
                        route.abort()
                        return
                    if not read_only_request(req.method, req.url, req.post_data):
                        blocked['count'] += 1
                        route.abort()
                        return
                    previous = last_first_party[0]
                    if previous is not None:
                        delay = 1 - (time.monotonic() - previous)
                        if delay > 0:
                            time.sleep(delay)
                    last_first_party[0] = time.monotonic()
                    route.continue_()

                context.route('**/*', guard)
                page = context.pages[0] if context.pages else context.new_page()
                context.on('page', lambda popup: popup.close())
                for target in plan['targets']:
                    if progress:
                        progress(f"{role}/{target['name']}: navigating")
                    if last_main is not None:
                        delay = 1 - (time.monotonic() - last_main)
                        if delay > 0:
                            time.sleep(delay)
                    blocked['count'] = 0
                    status = None
                    navigation_error = False
                    last_main = time.monotonic()
                    try:
                        response = page.goto(target['url'], wait_until='commit', timeout=20000)
                        status = response.status if response else None
                    except Exception:
                        navigation_error = True
                    observed = classify_observation(status, page.url, '', target['expected'].get(role, 'unknown'),
                                                    blocked_requests=blocked['count'], navigation_error=navigation_error)
                    final = urlsplit(page.url)
                    selected_paths = {urlsplit(selected['url']).path for selected in plan['targets']}
                    safe_path = '/login' if final.hostname in {'accounts.shopify.com', 'accounts.shopifycloud.com'} else final.path if final.path in selected_paths else '[unselected path withheld]'
                    rows.append({'role': role, 'target': target['name'], 'url': target['url'], 'http_status': status,
                                 'final_host': final.hostname, 'final_path': safe_path, 'query_present': bool(final.query),
                                 'blocked_requests': blocked['count'], **observed})
                    if progress:
                        progress(f"{role}/{target['name']}: HTTP {status if status is not None else 'none'}, {observed['observed']}")
                    if observed['observed'] == 'login_required':
                        break
            finally:
                _stop_edge(process, browser)
    return {'program': 'shopify', 'job': 'shopify-owned-account-checks', 'shop': plan['shop'],
            'generated_at': int(time.time()),
            'organization': plan['organization'], 'test_selection': 'read_only_account_comparison',
            'mutating_requests': False, 'rows': rows, 'confirmed_findings': [],
            'session_values_saved_in_report': False, 'interpretation': 'Unverified access observations; manual confirmation required'}


def report_markdown(report: dict) -> str:
    lines = ['# Owned Shopify Account Comparison', '', f"Shop: {report['shop']}",
             'Read-only observations only. No confirmed vulnerability is inferred from a reachable page.', '',
             '| Role | Target | Expected | Observed | HTTP | Manual Review |',
             '|---|---|---|---|---|---|']
    for row in report['rows']:
        lines.append(f"| {row['role']} | {row['target']} | {row['expected']} | {row['observed']} | {row['http_status']} | {'Yes' if row['manual_review_required'] else 'No'} |")
    lines.extend(['', '## Verification Notes',
                  '- Reconfirm account identity and actual assigned role; capture labels are user attestations.',
                  '- A 200/SPA shell or visible navigation item is not proof of protected data or action access.',
                  '- Blocked unknown POST/persisted operations, route changes, or expired sessions can make results inconclusive.',
                  '- No raw response bodies, screenshots, cookies, local storage, or tokens are included.',
                  '- Do not report intentional GraphQL introspection or intended public behavior alone.'])
    return '\n'.join(lines) + '\n'


def main() -> None:
    parser = argparse.ArgumentParser(description='Explicit read-only checks on owned Shopify accounts')
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare')
    prepare.add_argument('--shop', required=True)
    prepare.add_argument('--organization', required=True)
    prepare.add_argument('--store-kind', choices=['unknown', 'development', 'production'], default='unknown')
    prepare.add_argument('--confirm-owned', action='store_true', required=True)
    prepare.add_argument('--confirm-alias', action='store_true', required=True)
    prepare.add_argument('--include-billing', action='store_true')
    for name in ('prepare', 'capture', 'run'):
        command = prepare if name == 'prepare' else commands.add_parser(name)
        command.add_argument('--plan', type=Path, default=Path('.secrets/shopify-account-plan.json'))
        if name != 'prepare':
            command.add_argument('--profiles', type=Path, default=Path('.secrets/shopify-account-profiles'))
        if name == 'capture':
            command.add_argument('--role', choices=['owner', 'appdev'], required=True)
            command.add_argument('--browser', choices=['edge'], default='edge')
        if name == 'run':
            command.add_argument('--browser', choices=['edge'], default='edge')
            command.add_argument('--output', type=Path, default=Path('results/shopify-owned-account-checks.json'))
    args = parser.parse_args()
    if args.command == 'prepare':
        plan = build_plan(args.shop, args.organization, owned_confirmed=args.confirm_owned, alias_confirmed=args.confirm_alias,
                          store_kind=args.store_kind, include_billing=args.include_billing)
        validate_plan(plan)
        private_write(args.plan, plan)
        print('Owned-target plan saved. No network requests or scans started.')
        return
    plan = private_read(args.plan)
    if args.command == 'capture':
        capture_session(plan, args.role, args.profiles, browser_name=args.browser)
        return
    report = run_checks(plan, args.profiles, browser_name=args.browser,
                        progress=lambda message: print(message, flush=True))
    private_write(args.output, report)
    markdown = args.output.with_suffix('.md')
    private_write(markdown, report_markdown(report))
    print(json.dumps({'checks': len(report['rows']), 'manual_review_required': sum(row['manual_review_required'] for row in report['rows']),
                      'confirmed_findings': 0, 'mutating_requests': False}))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('Stopped by operator; no browser/session details logged')
    except ModuleNotFoundError:
        raise SystemExit('Install the account-check requirements and Microsoft Edge; see automation/README.md')
    except Exception:
        raise SystemExit('Account check failed. Check private plan/session permissions, role capture, and browser setup. Sensitive exception details withheld.')