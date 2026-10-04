from pathlib import Path
from tempfile import TemporaryDirectory
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'automation'))

from shopify_policy import apply_finding_eligibility, host_allowed, register_pending_store


class ShopifyPolicyTest(unittest.TestCase):
    def test_account_plan_and_read_only_checks_are_confined_and_conservative(self):
        from shopify_account_checks import build_plan, validate_plan, read_only_request, navigation_allowed, resource_allowed, classify_observation
        plan = build_plan('owned-example.myshopify.com', '12345', owned_confirmed=True, alias_confirmed=True,
                          store_kind='production', include_billing=True)
        validate_plan(plan)
        self.assertFalse(navigation_allowed('https://admin.shopify.com/store/other/settings', plan))
        self.assertFalse(navigation_allowed('https://admin.shopify.com/store/owned-example?shop=other.myshopify.com', plan))
        self.assertTrue(navigation_allowed('https://dev.shopify.com/dashboard/12345/apps', plan))
        self.assertFalse(resource_allowed('https://dev.shopify.com/dashboard/99999/apps', plan))
        self.assertFalse(resource_allowed('https://admin.shopify.com/api/graphql', plan))
        self.assertFalse(resource_allowed('https://other.myshopify.com/admin', plan))
        self.assertTrue(resource_allowed('https://cdn.shopify.com/shopifycloud/admin/assets/app.js', plan))
        self.assertFalse(navigation_allowed('https://admin.shopify.com:444/store/owned-example', plan))
        self.assertTrue(read_only_request('POST', 'https://admin.shopify.com/graphql', '{"query":"query Read { shop { id } }"}'))
        self.assertFalse(read_only_request('POST', 'https://admin.shopify.com/graphql', '{"query":"mutation Change { shopUpdate { id } }"}'))
        self.assertFalse(read_only_request('POST', 'https://admin.shopify.com/graphql', '{"extensions":{"persistedQuery":{"sha256Hash":"unknown"}}}'))
        self.assertFalse(read_only_request('DELETE', 'https://admin.shopify.com/store/owned-example'))
        self.assertFalse(read_only_request('GET', 'https://admin.shopify.com/store/owned-example/logout'))
        self.assertFalse(read_only_request('GET', 'https://admin.shopify.com/graphql?query=mutation%20Change%20%7B%20deleteShop%20%7D'))
        observation = classify_observation(200, plan['targets'][-1]['url'], 'Admin HTML shell', 'denied')
        self.assertFalse(observation['confirmed_vulnerability'])
        self.assertTrue(observation['manual_review_required'])
        self.assertEqual(classify_observation(200, 'https://accounts.shopify.com/login', 'Login', 'denied')['observed'], 'login_required')
        self.assertEqual(classify_observation(200, plan['targets'][0]['url'], 'Partial shell', 'allowed', blocked_requests=1)['observed'], 'inconclusive')

    def test_private_account_session_files_and_reports_never_expose_tokens(self):
        from shopify_account_checks import build_plan, private_write, private_read, _session_pair, report_markdown
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = root / 'sessions'
            sessions.mkdir(mode=0o700)
            plan = build_plan('owned-example.myshopify.com', '12345', owned_confirmed=True, alias_confirmed=True)
            state = {'cookies': [{'name': 'test-session', 'value': 'private-session-value', 'domain': '.shopify.com', 'path': '/'}], 'origins': []}
            for role in ('owner', 'appdev'):
                private_write(sessions / f'{role}.json', state)
                private_write(sessions / f'{role}.metadata.json', {'role': role, 'shop': plan['shop'], 'organization': plan['organization']})
            with self.assertRaises(ValueError):
                _session_pair(plan, sessions)
            (sessions / 'owner.json').chmod(0o644)
            with self.assertRaises(ValueError):
                private_read(sessions / 'owner.json')
            markdown = report_markdown({'shop': plan['shop'], 'rows': [{'role': 'appdev', 'target': 'owned_store_admin', 'expected': 'denied',
                                      'observed': 'reachable_unverified', 'http_status': 200, 'manual_review_required': True}]})
            self.assertNotIn('private-session-value', markdown)
            self.assertIn('not proof', markdown)

    def test_account_browser_runner_isolated_read_only_and_sanitized(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock, patch
        from shopify_account_checks import build_plan, private_write, run_checks
        plan = build_plan('owned-example.myshopify.com', '12345', owned_confirmed=True, alias_confirmed=True, store_kind='production')
        factory = MagicMock()
        browser = factory.return_value.__enter__.return_value.chromium.launch.return_value
        contexts = [MagicMock(), MagicMock()]
        browser.new_context.side_effect = contexts
        for context in contexts:
            page = context.new_page.return_value
            page.goto.return_value.status = 200
            page.url = plan['targets'][0]['url'] + '?token=private-response-token'
            page.locator.return_value.inner_text.return_value = 'Admin shell private-response-body'
        with TemporaryDirectory() as directory:
            sessions = Path(directory)
            sessions.chmod(0o700)
            for role in ('owner', 'appdev'):
                private_write(sessions / f'{role}.json', {'cookies': [{'name': 'session', 'value': role + '-private-cookie'}], 'origins': []})
                private_write(sessions / f'{role}.metadata.json', {'role': role, 'shop': plan['shop'], 'organization': plan['organization']})
            with patch.dict(sys.modules, {'playwright': SimpleNamespace(), 'playwright.sync_api': SimpleNamespace(sync_playwright=factory)}), patch('shopify_account_checks.time.sleep'):
                report = run_checks(plan, sessions)
        self.assertEqual(len(report['rows']), 6)
        self.assertTrue(report['rows'][-1]['manual_review_required'])
        self.assertFalse(report['rows'][-1]['confirmed_vulnerability'])
        serialized = json.dumps(report)
        self.assertNotIn('private-cookie', serialized)
        self.assertNotIn('private-response-token', serialized)
        self.assertNotIn('private-response-body', serialized)
        for context in contexts:
            context.route_web_socket.assert_called_once()
            context.close.assert_called_once()
            guard = context.route.call_args.args[1]
            route = MagicMock()
            route.request.url = 'https://other.myshopify.com/admin'
            route.request.is_navigation_request.return_value = True
            guard(route)
            route.abort.assert_called_once()
        browser.close.assert_called_once()

    def test_account_session_capture_refuses_login_page(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock, patch
        from shopify_account_checks import build_plan, capture_session
        plan = build_plan('owned-example.myshopify.com', '12345', owned_confirmed=True, alias_confirmed=True)
        browser = MagicMock()
        context = browser.new_context.return_value
        context.new_page.return_value.url = 'https://accounts.shopify.com/login'
        playwright = SimpleNamespace(chromium=SimpleNamespace(launch=MagicMock(return_value=browser)))
        manager = MagicMock()
        manager.__enter__.return_value = playwright
        with TemporaryDirectory() as directory, patch.dict(sys.modules, {'playwright': SimpleNamespace(), 'playwright.sync_api': SimpleNamespace(sync_playwright=MagicMock(return_value=manager))}), patch('builtins.input', return_value=''), patch('shopify_account_checks.private_write') as write, patch('builtins.print') as output:
            capture_session(plan, 'owner', Path(directory))
        write.assert_not_called()
        output.assert_any_call('Session not saved: return to the selected developer organization after login, then capture again.')
        context.close.assert_called_once()
        browser.close.assert_called_once()

    def test_pending_owned_store_is_recorded_but_not_enabled(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / 'programs/shopify'
            folder.mkdir(parents=True)
            registered = register_pending_store('shopify', 'owned-example.myshopify.com', root)
            self.assertEqual(registered['status'], 'pending_setup_confirmation')
            self.assertFalse(host_allowed('owned-example.myshopify.com', 'shopify', root))
            self.assertFalse(host_allowed('some-merchant.myshopify.com', 'shopify', root))
            self.assertFalse(host_allowed('your-store.myshopify.com', 'shopify', root))
            self.assertEqual((folder / '.shopify-controls.json').stat().st_mode & 0o777, 0o600)
            register_pending_store('shopify', 'owned-example.myshopify.com', root)
            self.assertEqual(len(json.loads((folder / '.shopify-controls.json').read_text())['owned_stores']), 1)

    def test_instruction_exclusions_and_unknown_cloud_hosts_are_blocked(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for host in ('vendorvoice.shopifycloud.com', 'nsolid-test-console.shopifycloud.com',
                         'devdegree-test.shopifycloud.com', 'invoices.shopify.io', 'factures.shopify.io',
                         'cdn.shopify.com', 'unknown-test.shopifykloud.com'):
                self.assertFalse(host_allowed(host, 'shopify', root), host)
            self.assertTrue(host_allowed('partners.shopify.com', 'shopify', root))
            self.assertTrue(host_allowed('cdn.shopify.com', 'other-program', root))

    def test_introspection_is_an_observation_only_for_shopify(self):
        payload = {'program': 'shopify', 'assets': [{'domain': 'app.shopify.com', 'findings': [
            {'type': 'graphql_introspection', 'severity': 'high'},
            {'type': 'debug_endpoint', 'path': '/backend/graphql', 'severity': 'high'},
            {'type': 'error_disclosure', 'severity': 'medium'}]}]}
        with TemporaryDirectory() as directory:
            result = apply_finding_eligibility(payload, Path(directory))
            self.assertEqual(len(result['assets'][0]['findings']), 1)
            self.assertEqual(len(result['assets'][0]['policy_observations']), 2)
            other = {'program': 'other-program', 'assets': [{'findings': [{'type': 'graphql_introspection', 'severity': 'medium'}]}]}
            self.assertEqual(len(apply_finding_eligibility(other, Path(directory))['assets'][0]['findings']), 1)

    def test_csv_instruction_review_keeps_placeholder_and_ambiguous_cloud_scope_manual(self):
        from program_builder import partition_csv_scope
        content = ('identifier,asset_type,in_scope,instruction\n'
                   'your-store.myshopify.com,URL,true,Your development store\n'
                   '*.shopifycloud.com,WILDCARD,true,May include developer test or third party applications\n'
                   'partners.shopify.com,URL,true,Core\n')
        partitions = partition_csv_scope(content)
        self.assertEqual([asset['identifier'] for asset in partitions['automatic']], ['partners.shopify.com'])
        self.assertEqual(len(partitions['manual']), 2)
        self.assertIn('instructions', partitions['manual'][0])

    def test_shopify_admin_store_context_and_guarded_exclusions_require_owned_setup(self):
        from shopify_policy import url_allowed
        from program_builder import create_program, configure_auto_run, read_guidelines, set_active_approval
        from auto_run import AutoRunGuard
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('shopify', ['*.shopify.com', '*.shopifycloud.com', '*.myshopify.com'], root=root,
                           guidelines="Shopify's Bug Bounty Program. Automated checks within scope.")
            _, digest = read_guidelines('shopify', root=root)
            set_active_approval('shopify', True, digest, root=root)
            configure_auto_run('shopify', root=root)
            guard = AutoRunGuard('shopify', root=root)
            guard.scope = ['*.shopify.com', '*.shopifycloud.com', '*.myshopify.com']
            self.assertFalse(guard.permits_url('https://other-merchant.myshopify.com/'))
            self.assertFalse(guard.permits_url('https://cdn.shopify.com/'))
            self.assertFalse(guard.permits_url('https://vendorvoice.shopifycloud.com/'))
            self.assertFalse(guard.permits_url('https://admin.shopify.com/store/other-merchant/orders'))
            self.assertFalse(url_allowed('https://partners.shopify.com/?shop=other-merchant.myshopify.com', 'shopify', root))
            self.assertTrue(guard.permits_url('https://partners.shopify.com/'))

    def test_explicit_listed_platform_host_remains_allowed_and_pending_store_is_visible(self):
        from program_builder import create_program
        from dashboard_app import app
        from unittest.mock import patch
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('shopify', ['partners.shopify.com', 'arrive-server.shopifycloud.com'], root=root, guidelines="Shopify's Bug Bounty Program.")
            folder = root / 'programs/shopify'
            (folder / 'scope-source.csv').write_text('identifier,asset_type,eligible_for_bounty,eligible_for_submission\narrive-server.shopifycloud.com,URL,true,true\n')
            register_pending_store('shopify', 'owned-example.myshopify.com', root)
            self.assertTrue(host_allowed('arrive-server.shopifycloud.com', 'shopify', root))
            self.assertFalse(host_allowed('random.shopifycloud.com', 'shopify', root))
            with patch('dashboard_app.ROOT', root), patch('dashboard_app.JOBS_DIR', root / 'jobs'), patch('dashboard_app.RESULTS_DIR', root / 'results'):
                page = app.test_client().get('/')
            self.assertEqual(page.status_code, 200)
            self.assertIn(b'owned-example.myshopify.com', page.data)
            self.assertIn(b'pending_setup_confirmation', page.data)
            self.assertIn(b'testing disabled', page.data)

    def test_intentional_shopify_signals_never_become_ntfy_alerts(self):
        from ntfy_notifier import finding_signals
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = {'program': 'shopify', 'job': 'shopify-api-testing', 'assets': [{'domain': 'api.shopify.com', 'findings': [
                {'type': 'graphql_introspection', 'severity': 'critical'},
                {'type': 'debug_endpoint', 'path': '/service/graphql', 'severity': 'high'}]}]}
            self.assertEqual(finding_signals(payload, root=root), [])