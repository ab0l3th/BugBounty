from pathlib import Path
from tempfile import TemporaryDirectory
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'automation'))

from shopify_policy import apply_finding_eligibility, host_allowed, register_pending_store


class ShopifyPolicyTest(unittest.TestCase):
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