import sys
import io
import json
import unittest
from email.message import Message
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'automation') not in sys.path:
    sys.path.insert(0, str(ROOT / 'automation'))

from manual_url_checker import ApprovedScopeClient, run_url_check
from program_builder import create_manual_program, read_guidelines, set_active_approval
from manual_workflow import queue_manual_workflow, run_manual_stage, stage_block_reason
from stages import STAGES


class ManualUrlCheckerTest(unittest.TestCase):
    def _make_approved_program(self, root):
        content = (
            'identifier,asset_type,in_scope\n'
            'https://app.example.com/login,URL,true\n'
            'https://app.example.com/account?key=secret,URL,true\n'
        )
        create_manual_program('sample', content, 'Requests must not exceed 3 requests per second.',
                              {'eligible_asset_types': {'URL': 2}, 'manual_only': True}, root=root)
        _, digest = read_guidelines('sample', root=root)
        set_active_approval('sample', True, digest, root=root)

    def test_head_check_is_bounded_exact_skips_query_and_does_not_follow_redirect(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._make_approved_program(root)
            calls = []
            sleeps = []
            now = [0.0]

            class FakeResponse:
                status = 200
                headers = {'Server': 'example', 'Content-Type': 'text/html'}
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def getcode(self): return self.status
                def read(self, *args): raise AssertionError('HEAD checker must not read response bodies')

            def fake_open(request, timeout=8):
                calls.append((request.full_url, request.get_method(), timeout))
                headers = Message()
                headers['Location'] = 'https://login.example.com/signin?token=private'
                headers['Server'] = 'edge'
                raise HTTPError(request.full_url, 302, 'redirect', headers, None)

            def fake_sleep(delay):
                sleeps.append(delay)
                now[0] += delay

            with patch('manual_url_checker.active_approved', return_value=True):
                result = run_url_check('sample', root=root, open_request=fake_open,
                                       sleep_fn=fake_sleep, monotonic_fn=lambda: now[0])

            self.assertEqual(calls, [('https://app.example.com/login', 'HEAD', 8)])
            self.assertEqual(result['checked'], 1)
            self.assertEqual(result['remaining'], 0)
            self.assertEqual(result['skipped_query_urls'], 1)
            self.assertTrue(result['complete'])
            self.assertEqual(result['results'][0]['status'], 302)
            self.assertEqual(result['results'][0]['redirect'], {'host': 'login.example.com', 'path': '/signin', 'query_present': True})
            self.assertNotIn('private', str(result))
            self.assertEqual(sleeps, [])

    def test_unapproved_rules_prevent_any_request(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._make_approved_program(root)
            with patch('manual_url_checker.active_approved', return_value=False):
                with self.assertRaises(PermissionError):
                    run_url_check('sample', root=root, open_request=lambda *args, **kwargs: self.fail('request should not be sent'))

    def test_all_query_urls_are_persisted_as_skipped_without_requests(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            content = 'identifier,asset_type,in_scope\nhttps://app.example.com/page?key=value,URL,true\n'
            create_manual_program('sample', content, 'Maximum 3 requests per second.',
                                  {'eligible_asset_types': {'URL': 1}, 'manual_only': True}, root=root)
            with patch('manual_url_checker.active_approved', return_value=True):
                result = run_url_check('sample', root=root,
                                       open_request=lambda *args, **kwargs: self.fail('query URL must be skipped'))
            self.assertEqual(result['checked'], 0)
            self.assertEqual(result['remaining'], 0)
            self.assertEqual(result['skipped_query_urls'], 1)
            self.assertTrue(result['complete'])
            self.assertTrue((root / 'results/manual-url-check-sample.json').exists())

    def test_multiple_urls_are_spaced_to_one_request_per_second(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            content = ('identifier,asset_type,in_scope\n'
                       'one.example.com,URL,true\n'
                       'two.example.com,URL,true\n')
            create_manual_program('sample', content, 'Traffic must not exceed 3 requests per second.',
                                  {'eligible_asset_types': {'URL': 2}, 'manual_only': True}, root=root)
            _, digest = read_guidelines('sample', root=root)
            set_active_approval('sample', True, digest, root=root)
            calls = []
            sleeps = []
            now = [0.0]

            class FakeResponse:
                status = 200
                headers = {'Server': 'origin'}
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def getcode(self): return self.status
                def read(self, *args): raise AssertionError('checker must not read response body')

            def fake_open(request, timeout=8):
                calls.append((request.full_url, request.get_method()))
                return FakeResponse()

            def fake_sleep(delay):
                sleeps.append(delay)
                now[0] += delay

            with patch('manual_url_checker.active_approved', return_value=True):
                result = run_url_check('sample', root=root, open_request=fake_open,
                                       sleep_fn=fake_sleep, monotonic_fn=lambda: now[0])
            self.assertEqual([method for _, method in calls], ['HEAD', 'HEAD'])
            self.assertEqual(sleeps, [1.0])
            self.assertEqual(result['checked'], 2)
            self.assertTrue(result['complete'])

    def test_in_scope_non_login_redirect_is_followed_at_one_rps(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_manual_program('sample', 'identifier,asset_type,in_scope\napp.example.com,URL,true\n',
                                  'Maximum 3 requests per second.', {'manual_only': True}, root=root)
            _, digest = read_guidelines('sample', root=root)
            set_active_approval('sample', True, digest, root=root)
            calls = []
            sleeps = []
            now = [0.0]

            def fake_open(request, timeout=8):
                calls.append((request.full_url, request.get_method()))
                headers = Message()
                if len(calls) == 1:
                    headers['Location'] = '/public'
                raise HTTPError(request.full_url, 302 if len(calls) == 1 else 200, 'response', headers, None)

            def fake_sleep(delay):
                sleeps.append(delay)
                now[0] += delay

            result = run_url_check('sample', root=root, open_request=fake_open,
                                   sleep_fn=fake_sleep, monotonic_fn=lambda: now[0])
            self.assertEqual(calls, [('https://app.example.com/', 'HEAD'), ('https://app.example.com/public', 'HEAD')])
            self.assertEqual(sleeps, [1.0])
            self.assertEqual(result['results'][0]['final_url'], 'https://app.example.com/public')

    def test_redirects_stop_before_login_scope_exit_query_or_downgrade(self):
        for destination, expected in [('/login', 'login_redirect'), ('https://sso.app.example.com/', 'login_redirect'),
                                       ('https://outside.example.com/', 'outside_scope'), ('/public?token=secret', 'outside_scope'),
                                       ('http://app.example.com/', 'https_downgrade')]:
            with self.subTest(destination=destination), TemporaryDirectory() as directory:
                root = Path(directory)
                create_manual_program('sample', 'identifier,asset_type,in_scope\napp.example.com,URL,true\n',
                                      'Maximum 3 requests per second.', {'manual_only': True}, root=root)
                _, digest = read_guidelines('sample', root=root)
                set_active_approval('sample', True, digest, root=root)
                calls = []

                def fake_open(request, timeout=8):
                    calls.append(request.full_url)
                    headers = Message()
                    headers['Location'] = destination
                    raise HTTPError(request.full_url, 302, 'redirect', headers, None)

                result = run_url_check('sample', root=root, open_request=fake_open)
                self.assertEqual(len(calls), 1)
                self.assertEqual(result['results'][0]['redirect_stop'], expected)
                self.assertNotIn('token=secret', str(result))

    def test_exact_url_scope_does_not_expand_into_other_paths(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_manual_program('sample', 'identifier,asset_type,in_scope\nhttps://app.example.com/allowed,URL,true\n',
                                  'Maximum 3 requests per second.', {'manual_only': True}, root=root)
            _, digest = read_guidelines('sample', root=root)
            set_active_approval('sample', True, digest, root=root)
            client = ApprovedScopeClient('sample', root=root, open_request=lambda *args, **kwargs: self.fail('Must not request another path'))
            self.assertTrue(client.allows('https://app.example.com/allowed'))
            self.assertFalse(client.allows('https://app.example.com/other'))
            self.assertEqual(client.request('https://app.example.com/other')['error'], 'OutsideExactScope')

    def test_approved_manual_workflow_queues_nine_steps_without_automatic_jobs(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._make_approved_program(root)
            names = queue_manual_workflow('sample', root=root)
            self.assertEqual(len(names), 9)
            self.assertFalse((root / 'jobs/generated').exists())
            self.assertTrue(all(json.loads((root / 'results' / f'{name}.json').read_text())['job_state'] == 'queued' for name in names))
            self.assertIn('Complete passive-web-discovery', stage_block_reason('sample', 'passive-dns-discovery', root=root))
            self.assertIn('URL-only scope', stage_block_reason('sample', 'port-scan', root=root))
            run_manual_stage('sample', 'passive-web-discovery', root=root)
            self.assertIsNone(stage_block_reason('sample', 'passive-dns-discovery', root=root))
            _, digest = read_guidelines('sample', root=root)
            set_active_approval('sample', False, digest, root=root)
            self.assertIn('approved', stage_block_reason('sample', 'passive-web-discovery', root=root))

    def test_all_nine_manual_steps_use_bounded_scoped_transports(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_manual_program('sample', 'identifier,asset_type,in_scope\napp.example.com,URL,true\n',
                                  'Maximum 3 requests per second. Allow port scanning.', {'manual_only': True}, root=root)
            _, digest = read_guidelines('sample', root=root)
            set_active_approval('sample', True, digest, root=root)
            queue_manual_workflow('sample', root=root)
            calls = []
            post_bodies = []
            host_routes = []
            now = [0.0]

            def fake_open(request, timeout=8):
                calls.append((request.full_url, request.get_method(), now[0]))
                host_routes.append((request.full_url, request.get_header('Host')))
                if request.get_method() == 'POST':
                    post_bodies.append(request.data)
                headers = Message()
                headers['Content-Type'] = 'application/json'
                headers['Server'] = 'mock-edge'
                return HTTPError(request.full_url, 200, 'mock response', headers, io.BytesIO(b'{"sample":true}'))

            def fake_sleep(delay):
                now[0] += delay

            client = ApprovedScopeClient('sample', root=root, open_request=fake_open,
                                         sleep_fn=fake_sleep, monotonic_fn=lambda: now[0])
            with patch('worker._resolve_host_ips', return_value={'203.0.113.9'}), \
                 patch('worker._tcp_port_open', return_value=False), \
                 patch('worker._discovery_wordlist', return_value=['/public']), \
                 patch('worker._full_tcp_ports', return_value=[22, 6379]), \
                 patch('worker.subprocess.run') as external:
                for stage in STAGES:
                    result = run_manual_stage('sample', stage['stage'], root=root, client=client)
                    self.assertEqual(result['job_state'], 'completed', result.get('error'))
                external.assert_not_called()
            self.assertTrue(calls)
            self.assertTrue(all(url.startswith('https://app.example.com') or url == 'https://203.0.113.9/' for url, _, _ in calls))
            self.assertTrue(all(header == 'app.example.com' for url, header in host_routes if url == 'https://203.0.113.9/'))
            self.assertTrue(all(method in {'HEAD', 'GET', 'POST'} for _, method, _ in calls))
            self.assertTrue(all(url.endswith('/graphql') for url, method, _ in calls if method == 'POST'))
            self.assertEqual(post_bodies, [b'{"query":"{__schema{types{name}}}"}'])
            self.assertTrue(all(later[2] - earlier[2] >= 1 for earlier, later in zip(calls, calls[1:])))
            self.assertEqual(len(list((root / 'results').glob('*.json'))), 9)

    def test_full_host_scope_allows_alt_web_ports_but_not_new_domains(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_manual_program('sample', 'identifier,asset_type,in_scope\napp.example.com,URL,true\n',
                                  'Maximum 3 requests per second.', {'manual_only': True}, root=root)
            _, digest = read_guidelines('sample', root=root)
            set_active_approval('sample', True, digest, root=root)
            client = ApprovedScopeClient('sample', root=root)
            self.assertTrue(client.allows('https://app.example.com:9443/nested/api/resource'))
            self.assertFalse(client.allows('https://app.example.com:0/'))
            self.assertFalse(client.allows('https://new.app.example.com/'))
            self.assertFalse(client.allows('https://203.0.113.9/', 'app.example.com'))
            client.ip_owners['203.0.113.9'] = {'app.example.com'}
            self.assertTrue(client.allows('https://203.0.113.9/', 'app.example.com'))
            self.assertFalse(client.allows('https://203.0.113.9/', 'outside.example.org'))

    def test_vhost_relative_redirect_preserves_authorized_host_header(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_manual_program('sample', 'identifier,asset_type,in_scope\napp.example.com,URL,true\n',
                                  'Maximum 3 requests per second.', {'manual_only': True}, root=root)
            _, digest = read_guidelines('sample', root=root)
            set_active_approval('sample', True, digest, root=root)
            calls = []

            def fake_open(request, timeout=8):
                calls.append((request.full_url, request.get_header('Host')))
                headers = Message()
                if len(calls) == 1:
                    headers['Location'] = '/public'
                return HTTPError(request.full_url, 302 if len(calls) == 1 else 200, 'mock', headers, io.BytesIO(b'public'))

            client = ApprovedScopeClient('sample', root=root, open_request=fake_open, sleep_fn=lambda delay: None, monotonic_fn=lambda: 0)
            client.ip_owners['203.0.113.9'] = {'app.example.com'}
            response = client.request('https://203.0.113.9/', headers={'Host': 'app.example.com'})
            self.assertEqual(response['status'], 200)
            self.assertEqual(calls, [('https://203.0.113.9/', 'app.example.com'), ('https://203.0.113.9/public', 'app.example.com')])

    def test_explicit_port_ban_still_blocks_full_host_scan(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_manual_program('sample', 'identifier,asset_type,in_scope\napp.example.com,URL,true\n',
                                  'Maximum 3 requests per second. Port scanning is prohibited.', {'manual_only': True}, root=root)
            _, digest = read_guidelines('sample', root=root)
            set_active_approval('sample', True, digest, root=root)
            queue_manual_workflow('sample', root=root)
            self.assertIn('prohibit', stage_block_reason('sample', 'port-scan', root=root))

    def test_revocation_or_guideline_change_during_wait_stops_the_next_request(self):
        for change_rules in (False, True):
            with self.subTest(change_rules=change_rules), TemporaryDirectory() as directory:
                root = Path(directory)
                content = 'identifier,asset_type,in_scope\none.example.com,URL,true\ntwo.example.com,URL,true\n'
                create_manual_program('sample', content, 'Maximum 3 requests per second.',
                                      {'eligible_asset_types': {'URL': 2}, 'manual_only': True}, root=root)
                _, digest = read_guidelines('sample', root=root)
                set_active_approval('sample', True, digest, root=root)
                calls = []

                def fake_open(request, timeout=8):
                    calls.append(request.full_url)
                    raise HTTPError(request.full_url, 404, 'not found', Message(), None)

                def change_approval(delay):
                    if change_rules:
                        (root / 'programs/sample/rules.md').write_text('New rules. Maximum 3 requests per second.')
                        _, new_digest = read_guidelines('sample', root=root)
                        set_active_approval('sample', True, new_digest, root=root)
                    else:
                        set_active_approval('sample', False, digest, root=root)

                result = run_url_check('sample', root=root, open_request=fake_open,
                                       sleep_fn=change_approval, monotonic_fn=lambda: 0.0)
                self.assertEqual(calls, ['https://one.example.com/'])
                self.assertEqual(result['state'], 'stopped')
                self.assertEqual(result['remaining'], 1)
                self.assertFalse(result['complete'])


if __name__ == '__main__':
    unittest.main()
