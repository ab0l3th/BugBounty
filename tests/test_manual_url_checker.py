import sys
import unittest
from email.message import Message
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'automation') not in sys.path:
    sys.path.insert(0, str(ROOT / 'automation'))

from manual_url_checker import run_url_check
from program_builder import create_manual_program, read_guidelines, set_active_approval


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
