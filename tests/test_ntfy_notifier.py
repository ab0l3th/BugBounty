import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'automation'))

from ntfy_notifier import collect_findings, deliver_pending, finding_signals, load_configuration


class NtfyNotifierTest(unittest.TestCase):
    def test_bursts_are_grouped_and_unchanged_results_skip_parsing(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'results').mkdir()
            signatures = {}
            collect_findings(root, signatures=signatures)
            path = root / 'results/sample-job.json'
            payload = {'job': 'sample-job', 'program': 'sample', 'assets': [{'domain': 'app.example.com', 'findings': [
                {'type': 'open_port', 'port': port, 'severity': 'high'} for port in range(30)]}]}
            path.write_text(json.dumps(payload))
            self.assertEqual(collect_findings(root, signatures=signatures)['new_alerts'], 30)
            with patch('ntfy_notifier.json.loads', side_effect=AssertionError('unchanged files must not be parsed')):
                self.assertEqual(collect_findings(root, signatures=signatures)['new_alerts'], 0)
            calls = []

            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def getcode(self): return 200
                def read(self, *args): return b'{}'

            def publish(req, **kwargs):
                calls.append(json.loads(req.data))
                return Response()

            config = {'BUGBOUNTY_NTFY_URL': 'https://ntfy.sh', 'BUGBOUNTY_NTFY_TOPIC': 'unit-test',
                      'BUGBOUNTY_NTFY_TOKEN': 'unit-test-secret', 'BUGBOUNTY_DASHBOARD_URL': 'http://192.168.1.16:8001'}
            self.assertEqual(deliver_pending(root, config, open_request=publish, now=100)['sent'], 20)
            self.assertEqual(deliver_pending(root, config, open_request=publish, now=110)['sent'], 0)
            self.assertEqual(deliver_pending(root, config, open_request=publish, now=160)['sent'], 10)
            self.assertEqual(len(calls), 2)
            self.assertNotIn('app.example.com', calls[0]['message'])

    def test_configuration_is_private_and_not_executed(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'config'
            path.write_text('BUGBOUNTY_NTFY_URL=https://ntfy.sh\nBUGBOUNTY_NTFY_TOPIC=unit-test\nBUGBOUNTY_NTFY_TOKEN=unit-test-secret\nBUGBOUNTY_DASHBOARD_URL=http://192.168.1.16:8001\n')
            path.chmod(0o600)
            self.assertEqual(load_configuration(path)['BUGBOUNTY_NTFY_TOPIC'], 'unit-test')
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                load_configuration(path)

    def test_baseline_deduplication_metadata_privacy_and_retry(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / 'results'
            results.mkdir()
            path = results / 'sample-job.json'
            payload = {'job': 'sample-job', 'program': 'sample', 'assets': [{'domain': 'app.example.com', 'findings': [
                {'type': 'old_signal', 'severity': 'high'}, {'type': 'low_signal', 'severity': 'low'}]}]}
            path.write_text(json.dumps(payload))
            self.assertTrue(collect_findings(root)['baseline'])
            payload['assets'][0]['findings'].append({'type': 'new_signal', 'severity': 'critical', 'path': '/secret?token=private-value', 'detail': 'private-response-body'})
            path.write_text(json.dumps(payload))
            self.assertEqual(collect_findings(root)['new_alerts'], 1)
            self.assertEqual(collect_findings(root)['new_alerts'], 0)
            sent = []
            config = {'BUGBOUNTY_NTFY_URL': 'https://ntfy.sh', 'BUGBOUNTY_NTFY_TOPIC': 'unit-test',
                      'BUGBOUNTY_NTFY_TOKEN': 'unit-test-secret', 'BUGBOUNTY_DASHBOARD_URL': 'http://192.168.1.16:8001'}

            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def getcode(self): return 200
                def read(self, *args): return b'{}'

            def fail(req, **kwargs):
                raise TimeoutError('mock timeout')

            self.assertEqual(deliver_pending(root, config, open_request=fail, now=0)['failed_batches'], 1)
            self.assertEqual(deliver_pending(root, config, open_request=fail, now=10)['failed_batches'], 0)

            def publish(req, **kwargs):
                sent.append(json.loads(req.data))
                self.assertEqual(req.get_header('Authorization'), 'Bearer unit-test-secret')
                return Response()

            self.assertEqual(deliver_pending(root, config, open_request=publish, now=31)['sent'], 1)
            self.assertEqual(deliver_pending(root, config, open_request=publish, now=60)['sent'], 0)
            self.assertEqual(sent[0]['priority'], 5)
            self.assertIn('unverified', sent[0]['message'].lower())
            self.assertNotIn('private-value', json.dumps(sent))
            self.assertNotIn('private-response-body', json.dumps(sent))
            self.assertNotIn('unit-test-secret', json.dumps(sent))
            self.assertNotIn('click', sent[0])
            self.assertNotIn('app.example.com', sent[0]['message'])
            self.assertNotIn('sample-job', sent[0]['message'])

    def test_private_topic_verification_enables_details_only_with_denied_public_reads(self):
        from ntfy_notifier import topic_is_private
        config = {'BUGBOUNTY_NTFY_URL': 'https://ntfy.sh', 'BUGBOUNTY_NTFY_TOPIC': 'unit-test', 'BUGBOUNTY_NTFY_TOKEN': 'unit-test-secret'}

        class Response:
            def __init__(self, reservations): self.reservations = reservations
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, *args): return json.dumps({'reservations': self.reservations}).encode()

        self.assertFalse(topic_is_private(config, open_request=lambda *args, **kwargs: Response([])))
        self.assertTrue(topic_is_private(config, open_request=lambda *args, **kwargs: Response([{'topic': 'unit-test', 'everyone': 'deny-all'}])))

    def test_private_topic_details_still_exclude_sensitive_evidence(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'results').mkdir()
            collect_findings(root)
            payload = {'job': 'sample-job', 'program': 'sample', 'assets': [{'domain': 'app.example.com', 'findings': [
                {'type': 'debug_endpoint', 'severity': 'high', 'path': '/debug?token=private-query', 'detail': 'private-evidence'}]}]}
            (root / 'results/sample-job.json').write_text(json.dumps(payload))
            collect_findings(root)
            sent = []

            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def getcode(self): return 200
                def read(self, *args): return b'{}'

            def publish(req, **kwargs):
                sent.append(json.loads(req.data))
                return Response()

            config = {'BUGBOUNTY_NTFY_URL': 'https://ntfy.sh', 'BUGBOUNTY_NTFY_TOPIC': 'unit-test',
                      'BUGBOUNTY_NTFY_TOKEN': 'unit-test-secret', 'BUGBOUNTY_DASHBOARD_URL': 'http://192.168.1.16:8001', '_private_topic': True}
            self.assertEqual(deliver_pending(root, config, open_request=publish, now=0)['sent'], 1)
            self.assertIn('app.example.com', sent[0]['message'])
            self.assertIn('program=sample', sent[0]['click'])
            self.assertNotIn('private-query', json.dumps(sent))
            self.assertNotIn('private-evidence', json.dumps(sent))
            self.assertNotIn('unit-test-secret', json.dumps(sent))