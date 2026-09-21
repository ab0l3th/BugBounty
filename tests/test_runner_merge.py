import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'automation') not in sys.path:
    sys.path.insert(0, str(ROOT / 'automation'))

import runner


class RunnerMergeTest(unittest.TestCase):
    def test_merge_result_keeps_previous_discovery(self):
        previous = {
            'job': 'aa-passive-discovery',
            'program': 'american-airlines',
            'type': 'passive',
            'discovered': ['a.aa.com', 'b.aa.com'],
            'assets': [
                {'domain': 'a.aa.com', 'source': 'legacy', 'sources': ['legacy'], 'evidence': [{'source': 'legacy', 'url': 'https://a'}]},
                {'domain': 'b.aa.com', 'source': 'legacy', 'sources': ['legacy'], 'evidence': [{'source': 'legacy', 'url': 'https://b'}]},
            ],
            'source_count': 1,
        }
        current = {
            'job': 'aa-passive-discovery',
            'program': 'american-airlines',
            'type': 'passive',
            'discovered': ['b.aa.com', 'c.aa.com'],
            'assets': [
                {'domain': 'b.aa.com', 'source': 'dns.google', 'sources': ['dns.google'], 'evidence': [{'source': 'dns.google', 'url': 'https://dns'}]},
                {'domain': 'c.aa.com', 'source': 'crt.sh', 'sources': ['crt.sh'], 'evidence': [{'source': 'crt.sh', 'url': 'https://crt'}]},
            ],
            'source_count': 2,
        }

        merged = runner.merge_result_payloads(previous, current)
        self.assertEqual(set(merged['discovered']), {'a.aa.com', 'b.aa.com', 'c.aa.com'})
        self.assertEqual(len(merged['assets']), 3)
        self.assertGreaterEqual(merged['source_count'], 2)

    def test_diff_ignores_volatile_probe_and_timestamp_fields(self):
        base = {
            'job': 'confirm-live-web-assets',
            'status': 'ok',
            'discovered': ['a.aa.com'],
            'assets': [{'domain': 'a.aa.com', 'sources': ['http-probe'], 'status': 'live'}],
        }
        noisy = dict(base)
        noisy['probe_log'] = [{'host': 'a.aa.com', 'timestamp': 123456.789}]
        noisy['thread_status'] = [{'host': 'a.aa.com', 'timestamp': 987654.321}]
        self.assertFalse(runner.diff_changed(noisy, base))

    def test_diff_detects_new_discovery(self):
        previous = {'status': 'ok', 'discovered': ['a.aa.com'], 'assets': []}
        current = {'status': 'ok', 'discovered': ['a.aa.com', 'b.aa.com'], 'assets': []}
        self.assertTrue(runner.diff_changed(current, previous))


if __name__ == '__main__':
    unittest.main()
