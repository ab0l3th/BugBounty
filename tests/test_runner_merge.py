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


if __name__ == '__main__':
    unittest.main()
