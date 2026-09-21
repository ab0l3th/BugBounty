import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
AUTOMATION = ROOT / 'automation'
if str(AUTOMATION) not in sys.path:
    sys.path.insert(0, str(AUTOMATION))

import worker


class WorkerMergeTest(unittest.TestCase):
    def test_run_passive_job_merges_legacy_and_enrichment_results(self):
        legacy = {
            'job': 'aa-passive-discovery',
            'type': 'passive',
            'targets': ['*.aa.com'],
            'discovered': ['a.aa.com', 'c.aa.com'],
            'assets': [
                {
                    'domain': 'a.aa.com',
                    'source': 'legacy',
                    'sources': ['legacy'],
                    'source_count': 1,
                    'evidence': [{'source': 'legacy', 'url': 'https://example.com/a'}],
                },
                {
                    'domain': 'c.aa.com',
                    'source': 'legacy',
                    'sources': ['legacy'],
                    'source_count': 1,
                    'evidence': [{'source': 'legacy', 'url': 'https://example.com/c'}],
                },
            ],
            'status': 'ok',
            'source_count': 1,
        }
        enrichment = {
            'job': 'american-airlines-passive-dns',
            'type': 'passive',
            'program': 'american-airlines',
            'targets': ['*.aa.com'],
            'discovered': ['a.aa.com', 'b.aa.com'],
            'assets': [
                {
                    'domain': 'a.aa.com',
                    'source': 'crt.sh',
                    'sources': ['crt.sh'],
                    'source_count': 1,
                    'evidence': [{'source': 'crt.sh', 'url': 'https://crt.sh/?q=%25.a.aa.com&output=json'}],
                },
                {
                    'domain': 'b.aa.com',
                    'source': 'dns.google',
                    'sources': ['dns.google'],
                    'source_count': 1,
                    'evidence': [{'source': 'dns.google', 'url': 'https://dns.google/resolve?name=b.aa.com&type=A'}],
                },
            ],
            'status': 'ok',
            'source_count': 2,
        }

        with patch('passive_discovery.build_job_output', return_value=legacy), \
             patch('passive_dns_enrichment.passive_dns_enrichment', return_value=enrichment):
            result = worker.run_passive_job(
                {'name': 'american-airlines-passive-dns', 'program': 'american-airlines', 'targets': ['*.aa.com'], 'type': 'passive'},
                ['*.aa.com'],
            )

        discovered = set(result['discovered'])
        self.assertEqual(discovered, {'a.aa.com', 'b.aa.com', 'c.aa.com'})
        self.assertEqual(result['status'], 'ok')
        self.assertGreaterEqual(result['source_count'], 2)

    def test_merge_result_payloads_keeps_previous_history(self):
        previous = {
            'job': 'aa-passive-discovery',
            'program': 'american-airlines',
            'targets': ['*.aa.com'],
            'discovered': ['a.aa.com', 'legacy.aa.com'],
            'assets': [{'domain': 'a.aa.com', 'sources': ['legacy']}, {'domain': 'legacy.aa.com', 'sources': ['legacy']}],
            'status': 'ok',
        }
        current = {
            'job': 'aa-passive-discovery',
            'program': 'american-airlines',
            'targets': ['*.aa.com'],
            'discovered': ['a.aa.com', 'new.aa.com'],
            'assets': [{'domain': 'a.aa.com', 'sources': ['crt.sh']}, {'domain': 'new.aa.com', 'sources': ['crt.sh']}],
            'status': 'ok',
        }

        merged = worker.merge_result_payloads(previous, current)

        self.assertEqual(set(merged['discovered']), {'a.aa.com', 'legacy.aa.com', 'new.aa.com'})
        self.assertEqual(len(merged['assets']), 3)

    def test_active_job_result_replaces_and_does_not_merge_stale_targets(self):
        stale = {'job': 'service-enumeration-live-hosts', 'targets': [f'cand{i}.aa.com' for i in range(3354)], 'discovered': [], 'assets': [], 'status': 'queued'}
        fresh = {'job': 'service-enumeration-live-hosts', 'targets': ['live1.aa.com', 'live2.aa.com'], 'discovered': ['live1.aa.com'], 'assets': [{'domain': 'live1.aa.com', 'kind': 'app-server'}], 'status': 'ok'}
        written = worker._result_for_write('service-enumeration-live-hosts', stale, fresh)
        self.assertEqual(written['targets'], ['live1.aa.com', 'live2.aa.com'])

    def test_passive_job_result_still_accumulates(self):
        previous = {'job': 'aa-passive-discovery', 'targets': ['*.aa.com'], 'discovered': ['old.aa.com'], 'assets': [{'domain': 'old.aa.com', 'sources': ['legacy']}], 'status': 'ok'}
        current = {'job': 'aa-passive-discovery', 'targets': ['*.aa.com'], 'discovered': ['new.aa.com'], 'assets': [{'domain': 'new.aa.com', 'sources': ['crt.sh']}], 'status': 'ok'}
        written = worker._result_for_write('aa-passive-discovery', previous, current)
        self.assertEqual(set(written['discovered']), {'old.aa.com', 'new.aa.com'})

    def test_should_run_job_skips_existing_completed_results(self):
        path = Path('jobs/aa-passive-discovery.yaml')
        result_path = Path('results/aa-passive-discovery.json')
        previous = {'status': 'ok', 'job_state': 'completed'}
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(__import__('json').dumps(previous), encoding='utf-8')
        try:
            self.assertFalse(worker.should_run_job(path, force=False))
            self.assertTrue(worker.should_run_job(path, force=True))
        finally:
            result_path.unlink(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
