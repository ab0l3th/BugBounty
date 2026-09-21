import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'automation') not in sys.path:
    sys.path.insert(0, str(ROOT / 'automation'))

from dashboard_app import job_title_label, list_jobs
from passive_discovery import public_sources_for


class DashboardJobMetadataTest(unittest.TestCase):
    def test_list_jobs_uses_yaml_metadata_for_queued_jobs(self):
        jobs = list_jobs()
        names = {job['name'] for job in jobs}
        self.assertIn('aa-passive-discovery', names)
        queued = next(job for job in jobs if job['name'] == 'aa-passive-discovery')
        self.assertEqual(queued['program'], 'american-airlines')
        self.assertEqual(queued['type'], 'passive')
        self.assertEqual(queued['job_state'], 'queued')
        self.assertEqual(queued['status'], 'queued')

    def test_passive_jobs_share_one_dns_label_and_provider_list(self):
        self.assertEqual(job_title_label('aa-passive-discovery'), 'Passive DNS Discovery')
        self.assertEqual(job_title_label('american-airlines-passive-dns'), 'Passive DNS Discovery')

        sources = public_sources_for('example.com')
        labels = [url.split('://', 1)[1].split('/', 1)[0] for url in sources]
        self.assertIn('crt.sh', labels)
        self.assertIn('api.certspotter.com', labels)
        self.assertIn('api.hackertarget.com', labels)
        self.assertIn('dns.google', labels)
        self.assertNotIn('www.google.com', labels)


if __name__ == '__main__':
    unittest.main()
