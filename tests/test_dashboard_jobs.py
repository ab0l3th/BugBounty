import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'automation') not in sys.path:
    sys.path.insert(0, str(ROOT / 'automation'))

from dashboard_app import list_jobs


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


if __name__ == '__main__':
    unittest.main()
