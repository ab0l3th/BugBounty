import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'automation') not in sys.path:
    sys.path.insert(0, str(ROOT / 'automation'))

from unittest.mock import patch

from dashboard_app import app, job_title_label, list_jobs
from passive_discovery import public_sources_for
from passive_dns_enrichment import passive_dns_enrichment


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

    def test_passive_dns_enrichment_records_provider_statuses(self):
        with patch('passive_dns_enrichment.load_allowed_patterns', return_value=['*.aa.com'], create=True):
            with patch('passive_dns_enrichment.certspotter_candidates', return_value={'www.aa.com'}), \
                 patch('passive_dns_enrichment.hackertarget_candidates', return_value={'api.aa.com'}), \
                 patch('passive_dns_enrichment.crt_sh_candidates', return_value={'crt.aa.com'}), \
                 patch('passive_dns_enrichment.dns_google_candidates', return_value={'dns.aa.com'}), \
                 patch('passive_dns_enrichment.is_in_scope', side_effect=lambda host, patterns: True):
                result = passive_dns_enrichment('american-airlines')
                self.assertIn('provider_status', result)
                provider_names = {entry['source'] for entry in result['provider_status']}
                self.assertTrue({'certspotter', 'hackertarget', 'crt.sh', 'dns.google'} <= provider_names)

    def test_dashboard_can_queue_rerun_for_job(self):
        with patch('dashboard_app.subprocess.Popen', return_value=type('Proc', (), {'pid': 1234})()) as mock_popen:
            with app.test_client() as client:
                response = client.post('/jobs/aa-passive-discovery/rerun')
                self.assertEqual(response.status_code, 202)
                self.assertIn('queued', response.get_json()['status'])
                mock_popen.assert_called_once()


if __name__ == '__main__':
    unittest.main()
