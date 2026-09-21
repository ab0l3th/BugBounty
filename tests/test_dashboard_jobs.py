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
        result_path = ROOT / 'results' / 'aa-passive-discovery.json'
        lock_path = ROOT / 'results' / '.running' / 'aa-passive-discovery.lock'
        if result_path.exists():
            result_path.unlink()
        if lock_path.exists():
            lock_path.unlink()

        jobs = list_jobs()
        names = {job['name'] for job in jobs}
        self.assertIn('aa-passive-discovery', names)
        queued = next(job for job in jobs if job['name'] == 'aa-passive-discovery')
        self.assertEqual(queued['program'], 'american-airlines')
        self.assertEqual(queued['type'], 'passive')
        self.assertEqual(queued['job_state'], 'queued')
        self.assertEqual(queued['status'], 'queued')

    def test_running_lock_overrides_queued_payload_state(self):
        result_path = ROOT / 'results' / 'aa-passive-discovery.json'
        lock_path = ROOT / 'results' / '.running' / 'aa-passive-discovery.lock'
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(__import__('json').dumps({
            'job': 'aa-passive-discovery',
            'program': 'american-airlines',
            'status': 'queued',
            'job_state': 'queued',
            'discovered': [],
            'assets': [],
            'targets': []
        }, indent=2), encoding='utf-8')
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text('123456', encoding='utf-8')

        jobs = list_jobs()
        queued = next(job for job in jobs if job['name'] == 'aa-passive-discovery')
        self.assertEqual(queued['job_state'], 'running')

        result_path.unlink()
        if lock_path.exists():
            lock_path.unlink()

    def test_running_lock_is_visible_even_without_result_payload(self):
        lock_path = ROOT / 'results' / '.running' / 'confirm-live-web-assets.lock'
        result_path = ROOT / 'results' / 'confirm-live-web-assets.json'
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text('123456', encoding='utf-8')
        result_path.unlink(missing_ok=True)

        try:
            jobs = list_jobs()
            live_assets_job = next(job for job in jobs if job['name'] == 'confirm-live-web-assets')
            self.assertEqual(live_assets_job['job_state'], 'running')
            self.assertEqual(live_assets_job['status'], 'running')
        finally:
            if lock_path.exists():
                lock_path.unlink()

    def test_passive_jobs_are_distinct_in_dashboard_titles(self):
        self.assertEqual(job_title_label('aa-passive-discovery'), 'Passive Web Discovery')
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

    def test_dashboard_detects_third_workflow_job_and_order(self):
        jobs = list_jobs()
        live_assets_job = next(job for job in jobs if job['name'] == 'confirm-live-web-assets')
        self.assertEqual(live_assets_job['workflow_step'], 3)
        self.assertEqual(live_assets_job['depends_on'], ['aa-passive-discovery', 'american-airlines-passive-dns'])
        self.assertEqual(job_title_label('confirm-live-web-assets'), 'Confirm Live Web Assets')

    def test_dashboard_detects_service_enumeration_step_and_title(self):
        jobs = list_jobs()
        service_job = next((job for job in jobs if job['name'] == 'service-enumeration-live-hosts'), None)
        self.assertIsNotNone(service_job)
        self.assertEqual(service_job['workflow_step'], 4)
        self.assertEqual(service_job['depends_on'], ['confirm-live-web-assets'])
        self.assertEqual(job_title_label('service-enumeration-live-hosts'), 'Service Enumeration')

    def test_service_enumeration_uses_step3_live_asset_output(self):
        result_path = ROOT / 'results' / 'confirm-live-web-assets.json'
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(__import__('json').dumps({
            'job': 'confirm-live-web-assets',
            'program': 'american-airlines',
            'status': 'ok',
            'discovered': ['host-001.example.com', 'host-002.example.com', 'host-001.example.com'],
            'targets': ['host-001.example.com', 'host-002.example.com', 'cand-a.example.com', 'cand-b.example.com', 'cand-c.example.com'],
            'queued': ['host-001.example.com', 'host-002.example.com', 'cand-a.example.com', 'cand-b.example.com', 'cand-c.example.com'],
            'assets': [
                {'domain': 'host-001.example.com', 'status': 'live', 'source': 'http-probe', 'sources': ['http-probe']},
                {'domain': 'host-002.example.com', 'status': 'live', 'source': 'http-probe', 'sources': ['http-probe']},
            ],
            'source_count': 2,
        }, indent=2), encoding='utf-8')
        try:
            jobs = list_jobs()
            service_job = next(job for job in jobs if job['name'] == 'service-enumeration-live-hosts')
            self.assertEqual(service_job['targets'], ['host-001.example.com', 'host-002.example.com'])
            self.assertEqual(service_job['queued'], ['host-001.example.com', 'host-002.example.com'])
        finally:
            result_path.unlink(missing_ok=True)

    def test_confirm_live_web_assets_uses_merged_step1_and_step2_targets(self):
        from worker import run_passive_job

        root = ROOT / 'results'
        root.mkdir(exist_ok=True)

        (root / 'aa-passive-discovery.json').write_text(__import__('json').dumps({
            'job': 'aa-passive-discovery',
            'program': 'american-airlines',
            'status': 'ok',
            'discovered': ['alpha.example.com', 'beta.example.com'],
            'targets': ['alpha.example.com', 'beta.example.com'],
            'assets': []
        }, indent=2), encoding='utf-8')
        (root / 'american-airlines-passive-dns.json').write_text(__import__('json').dumps({
            'job': 'american-airlines-passive-dns',
            'program': 'american-airlines',
            'status': 'ok',
            'discovered': ['beta.example.com', 'gamma.example.com'],
            'targets': ['beta.example.com', 'gamma.example.com'],
            'assets': []
        }, indent=2), encoding='utf-8')

        with patch('worker._probe_live_web_assets', return_value=[
            {'domain': 'alpha.example.com', 'status': 'live', 'source': 'http-probe', 'sources': ['http-probe'], 'source_count': 1, 'evidence': [{'source': 'http-probe', 'url': 'https://alpha.example.com'}]},
            {'domain': 'gamma.example.com', 'status': 'live', 'source': 'http-probe', 'sources': ['http-probe'], 'source_count': 1, 'evidence': [{'source': 'http-probe', 'url': 'https://gamma.example.com'}]},
        ]):
            result = run_passive_job({'name': 'confirm-live-web-assets', 'program': 'american-airlines', 'type': 'passive', 'targets': []}, ['*.example.com'])
            self.assertEqual(result['targets'], ['alpha.example.com', 'beta.example.com', 'gamma.example.com'])
            self.assertEqual(result['discovered'], ['alpha.example.com', 'gamma.example.com'])

        (root / 'aa-passive-discovery.json').unlink(missing_ok=True)
        (root / 'american-airlines-passive-dns.json').unlink(missing_ok=True)

    def test_dashboard_reports_dependency_wait_as_waiting_state(self):
        result_path = ROOT / 'results' / 'confirm-live-web-assets.json'
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(__import__('json').dumps({
            'job': 'confirm-live-web-assets',
            'program': 'american-airlines',
            'status': 'waiting_on_dependencies',
            'job_state': 'waiting_on_dependencies',
            'discovered': [],
            'assets': [],
            'targets': [],
            'queued': [],
            'skipped': []
        }, indent=2), encoding='utf-8')

        try:
            jobs = list_jobs()
            live_assets_job = next(job for job in jobs if job['name'] == 'confirm-live-web-assets')
            self.assertEqual(live_assets_job['job_state'], 'waiting_on_dependencies')
            self.assertEqual(live_assets_job['status'], 'waiting_on_dependencies')
        finally:
            result_path.unlink(missing_ok=True)

    def test_probe_live_web_assets_records_thread_progress(self):
        from worker import _probe_live_web_assets

        class FakeResponse:
            def __init__(self, status):
                self.status = status

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                return False

            def getcode(self):
                return self.status

        def fake_urlopen(req, timeout=8):
            url = req.full_url
            if 'alpha.example.com' in url:
                return FakeResponse(200)
            raise OSError('no response')

        with patch('worker.urllib_request.urlopen', side_effect=fake_urlopen):
            result = _probe_live_web_assets(['alpha.example.com', 'beta.example.com'])
            self.assertIn('probe_log', result)
            self.assertIn('thread_status', result)
            self.assertTrue(any(entry.get('host') == 'alpha.example.com' for entry in result['probe_log']))
            self.assertTrue(any(status.get('host') == 'beta.example.com' for status in result['thread_status']))

    def test_probe_live_web_assets_can_record_external_tool_results(self):
        from worker import _probe_live_web_assets

        class FakeResponse:
            def __init__(self, status):
                self.status = status

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                return False

            def getcode(self):
                return self.status

        def fake_urlopen(req, timeout=8):
            raise OSError('no response')

        with patch('worker.urllib_request.urlopen', side_effect=fake_urlopen), \
             patch('worker.shutil.which', side_effect=lambda tool: '/usr/bin/' + tool if tool in {'curl', 'nmap', 'whatweb'} else None), \
             patch('worker.subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = 'HTTP/1.1 200 OK'
            mock_run.return_value.stderr = ''
            result = _probe_live_web_assets(['alpha.example.com'], use_external_tools=True)
            self.assertTrue(any(entry.get('external_tool') == 'curl' for entry in result['probe_log']))
            self.assertTrue(any(entry.get('tool') == 'curl' for entry in result['thread_status']))

    def test_service_enumeration_evidence_has_source_and_correct_port(self):
        from worker import _enumerate_live_services

        class FakeResponse:
            def __init__(self, status, server):
                self.status = status
                self.headers = {'Server': server}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                return False

            def getcode(self):
                return self.status

        def fake_urlopen(req, timeout=8):
            url = req.full_url
            if url == 'https://alpha.example.com':
                return FakeResponse(200, 'nginx')
            if url == 'https://alpha.example.com:8443':
                return FakeResponse(200, 'envoy')
            raise OSError('no response')

        with patch('worker.urllib_request.urlopen', side_effect=fake_urlopen):
            result = _enumerate_live_services(['alpha.example.com'])
            asset = next(row for row in result['assets'] if row['domain'] == 'alpha.example.com')
            self.assertIn(443, asset['ports'])
            self.assertIn(8443, asset['ports'])
            self.assertTrue(asset['evidence'])
            self.assertTrue(all(item.get('source') for item in asset['evidence']))
            self.assertTrue(asset.get('source'))

    def test_dashboard_can_queue_rerun_for_job(self):
        with patch('dashboard_app.subprocess.Popen', return_value=type('Proc', (), {'pid': 1234})()) as mock_popen, \
             patch.dict('os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token'}):
            with app.test_client() as client:
                response = client.post('/jobs/aa-passive-discovery/rerun', headers={'X-BugBounty-Token': 'test-token'})
                self.assertEqual(response.status_code, 202)
                self.assertIn('queued', response.get_json()['status'])
                mock_popen.assert_called_once()

                payload = __import__('json').loads((Path(__file__).resolve().parents[1] / 'results' / 'aa-passive-discovery.json').read_text())
                self.assertEqual(payload['status'], 'queued')
                self.assertEqual(payload['job_state'], 'queued')

    def test_dashboard_rerun_requires_auth_token(self):
        with patch('dashboard_app.subprocess.Popen', return_value=type('Proc', (), {'pid': 1234})()) as mock_popen, \
             patch.dict('os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token'}):
            with app.test_client() as client:
                response = client.post('/jobs/aa-passive-discovery/rerun')
                self.assertEqual(response.status_code, 401)
                mock_popen.assert_not_called()

    def test_rerun_launches_only_the_requested_job(self):
        with patch('dashboard_app.subprocess.Popen', return_value=type('Proc', (), {'pid': 4321})()) as mock_popen, \
             patch.dict('os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token'}):
            with app.test_client() as client:
                response = client.post('/jobs/service-enumeration-live-hosts/rerun', headers={'X-BugBounty-Token': 'test-token'})
                self.assertEqual(response.status_code, 202)
                launched_cmd = mock_popen.call_args[0][0]
                self.assertIn('--job', launched_cmd)
                self.assertEqual(launched_cmd[launched_cmd.index('--job') + 1], 'service-enumeration-live-hosts')
                self.assertIn('--allow-active', launched_cmd)
        (Path(__file__).resolve().parents[1] / 'results' / 'service-enumeration-live-hosts.json').unlink(missing_ok=True)
        (Path(__file__).resolve().parents[1] / 'results' / '.running' / 'service-enumeration-live-hosts.lock').unlink(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
