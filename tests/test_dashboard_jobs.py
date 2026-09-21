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
        import os
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
        lock_path.write_text(str(os.getpid()), encoding='utf-8')

        jobs = list_jobs()
        queued = next(job for job in jobs if job['name'] == 'aa-passive-discovery')
        self.assertEqual(queued['job_state'], 'running')

        result_path.unlink()
        if lock_path.exists():
            lock_path.unlink()

    def test_running_lock_is_visible_even_without_result_payload(self):
        import os
        lock_path = ROOT / 'results' / '.running' / 'confirm-live-web-assets.lock'
        result_path = ROOT / 'results' / 'confirm-live-web-assets.json'
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(str(os.getpid()), encoding='utf-8')
        result_path.unlink(missing_ok=True)

        try:
            jobs = list_jobs()
            live_assets_job = next(job for job in jobs if job['name'] == 'confirm-live-web-assets')
            self.assertEqual(live_assets_job['job_state'], 'running')
            self.assertEqual(live_assets_job['status'], 'running')
        finally:
            if lock_path.exists():
                lock_path.unlink()

    def test_stale_lock_with_dead_pid_is_not_running(self):
        import os
        lock_path = ROOT / 'results' / '.running' / 'aa-passive-discovery.lock'
        result_path = ROOT / 'results' / 'aa-passive-discovery.json'
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        # A PID that is almost certainly not alive.
        lock_path.write_text('2147480000', encoding='utf-8')
        result_path.write_text(__import__('json').dumps({
            'job': 'aa-passive-discovery', 'program': 'american-airlines',
            'status': 'ok', 'discovered': ['x.aa.com'], 'assets': [], 'targets': []
        }, indent=2), encoding='utf-8')
        try:
            jobs = list_jobs()
            job = next(j for j in jobs if j['name'] == 'aa-passive-discovery')
            self.assertNotEqual(job['job_state'], 'running')
            # stale lock should have been cleaned up
            self.assertFalse(lock_path.exists())
        finally:
            lock_path.unlink(missing_ok=True)
            result_path.unlink(missing_ok=True)

    def test_live_lock_with_current_pid_is_running(self):
        import os
        lock_path = ROOT / 'results' / '.running' / 'aa-passive-discovery.lock'
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(str(os.getpid()), encoding='utf-8')
        try:
            jobs = list_jobs()
            job = next(j for j in jobs if j['name'] == 'aa-passive-discovery')
            self.assertEqual(job['job_state'], 'running')
        finally:
            lock_path.unlink(missing_ok=True)

    def test_should_run_job_runs_queued_but_skips_completed(self):
        from worker import should_run_job, RESULTS_DIR
        from pathlib import Path
        import json as _json
        stem = 'unit-test-should-run'
        result_path = RESULTS_DIR / f'{stem}.json'
        fake = Path(f'jobs/{stem}.yaml')
        try:
            result_path.write_text(_json.dumps({'status': 'queued', 'job_state': 'queued'}), encoding='utf-8')
            self.assertTrue(should_run_job(fake))
            result_path.write_text(_json.dumps({'status': 'waiting_on_dependencies', 'job_state': 'waiting_on_dependencies'}), encoding='utf-8')
            self.assertTrue(should_run_job(fake))
            result_path.write_text(_json.dumps({'status': 'ok'}), encoding='utf-8')
            self.assertFalse(should_run_job(fake))
        finally:
            result_path.unlink(missing_ok=True)

    def test_resource_caps_bound_hosts_and_workers(self):
        import worker as w
        with patch.object(w, 'MAX_HOSTS_PER_RUN', 3), patch.object(w, 'MAX_WORKERS', 2):
            capped, truncated = w._cap_hosts([f'h{i}.aa.com' for i in range(10)])
            self.assertEqual(len(capped), 3)
            self.assertTrue(truncated)
            self.assertEqual(w._bounded_workers(50), 2)
            self.assertEqual(w._bounded_workers(1), 1)
        # Under the cap, nothing is truncated.
        small, truncated2 = w._cap_hosts(['a.aa.com', 'b.aa.com'])
        self.assertFalse(truncated2)
        self.assertEqual(small, ['a.aa.com', 'b.aa.com'])

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

    def test_dashboard_about_page_exists_and_describes_workflow(self):
        client = app.test_client()
        response = client.get('/about')
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('BugBounty Workflow Overview', body)
        self.assertIn('Passive Web Discovery', body)
        self.assertIn('Confirm Live Web Assets', body)
        self.assertIn('Application Security Testing', body)
        self.assertIn('API Endpoint Testing', body)

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

    def test_dashboard_detects_vhost_discovery_step_and_title(self):
        jobs = list_jobs()
        vhost_job = next((job for job in jobs if job['name'] == 'vhost-discovery-shared-infra'), None)
        self.assertIsNotNone(vhost_job)
        self.assertEqual(vhost_job['workflow_step'], 5)
        self.assertEqual(vhost_job['depends_on'], ['service-enumeration-live-hosts'])
        self.assertEqual(job_title_label('vhost-discovery-shared-infra'), 'Vhost Discovery')

    def test_vhost_discovery_uses_step4_live_hosts_as_targets(self):
        result_path = ROOT / 'results' / 'service-enumeration-live-hosts.json'
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(__import__('json').dumps({
            'job': 'service-enumeration-live-hosts',
            'program': 'american-airlines',
            'status': 'ok',
            'discovered': ['host-001.example.com', 'host-002.example.com'],
            'targets': ['host-001.example.com', 'host-002.example.com'],
            'assets': [
                {'domain': 'host-001.example.com', 'status': 'enumerated', 'kind': 'reverse-proxy', 'ports': [443]},
                {'domain': 'host-002.example.com', 'status': 'enumerated', 'kind': 'static-site', 'ports': [443]},
            ],
            'source_count': 2,
        }, indent=2), encoding='utf-8')
        try:
            jobs = list_jobs()
            vhost_job = next(job for job in jobs if job['name'] == 'vhost-discovery-shared-infra')
            self.assertEqual(vhost_job['targets'], ['host-001.example.com', 'host-002.example.com'])
        finally:
            result_path.unlink(missing_ok=True)

    def test_vhost_gate_flags_shared_ip_and_proxy_only(self):
        from worker import _select_vhost_candidates

        service_assets = [
            {'domain': 'a.example.com', 'kind': 'static-site', 'ports': [443]},
            {'domain': 'b.example.com', 'kind': 'static-site', 'ports': [443]},
            {'domain': 'proxy.example.com', 'kind': 'reverse-proxy', 'ports': [443]},
            {'domain': 'unique.example.com', 'kind': 'static-site', 'ports': [443]},
        ]
        ip_map = {
            'a.example.com': {'10.0.0.1'},
            'b.example.com': {'10.0.0.1'},
            'proxy.example.com': {'10.0.0.9'},
            'unique.example.com': {'10.0.0.2'},
        }
        with patch('worker._resolve_host_ips', side_effect=lambda h: ip_map.get(h, set())):
            candidates = _select_vhost_candidates(service_assets)
        flagged = {c['domain']: c for c in candidates}
        self.assertIn('a.example.com', flagged)
        self.assertIn('b.example.com', flagged)
        self.assertIn('proxy.example.com', flagged)
        self.assertNotIn('unique.example.com', flagged)
        self.assertEqual(flagged['a.example.com']['reason'], 'shared-ip')
        self.assertEqual(sorted(flagged['a.example.com']['co_hosted']), ['b.example.com'])
        self.assertEqual(flagged['proxy.example.com']['reason'], 'proxy-fronted')

    def test_probe_vhost_handles_ipv6_without_raising(self):
        # An IPv6 literal must be bracketed in the URL; a bad address must never raise.
        from worker import _probe_vhost
        result = _probe_vhost('2001:db8::904b', 'host.example.com')
        self.assertIn('ok', result)
        self.assertFalse(result['ok'])

    def test_run_vhost_discovery_survives_ipv6_candidate(self):
        # A single malformed/unreachable probe must not crash the whole run.
        from worker import _run_vhost_discovery
        service_assets = [
            {'domain': 'a.example.com', 'kind': 'static-site', 'ports': [443]},
            {'domain': 'b.example.com', 'kind': 'static-site', 'ports': [443]},
        ]
        ip_map = {
            'a.example.com': {'2001:db8::904b'},
            'b.example.com': {'2001:db8::904b'},
        }
        with patch('worker._resolve_host_ips', side_effect=lambda h: ip_map.get(h, set())):
            result = _run_vhost_discovery(service_assets)
        self.assertIn('assets', result)
        self.assertIsInstance(result['assets'], list)

    def test_dashboard_detects_directory_enumeration_step_and_title(self):
        jobs = list_jobs()
        dir_job = next((job for job in jobs if job['name'] == 'directory-enumeration-live-hosts'), None)
        self.assertIsNotNone(dir_job)
        self.assertEqual(dir_job['workflow_step'], 6)
        self.assertEqual(dir_job['depends_on'], ['service-enumeration-live-hosts', 'vhost-discovery-shared-infra'])
        self.assertEqual(job_title_label('directory-enumeration-live-hosts'), 'Directory Enumeration')

    def test_directory_enumeration_uses_combined_step4_and_step5_hosts(self):
        step4 = ROOT / 'results' / 'service-enumeration-live-hosts.json'
        step5 = ROOT / 'results' / 'vhost-discovery-shared-infra.json'
        step4.parent.mkdir(parents=True, exist_ok=True)
        step4.write_text(__import__('json').dumps({
            'job': 'service-enumeration-live-hosts',
            'program': 'american-airlines',
            'status': 'ok',
            'discovered': ['app.example.com', 'api.example.com'],
            'assets': [
                {'domain': 'app.example.com', 'kind': 'app-server', 'ports': [443]},
                {'domain': 'api.example.com', 'kind': 'api-gateway', 'ports': [443]},
            ],
        }, indent=2), encoding='utf-8')
        step5.write_text(__import__('json').dumps({
            'job': 'vhost-discovery-shared-infra',
            'program': 'american-airlines',
            'status': 'ok',
            'discovered': ['api.example.com', 'vhost.example.com'],
            'assets': [
                {'domain': 'vhost.example.com', 'kind': 'shared-ip'},
            ],
        }, indent=2), encoding='utf-8')
        try:
            jobs = list_jobs()
            dir_job = next(job for job in jobs if job['name'] == 'directory-enumeration-live-hosts')
            self.assertEqual(dir_job['targets'], ['app.example.com', 'api.example.com', 'vhost.example.com'])
        finally:
            step4.unlink(missing_ok=True)
            step5.unlink(missing_ok=True)

    def test_directory_enumeration_records_interesting_paths(self):
        from worker import _directory_enumeration

        class FakeResponse:
            def __init__(self, status):
                self.status = status
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc_val, exc_tb):
                return False
            def getcode(self):
                return self.status
            def read(self, n=None):
                return b'body'

        def fake_urlopen(req, timeout=8):
            if req.full_url.endswith('/login'):
                return FakeResponse(200)
            if req.full_url.endswith('/admin'):
                return FakeResponse(403)
            raise OSError('404')

        with patch('worker.urllib_request.urlopen', side_effect=fake_urlopen):
            result = _directory_enumeration(['app.example.com'], wordlist=['/login', '/admin', '/nope'])
            asset = next(a for a in result['assets'] if a['domain'] == 'app.example.com')
            found_paths = {p['path']: p['status_code'] for p in asset['paths']}
            self.assertEqual(found_paths.get('/login'), 200)
            self.assertEqual(found_paths.get('/admin'), 403)
            self.assertNotIn('/nope', found_paths)
            self.assertTrue(result['thread_status'])

    def test_dashboard_detects_application_testing_step_and_title(self):
        jobs = list_jobs()
        app_job = next((job for job in jobs if job['name'] == 'application-security-testing'), None)
        self.assertIsNotNone(app_job)
        self.assertEqual(app_job['workflow_step'], 7)
        self.assertEqual(app_job['depends_on'], ['directory-enumeration-live-hosts'])
        self.assertEqual(job_title_label('application-security-testing'), 'Application Testing')

    def test_dashboard_detects_api_testing_step_and_title(self):
        jobs = list_jobs()
        api_job = next((job for job in jobs if job['name'] == 'api-endpoint-testing'), None)
        self.assertIsNotNone(api_job)
        self.assertEqual(api_job['workflow_step'], 8)
        self.assertEqual(api_job['depends_on'], ['directory-enumeration-live-hosts'])
        self.assertEqual(job_title_label('api-endpoint-testing'), 'API Testing')

    def test_api_testing_targets_api_gateways_and_api_path_hosts(self):
        step4 = ROOT / 'results' / 'service-enumeration-live-hosts.json'
        step6 = ROOT / 'results' / 'directory-enumeration-live-hosts.json'
        step4.parent.mkdir(parents=True, exist_ok=True)
        step4.write_text(__import__('json').dumps({
            'job': 'service-enumeration-live-hosts', 'program': 'american-airlines', 'status': 'ok',
            'discovered': ['api.example.com', 'www.example.com'],
            'assets': [
                {'domain': 'api.example.com', 'kind': 'api-gateway', 'ports': [443]},
                {'domain': 'www.example.com', 'kind': 'static-site', 'ports': [443]},
            ],
        }, indent=2), encoding='utf-8')
        step6.write_text(__import__('json').dumps({
            'job': 'directory-enumeration-live-hosts', 'program': 'american-airlines', 'status': 'ok',
            'discovered': ['portal.example.com'],
            'assets': [
                {'domain': 'portal.example.com', 'kind': 'content', 'paths': [{'path': '/api', 'status_code': 200}, {'path': '/login', 'status_code': 200}]},
                {'domain': 'www.example.com', 'kind': 'content', 'paths': [{'path': '/login', 'status_code': 200}]},
            ],
        }, indent=2), encoding='utf-8')
        try:
            jobs = list_jobs()
            api_job = next(job for job in jobs if job['name'] == 'api-endpoint-testing')
            # api.example.com (api-gateway) + portal.example.com (/api path); www excluded
            self.assertEqual(sorted(api_job['targets']), ['api.example.com', 'portal.example.com'])
        finally:
            step4.unlink(missing_ok=True)
            step6.unlink(missing_ok=True)

    def test_application_security_tests_flag_missing_headers_and_cors(self):
        from worker import _application_security_tests

        class FakeResp:
            def __init__(self, status, headers, body=b'ok'):
                self.status = status
                self._headers = headers
                self._body = body
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def getcode(self):
                return self.status
            def read(self, n=None):
                return self._body
            @property
            def headers(self):
                class H(dict):
                    def items(inner):
                        return list(super().items())
                h = H(); h.update(self._headers); return h

        def fake_urlopen(req, timeout=8):
            origin = req.headers.get('Origin') if hasattr(req, 'headers') else None
            if origin:
                return FakeResp(200, {'Access-Control-Allow-Origin': 'https://evil.example', 'Access-Control-Allow-Credentials': 'true'})
            return FakeResp(200, {'Server': 'nginx/1.18'})

        with patch('worker.urllib_request.urlopen', side_effect=fake_urlopen):
            result = _application_security_tests(['app.example.com'])
            asset = next(a for a in result['assets'] if a['domain'] == 'app.example.com')
            types = {f['type'] for f in asset['findings']}
            self.assertIn('missing_security_headers', types)
            self.assertIn('cors_misconfig', types)
            self.assertIn('tech_disclosure', types)

    def test_application_findings_generate_html_writeup_with_repro_steps(self):
        from worker import _application_security_tests, RESULTS_DIR

        class FakeResp:
            def __init__(self, status, headers, body=b'ok'):
                self.status = status
                self._headers = headers
                self._body = body
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def getcode(self):
                return self.status
            def read(self, n=None):
                return self._body
            @property
            def headers(self):
                class H(dict):
                    def items(inner):
                        return list(super().items())
                h = H(); h.update(self._headers); return h

        def fake_urlopen(req, timeout=8):
            origin = req.headers.get('Origin') if hasattr(req, 'headers') else None
            if origin:
                return FakeResp(200, {'Access-Control-Allow-Origin': 'https://evil.example', 'Access-Control-Allow-Credentials': 'true'})
            return FakeResp(200, {'Server': 'nginx/1.18'})

        report = RESULTS_DIR / 'reports' / 'application-security-testing' / 'app.example.com.html'
        report.unlink(missing_ok=True)
        with patch('worker.urllib_request.urlopen', side_effect=fake_urlopen):
            result = _application_security_tests(['app.example.com'])
            asset = next(a for a in result['assets'] if a['domain'] == 'app.example.com')
            self.assertEqual(asset.get('report_url'), '/reports/application-security-testing/app.example.com')
            self.assertTrue(report.exists())
            html = report.read_text(encoding='utf-8')
            self.assertIn('Steps to Reproduce', html)
            self.assertIn('app.example.com', html)
            self.assertIn('curl', html)
        report.unlink(missing_ok=True)

    def test_api_endpoint_tests_flag_exposed_debug_endpoint(self):
        from worker import _api_endpoint_tests

        class FakeResp:
            def __init__(self, status, headers, body=b'{}'):
                self.status = status
                self._headers = headers
                self._body = body
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def getcode(self):
                return self.status
            def read(self, n=None):
                return self._body
            @property
            def headers(self):
                class H(dict):
                    def items(inner):
                        return list(super().items())
                h = H(); h.update(self._headers); return h

        def fake_urlopen(req, timeout=8):
            url = req.full_url
            if url.endswith('/actuator/env'):
                return FakeResp(200, {'Content-Type': 'application/json'}, b'{"activeProfiles":["prod"],"propertySources":[]}')
            raise OSError('404')

        with patch('worker.urllib_request.urlopen', side_effect=fake_urlopen):
            result = _api_endpoint_tests(['api.example.com'])
            asset = next(a for a in result['assets'] if a['domain'] == 'api.example.com')
            debug = [f for f in asset['findings'] if f['type'] == 'debug_endpoint']
            self.assertTrue(any(f['path'] == '/actuator/env' and f['exposes_data'] for f in debug))

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
