import sys
import unittest
import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'automation') not in sys.path:
    sys.path.insert(0, str(ROOT / 'automation'))

from program_builder import active_approved, analyze_url_scope, create_manual_program, create_program, parse_scope, read_guidelines, set_active_approval
from stages import STAGES
from worker import load_job, run_passive_job, job_workflow_dependencies
import worker
from dashboard_app import app, group_jobs_by_program, job_workflow_metadata, list_jobs


class ProgramBuilderTest(unittest.TestCase):
    def test_auto_run_policy_defaults_and_testing_restrictions(self):
        from program_builder import auto_run_policy
        policy = auto_run_policy('Automated testing is permitted. Respect scope exclusions.')
        self.assertEqual(policy['requests_per_second'], 1)
        self.assertEqual(policy['max_workers'], 2)
        self.assertEqual(len(policy['allowed_stages']), 9)
        self.assertFalse(policy['external_probes'])
        limited = auto_run_policy('Maximum 0.5 requests per second. Port scanning is prohibited. No directory enumeration.')
        self.assertEqual(limited['requests_per_second'], 0.5)
        self.assertNotIn('port-scan', limited['allowed_stages'])
        self.assertNotIn('directory-enumeration', limited['allowed_stages'])
        self.assertEqual(auto_run_policy('Rate limit: 12 requests per minute.')['requests_per_second'], 0.2)
        self.assertEqual(auto_run_policy('Maximum 0.25 RPS.')['requests_per_second'], 0.25)
        for rules in ('No automated scans.', 'Automation is prohibited.', 'Do not perform automated testing.'):
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                auto_run_policy(rules)

    def test_auto_run_configuration_requires_current_approval_and_domain_scope(self):
        from program_builder import configure_auto_run
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('automatic', ['*.example.com'], root=root, guidelines='Automation allowed.')
            with self.assertRaises(PermissionError):
                configure_auto_run('automatic', root=root)
            _, digest = read_guidelines('automatic', root=root)
            set_active_approval('automatic', True, digest, root=root)
            policy = configure_auto_run('automatic', root=root)
            self.assertEqual(policy['guidelines_sha256'], digest)
            self.assertTrue(policy['scope_sha256'])
            self.assertTrue((root / 'programs/automatic/.auto-run.json').exists())

    def test_auto_run_guard_paces_requests_and_enforces_scope_and_revocation(self):
        from auto_run import AutoRunGuard
        from program_builder import configure_auto_run
        from urllib.request import Request
        from urllib.error import URLError
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('automatic', ['*.example.com'], root=root, guidelines='Maximum 0.5 requests per second.')
            _, digest = read_guidelines('automatic', root=root)
            set_active_approval('automatic', True, digest, root=root)
            configure_auto_run('automatic', root=root)
            now = [0.0]
            calls = []
            sleeps = []

            def fake_sleep(delay):
                sleeps.append(delay)
                now[0] += delay

            guard = AutoRunGuard('automatic', root=root, open_request=lambda req, **kwargs: calls.append(req.full_url),
                                  sleep_fn=fake_sleep, monotonic_fn=lambda: now[0])
            guard.scope = ['*.example.com']
            guard.stage = 'application-testing'
            guard.urlopen('https://app.example.com/')
            guard.urlopen('https://api.example.com/health')
            self.assertEqual(sleeps, [2.0])
            with self.assertRaises(URLError):
                guard.urlopen('https://outside.example.org/')
            with self.assertRaises(URLError):
                guard.urlopen(Request('https://203.0.113.8/', headers={'Host': 'outside.example.org'}))
            self.assertEqual(len(calls), 2)
            set_active_approval('automatic', False, digest, root=root)
            with self.assertRaises(PermissionError):
                guard.urlopen('https://app.example.com/')
            self.assertEqual(len(calls), 2)

    def test_auto_run_pipeline_executes_all_nine_stages_in_order_with_shared_pacing(self):
        from auto_run import run_auto_pipeline
        from program_builder import configure_auto_run
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('automatic', ['*.example.com'], root=root, guidelines='Automated checks allowed.')
            _, digest = read_guidelines('automatic', root=root)
            set_active_approval('automatic', True, digest, root=root)
            configure_auto_run('automatic', root=root)
            now = [0.0]
            calls = []
            stages = []
            original_http = worker.urllib_request.urlopen
            original_workers = worker.MAX_WORKERS

            def fake_sleep(delay):
                now[0] += delay

            def fake_open(req, **kwargs):
                calls.append((req.full_url, now[0]))
                return None

            def fake_stage(job, scope, **kwargs):
                stages.append(job['stage'])
                self.assertFalse(kwargs['use_external_tools'])
                self.assertLessEqual(worker.MAX_WORKERS, 2)
                url = 'https://crt.sh/?q=example.com' if job['type'] == 'passive' else 'https://app.example.com/'
                worker.urllib_request.urlopen(url)
                return {'job': job['name'], 'program': 'automatic', 'type': job['type'], 'status': 'ok',
                        'targets': ['app.example.com'], 'discovered': ['app.example.com'], 'assets': [], 'source_count': 0}

            with patch.object(worker, 'ROOT', root), patch.object(worker, 'RESULTS_DIR', root / 'results'), \
                 patch.object(worker, 'RUNNING_DIR', root / 'results/.running'), \
                 patch.object(worker, 'run_passive_job', side_effect=fake_stage):
                results = run_auto_pipeline('automatic', root=root, open_request=fake_open,
                                            sleep_fn=fake_sleep, monotonic_fn=lambda: now[0])
                self.assertEqual(stages, [stage['stage'] for stage in STAGES])
                self.assertEqual(len(results), 9)
                self.assertTrue(all(result['job_state'] == 'completed' for result in results))
                self.assertTrue(all(later[1] - earlier[1] >= 1 for earlier, later in zip(calls, calls[1:])))
                self.assertFalse((root / 'results/.running/auto-program-automatic.lock').exists())
            self.assertIs(worker.urllib_request.urlopen, original_http)
            self.assertEqual(worker.MAX_WORKERS, original_workers)

    def test_auto_run_guard_covers_worker_http_dns_vhost_and_tcp(self):
        from auto_run import AutoRunGuard
        from program_builder import configure_auto_run
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('automatic', ['*.example.com'], root=root, guidelines='Automated testing allowed.')
            _, digest = read_guidelines('automatic', root=root)
            set_active_approval('automatic', True, digest, root=root)
            configure_auto_run('automatic', root=root)
            now = [0.0]
            calls = []

            class Response:
                status = 200
                headers = {'Server': 'mock-edge'}
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def getcode(self): return 200
                def read(self, *args): return b'public test response'

            def fake_open(req, **kwargs):
                calls.append((req.full_url, now[0]))
                return Response()

            guard = AutoRunGuard('automatic', root=root, open_request=fake_open,
                                  sleep_fn=lambda delay: now.__setitem__(0, now[0] + delay), monotonic_fn=lambda: now[0])
            guard.scope = ['*.example.com']
            with patch.object(worker, '_resolve_host_ips', return_value={'203.0.113.7'}) as resolve, \
                 patch.object(worker, '_tcp_port_open', return_value=True) as tcp:
                with guard.installed(worker):
                    guard.stage = 'vhost-discovery'
                    self.assertEqual(worker._resolve_host_ips('app.example.com'), {'203.0.113.7'})
                    self.assertEqual(worker._fetch_headers_body('https://app.example.com/')[0], 200)
                    self.assertTrue(worker._probe_vhost('203.0.113.7', 'app.example.com')['ok'])
                    guard.stage = 'port-scan'
                    self.assertTrue(worker._tcp_port_open('203.0.113.7', 6379))
                    self.assertFalse(worker._tcp_port_open('198.51.100.99', 6379))
                resolve.assert_called_once_with('app.example.com')
                tcp.assert_called_once_with('203.0.113.7', 6379, 1.5)
            self.assertEqual([timestamp for _, timestamp in calls], [1.0, 2.0])
            self.assertEqual(now[0], 3.0)

    def test_auto_run_pipeline_marks_forbidden_stages_without_executing_them(self):
        from auto_run import run_auto_pipeline
        from program_builder import configure_auto_run
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('automatic', ['*.example.com'], root=root, guidelines='Automated testing allowed. No port scanning.')
            _, digest = read_guidelines('automatic', root=root)
            set_active_approval('automatic', True, digest, root=root)
            configure_auto_run('automatic', root=root)
            stages = []

            def fake_stage(job, scope, **kwargs):
                stages.append(job['stage'])
                return {'job': job['name'], 'program': 'automatic', 'type': job['type'], 'status': 'ok', 'assets': [], 'discovered': []}

            with patch.object(worker, 'ROOT', root), patch.object(worker, 'RESULTS_DIR', root / 'results'), \
                 patch.object(worker, 'RUNNING_DIR', root / 'results/.running'), \
                 patch.object(worker, 'run_passive_job', side_effect=fake_stage):
                results = run_auto_pipeline('automatic', root=root)
            self.assertNotIn('port-scan', stages)
            self.assertEqual(len(stages), 8)
            self.assertEqual(results[-1]['job_state'], 'blocked')

    def test_auto_run_guard_redirects_and_scope_change_fail_closed(self):
        from auto_run import AutoRunGuard
        from program_builder import configure_auto_run
        from urllib.error import URLError
        from urllib.request import HTTPRedirectHandler, Request
        from email.message import Message
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('automatic', ['*.example.com'], root=root, guidelines='Automated checks allowed.')
            _, digest = read_guidelines('automatic', root=root)
            set_active_approval('automatic', True, digest, root=root)
            configure_auto_run('automatic', root=root)
            now = [0.0]
            guard = AutoRunGuard('automatic', root=root, sleep_fn=lambda delay: now.__setitem__(0, now[0] + delay),
                                  monotonic_fn=lambda: now[0])
            guard.scope = ['*.example.com']
            guard.stage = 'confirm-live-web-assets'
            redirect = next(handler for handler in guard.open_request.__self__.handlers if isinstance(handler, HTTPRedirectHandler))
            req = Request('https://app.example.com/')
            guard.before_http(req)
            followed = redirect.redirect_request(req, None, 302, 'redirect', Message(), 'https://api.example.com/public')
            self.assertEqual(followed.full_url, 'https://api.example.com/public')
            self.assertEqual(now[0], 1)
            for target in ('https://outside.example.org/', 'https://app.example.com/login', 'http://app.example.com/'):
                with self.subTest(target=target), self.assertRaises(URLError):
                    redirect.redirect_request(req, None, 302, 'redirect', Message(), target)
            (root / 'programs/automatic/scope.md').write_text('# Changed scope\n\n## In scope\n- *.other.example\n')
            with self.assertRaises(PermissionError):
                guard.before_http(Request('https://app.example.com/'))

    def test_worker_dispatches_opted_in_program_to_guarded_pipeline(self):
        from program_builder import configure_auto_run
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('automatic', ['*.example.com'], root=root, guidelines='Automated testing permitted.')
            _, digest = read_guidelines('automatic', root=root)
            set_active_approval('automatic', True, digest, root=root)
            configure_auto_run('automatic', root=root)
            with patch.object(worker, 'ROOT', root), patch.object(worker, 'JOBS_DIR', root / 'jobs'), \
                 patch('auto_run.run_auto_pipeline', return_value=[]) as pipeline, \
                 patch('sys.argv', ['worker.py', '--program', 'automatic', '--auto-run']), \
                 redirect_stdout(io.StringIO()):
                worker.main()
            pipeline.assert_called_once_with('automatic', root=root, job_name=None, force=False)

    def test_url_scope_analysis_is_exact_and_blocks_ambiguous_rules(self):
        content = ('identifier,asset_type,in_scope\n'
                   'https://app.example.com/account?token=private,URL,true\n'
                   'https://app.example.com/login,URL,true\n'
                   'com.example.app,GOOGLE_PLAY_APP_ID,true\n')
        analysis = analyze_url_scope(content, 'No aggressive scanning. Traffic must not exceed 3 requests per second.')
        self.assertEqual(analysis['policy']['automated_requests'], 'manual_approval_required')
        self.assertEqual(analysis['policy']['max_requests_per_second'], 1)
        self.assertEqual(analysis['policy']['stated_max_requests_per_second'], 3)
        self.assertEqual(analysis['policy']['method'], 'HEAD')
        self.assertTrue(analysis['policy']['follows_redirects'])
        self.assertTrue(analysis['policy']['skips_login_redirects'])
        self.assertEqual(analysis['eligible_urls'], 2)
        self.assertEqual(analysis['app_ids'], 1)
        self.assertEqual(analysis['app_assets'][0]['platform'], 'Google Play')
        self.assertEqual(analysis['assets'][0]['host'], 'app.example.com')
        self.assertEqual(analysis['assets'][0]['path'], '/account')
        self.assertTrue(analysis['assets'][0]['query_present'])
        self.assertNotIn('token=private', json.dumps(analysis))
        self.assertEqual(analysis['assets'][1]['category'], 'login')
        malformed = analyze_url_scope('identifier,asset_type,in_scope\nhttps://example.com:bad/path,URL,true\n', 'No automated scans.')
        self.assertEqual(malformed['eligible_urls'], 1)
        self.assertEqual(malformed['invalid_urls'], 1)
        self.assertEqual(malformed['assets'], [])
        prohibited = analyze_url_scope(
            'identifier,asset_type,in_scope\napp.example.com,URL,true\n',
            'Do not perform automated requests. Maximum 3 requests per second.')
        self.assertEqual(prohibited['policy']['automated_requests'], 'blocked')

    def test_automation_bans_override_rate_limits_but_report_restrictions_require_approval(self):
        content = 'identifier,asset_type,in_scope\napp.example.com,URL,true\n'
        for prohibition in ('No automated scans.', 'Automated scans are prohibited.',
                            'Automated requests are not allowed.', 'Do not perform automated testing.'):
            with self.subTest(prohibition=prohibition):
                policy = analyze_url_scope(content, prohibition + ' Maximum 3 requests per second.')['policy']
                self.assertEqual(policy['automated_requests'], 'blocked')
        policy = analyze_url_scope(content, 'Reports from automated tools or scans are ineligible. '
                                   'Do not perform aggressive vulnerability scans. Maximum 3 requests per second.')['policy']
        self.assertEqual(policy['automated_requests'], 'manual_approval_required')
        self.assertIn('manual verification', policy['reason'])

    def test_url_asset_bare_hostname_is_exact_host_not_wildcard(self):
        analysis = analyze_url_scope(
            'identifier,asset_type,in_scope\nportal.example.com,URL,true\n',
            'No automated scans. Requests must not exceed 3 requests per second.')
        self.assertEqual(analysis['assets'][0]['scope_kind'], 'exact_host')
        self.assertEqual(analysis['assets'][0]['host'], 'portal.example.com')
        self.assertEqual(analysis['assets'][0]['path'], '/')
        self.assertEqual(analysis['policy']['automated_requests'], 'blocked')
        wildcard = analyze_url_scope('identifier,asset_type,in_scope\n*.example.com,URL,true\n',
                         'Maximum 3 requests per second.')
        self.assertEqual(wildcard['assets'], [])
        self.assertEqual(wildcard['invalid_urls'], 1)

    def test_dashboard_imports_as_gunicorn_package(self):
        subprocess.run([sys.executable, '-c', 'from automation.dashboard_app import app'],
                       cwd=ROOT, check=True, capture_output=True)

    def test_hackerone_csv_filters_out_of_scope_and_unsupported_assets(self):
        slug, targets = parse_scope('hackerone-demo-scope.csv',
            'identifier,asset_type,eligible_for_bounty\n'
            '*.example.com,WILDCARD,true\n'
            'ignored.other.com,DOMAIN,false\n'
            '10.0.0.0/8,CIDR,false\n')
        self.assertEqual(slug, 'demo')
        self.assertEqual(targets, ['*.example.com'])
        with self.assertRaises(ValueError):
            parse_scope('demo.csv', 'identifier,asset_type,in_scope\n*.example.com,WILDCARD,true\n10.0.0.0/8,CIDR,true\n')

    def test_bugcrowd_csv_and_markdown_restrict_to_explicit_scope(self):
        slug, targets = parse_scope('bugcrowd-example-scope.csv',
            'Target,Type,In Scope\nhttps://app.example.com/,URL,yes\nadmin.other.com,domain,no\n')
        self.assertEqual((slug, targets), ('example', ['app.example.com']))
        slug, targets = parse_scope('new-program.md',
            '# Program\n## In-scope targets\n- *.example.com\n- api.example.com\n'
            '## Out-of-scope targets\n- internal.other.com\n')
        self.assertEqual((slug, targets), ('new-program', ['*.example.com', 'api.example.com']))
        with self.assertRaises(ValueError):
            parse_scope('scope.md', '# Example Program Scope\n## In-scope targets\n- *.example.com\n## Not in scope\n- secret.example.com\n')
        with self.assertRaises(ValueError):
            parse_scope('bugcrowd-example.csv', 'Target,Type,In Scope\nhttps://app.example.com/login,URL,yes\n')

    def test_rejects_ambiguous_scope_and_duplicate_programs(self):
        with self.assertRaises(ValueError):
            parse_scope('demo.csv', 'identifier,asset_type\n*.example.com,WILDCARD\n')
        with self.assertRaises(ValueError):
            parse_scope('demo.csv', 'identifier,asset_type,in_scope\n*.example.com,WILDCARD,true,unexpected\n')
        with self.assertRaises(ValueError):
            parse_scope('demo.csv', 'identifier,asset_type,in_scope,program\n*.example.com,WILDCARD,true,one\n*.other.com,WILDCARD,true,two\n')
        with TemporaryDirectory() as directory:
            root = Path(directory)
            names = create_program('demo', ['*.example.com'], root=root)
            self.assertEqual(len(names), len(STAGES))
            self.assertTrue((root / 'programs/demo/scope.md').exists())
            for stage, name in zip(STAGES, names):
                job = load_job(root / 'jobs' / 'generated' / f'{name}.yaml')
                self.assertEqual(job['program'], 'demo')
                self.assertEqual(job['targets'], ['*.example.com'])
                self.assertEqual(job['stage'], stage['stage'])
            with self.assertRaises(FileExistsError):
                create_program('demo', ['*.other.example'], root=root)

    def test_service_stage_reads_only_its_program_results(self):
        job = {'name': 'demo-service-enumeration', 'program': 'demo', 'stage': 'service-enumeration', 'type': 'active'}
        with TemporaryDirectory() as directory, patch('worker.RESULTS_DIR', Path(directory)):
            root = Path(directory)
            (root / 'confirm-live-web-assets.json').write_text(json.dumps({'discovered': ['aa.example.com']}), encoding='utf-8')
            waiting = run_passive_job(job, ['*.example.com'])
            self.assertEqual(waiting['status'], 'waiting_on_dependencies')
            self.assertEqual(waiting['dependencies'], ['demo-confirm-live-web-assets'])
            (root / 'demo-confirm-live-web-assets.json').write_text(json.dumps({'discovered': ['demo.example.com']}), encoding='utf-8')
            with patch('worker._enumerate_live_services', return_value={'assets': [], 'discovered': []}) as enumerate_services:
                result = run_passive_job(job, ['*.example.com'])
            enumerate_services.assert_called_once()
            self.assertEqual(enumerate_services.call_args.args[0], ['demo.example.com'])
            self.assertEqual(result['depends_on'], ['demo-confirm-live-web-assets'])
            self.assertEqual(job_workflow_dependencies('demo-port-scan'), [
                'demo-vhost-discovery', 'demo-directory-enumeration', 'demo-application-testing',
            ])

    def test_dashboard_lists_generated_program_stages(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('demo', ['*.example.com'], root=root, guidelines='Read-only validation.')
            with patch('dashboard_app.ROOT', root), patch('dashboard_app.JOBS_DIR', root / 'jobs'), patch('dashboard_app.RESULTS_DIR', root / 'results'):
                jobs = list_jobs()
                page = app.test_client().get('/')
            self.assertEqual(len(jobs), 9)
            self.assertEqual({job['program'] for job in jobs}, {'demo'})
            self.assertEqual([job['workflow_step'] for job in jobs], list(range(1, 10)))
            self.assertEqual(jobs[0]['queued'], ['*.example.com'])
            self.assertEqual(jobs[3]['queued'], [])
            self.assertEqual(page.status_code, 200)
            self.assertIn(b'id="program-upload"', page.data)
            self.assertIn(b'id="program-name"', page.data)
            self.assertIn(b'id="guidelines-file"', page.data)
            self.assertIn(b'function uploadDraftPending()', page.data)
            self.assertIn(b'scopeFile.files.length > 0', page.data)
            self.assertIn(b'guidelinesFile.files.length > 0', page.data)
            self.assertIn(b'async function refreshDashboard', page.data)
            self.assertIn(b'reconcileDashboardNode', page.data)
            self.assertNotIn(b'window.location.reload()', page.data)
            self.assertNotIn(b'restoreViewState()', page.data)
            self.assertIn(b'uploadComplete = true;', page.data)
            self.assertIn(b'Review required', page.data)
            self.assertIn(b'class="rules-acknowledged"', page.data)
            self.assertIn(b'disabled title="Review guidelines before active testing"', page.data)
            self.assertIn(b'Step 9', page.data)
            self.assertEqual(job_workflow_metadata('demo-port-scan')['depends_on'], [
                'demo-vhost-discovery', 'demo-directory-enumeration', 'demo-application-testing',
            ])

    def test_multiple_programs_have_separate_dashboard_groups(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('demo', ['*.example.com'], root=root)
            create_program('second', ['*.second.example'], root=root)
            with patch('dashboard_app.JOBS_DIR', root / 'jobs'), patch('dashboard_app.RESULTS_DIR', root / 'results'):
                grouped = group_jobs_by_program(list_jobs())
            self.assertEqual(set(grouped), {'demo', 'second'})
            self.assertTrue(all(len(jobs) == 9 for jobs in grouped.values()))
            self.assertFalse(set(job['name'] for job in grouped['demo']) & set(job['name'] for job in grouped['second']))

    def test_upload_authentication_generation_and_scoped_queue(self):
        with TemporaryDirectory() as directory, \
             patch('dashboard_app.ROOT', Path(directory)), \
             patch('dashboard_app.JOBS_DIR', Path(directory) / 'jobs'), \
             patch('dashboard_app.RESULTS_DIR', Path(directory) / 'results'), \
             patch('dashboard_app.subprocess.Popen') as launch, \
             patch.dict('dashboard_app.os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token', 'BUGBOUNTY_ALLOW_ACTIVE': '1'}):
            csv_data = b'identifier,asset_type,eligible_for_bounty\n*.example.com,WILDCARD,true\n'
            with app.test_client() as client:
                unauthorized = client.post('/programs/upload', data={'scope_file': (io.BytesIO(csv_data), 'hackerone-demo-scope.csv')})
                self.assertEqual(unauthorized.status_code, 401)
                self.assertFalse((Path(directory) / 'programs').exists())
                headers = {'X-BugBounty-Token': 'test-token'}
                malformed = client.post('/programs/upload', data={'program_name': 'Demo', 'scope_file': (io.BytesIO(b'bad data'), 'demo.csv')}, headers=headers)
                self.assertEqual(malformed.status_code, 400)
                no_rules = client.post('/programs/upload', data={'program_name': 'Demo', 'scope_file': (io.BytesIO(csv_data), 'hackerone-demo-scope.csv')}, headers=headers)
                self.assertEqual(no_rules.status_code, 400)
                self.assertFalse((Path(directory) / 'programs/demo').exists())
                accepted = client.post('/programs/upload', data={
                    'program_name': 'Demo',
                    'scope_file': (io.BytesIO(csv_data), 'hackerone-demo-scope.csv'),
                    'guidelines_text': 'Authorized read-only checks. No credential testing.',
                }, headers=headers)
                self.assertEqual(accepted.status_code, 202)
                self.assertEqual(accepted.get_json()['program'], 'demo')
                self.assertEqual(len(accepted.get_json()['jobs']), 9)
                self.assertEqual(launch.call_args.args[0][-2:], ['--program', 'demo'])
                self.assertIn('No credential testing.', (Path(directory) / 'programs/demo/rules.md').read_text(encoding='utf-8'))
                self.assertEqual(len(list_jobs()), 9)
                duplicate = client.post('/programs/upload', data={
                    'program_name': 'Demo',
                    'scope_file': (io.BytesIO(csv_data), 'hackerone-demo-scope.csv'),
                    'guidelines_text': 'Authorized read-only checks. No credential testing.',
                }, headers=headers)
                self.assertEqual(duplicate.status_code, 409)
                launch.assert_called_once()

    def test_upload_requires_name_and_separates_same_named_scope_files(self):
        with TemporaryDirectory() as directory, \
             patch('dashboard_app.ROOT', Path(directory)), \
             patch('dashboard_app.JOBS_DIR', Path(directory) / 'jobs'), \
             patch('dashboard_app.RESULTS_DIR', Path(directory) / 'results'), \
             patch('dashboard_app.subprocess.Popen') as launch, \
             patch.dict('dashboard_app.os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token'}):
            csv_data = b'identifier,asset_type,in_scope\n*.example.com,WILDCARD,true\n'
            headers = {'X-BugBounty-Token': 'test-token'}

            def submit(client, name):
                return client.post('/programs/upload', data={
                    'program_name': name,
                    'scope_file': (io.BytesIO(csv_data), 'scope.csv'),
                    'guidelines_text': 'Read-only validation.',
                }, headers=headers)

            with app.test_client() as client:
                self.assertEqual(submit(client, '').status_code, 400)
                self.assertEqual(submit(client, '../../other').status_code, 400)
                self.assertFalse((Path(directory) / 'programs').exists())
                first = submit(client, 'NBA Public')
                second = submit(client, 'WNBA Public')
                self.assertEqual(first.status_code, 202)
                self.assertEqual(second.status_code, 202)
                self.assertEqual(first.get_json()['program'], 'nba-public')
                self.assertEqual(second.get_json()['program'], 'wnba-public')
                self.assertTrue((Path(directory) / 'programs/nba-public/scope.md').exists())
                self.assertTrue((Path(directory) / 'programs/wnba-public/scope.md').exists())
                self.assertFalse(set(first.get_json()['jobs']) & set(second.get_json()['jobs']))
                self.assertEqual(launch.call_count, 2)

    def test_url_and_app_scope_creates_manual_only_program(self):
        with TemporaryDirectory() as directory, \
             patch('dashboard_app.ROOT', Path(directory)), \
             patch('dashboard_app.JOBS_DIR', Path(directory) / 'jobs'), \
             patch('dashboard_app.RESULTS_DIR', Path(directory) / 'results'), \
             patch('dashboard_app.subprocess.Popen') as launch, \
             patch.dict('dashboard_app.os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token', 'BUGBOUNTY_ALLOW_ACTIVE': '1'}):
            scope = (b'identifier,asset_type,in_scope\n'
                     b'https://app.example.com/restricted,URL,true\n'
                     b'com.example.app,GOOGLE_PLAY_APP_ID,true\n')
            with app.test_client() as client:
                response = client.post('/programs/upload', data={
                    'program_name': 'NBA Public',
                    'scope_file': (io.BytesIO(scope), 'scope.csv'),
                    'guidelines_text': 'Only known paths permitted.',
                }, headers={'X-BugBounty-Token': 'test-token'})
                self.assertEqual(response.status_code, 202)
                self.assertEqual(response.get_json()['status'], 'manual_review')
                self.assertEqual(response.get_json()['jobs'], [])
                self.assertTrue((Path(directory) / 'programs/nba-public/scope-source.csv').exists())
                inventory = json.loads((Path(directory) / 'programs/nba-public/scope-inventory.json').read_text())
                self.assertEqual(inventory['eligible_asset_types'], {'URL': 1, 'GOOGLE_PLAY_APP_ID': 1})
                self.assertEqual(list_jobs(), [])
                page = client.get('/')
                self.assertIn(b'NBA Public', page.data)
                self.assertIn(b'Start exact-URL check', page.data)
                duplicate = client.post('/programs/upload', data={
                    'program_name': 'NBA Public',
                    'scope_file': (io.BytesIO(scope), 'scope.csv'),
                    'guidelines_text': 'Only known paths permitted.',
                }, headers={'X-BugBounty-Token': 'test-token'})
                self.assertEqual(duplicate.status_code, 409)
                launch.assert_not_called()

    def test_existing_url_program_analysis_requires_token_and_redacts_query(self):
        with TemporaryDirectory() as directory, \
             patch('dashboard_app.ROOT', Path(directory)), \
             patch('dashboard_app.JOBS_DIR', Path(directory) / 'jobs'), \
             patch.dict('dashboard_app.os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token'}):
            root = Path(directory)
            scope = ('identifier,asset_type,in_scope\n'
                     'https://app.example.com/api/info?secret=private,URL,true\n')
            inventory = {'eligible_asset_types': {'URL': 1}, 'total_rows': 1, 'manual_only': True,
                         'display_name': 'NBA Public'}
            from program_builder import create_manual_program
            create_manual_program('nba-public', scope, 'No aggressive scans. Maximum 3 requests per second.',
                                  inventory, root=root)
            with app.test_client() as client:
                self.assertEqual(client.get('/programs/nba-public/analysis').status_code, 401)
                response = client.get('/programs/nba-public/analysis', headers={'X-BugBounty-Token': 'test-token'})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()['categories'], {'api': 1})
                self.assertEqual(response.get_json()['policy']['automated_requests'], 'manual_approval_required')
                self.assertNotIn(b'secret=private', response.data)

    def test_rules_review_and_approval_requires_current_guidelines(self):
        with TemporaryDirectory() as directory, \
             patch('dashboard_app.ROOT', Path(directory)), \
             patch('dashboard_app.JOBS_DIR', Path(directory) / 'jobs'), \
             patch('dashboard_app.subprocess.Popen') as launch, \
             patch.dict('dashboard_app.os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token', 'BUGBOUNTY_ALLOW_ACTIVE': '1'}):
            root = Path(directory)
            create_program('demo', ['*.example.com'], root=root, guidelines='No credential testing.')
            headers = {'X-BugBounty-Token': 'test-token'}
            with app.test_client() as client:
                self.assertEqual(client.get('/programs/demo/guidelines').status_code, 401)
                self.assertEqual(client.post('/programs/demo/active-approval', json={'approved': True}).status_code, 401)
                rules = client.get('/programs/demo/guidelines', headers=headers).get_json()
                self.assertEqual(rules['text'], 'No credential testing.\n')
                self.assertFalse(rules['approved'])
                url = '/programs/demo/active-approval'
                decision = {'approved': True, 'guidelines_sha256': rules['guidelines_sha256']}
                self.assertEqual(client.post(url, json=decision, headers=headers).status_code, 400)
                decision['acknowledged'] = True
                self.assertEqual(client.post(url, json={**decision, 'guidelines_sha256': 'old'}, headers=headers).status_code, 409)
                launch.assert_not_called()
                response = client.post(url, json=decision, headers=headers)
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.get_json()['active_run_started'])
                self.assertEqual(launch.call_args.args[0][-3:], ['--program', 'demo', '--allow-active'])
                self.assertTrue(active_approved('demo', root=root))
                (root / 'programs/demo/rules.md').write_text('No active testing.\n', encoding='utf-8')
                self.assertFalse(active_approved('demo', root=root))
                self.assertFalse(client.get('/programs/demo/guidelines', headers=headers).get_json()['approved'])

    def test_guidelines_file_upload_blocks_active_reruns_until_approved(self):
        with TemporaryDirectory() as directory, \
             patch('dashboard_app.ROOT', Path(directory)), \
             patch('dashboard_app.JOBS_DIR', Path(directory) / 'jobs'), \
             patch('dashboard_app.RESULTS_DIR', Path(directory) / 'results'), \
             patch('dashboard_app.subprocess.Popen') as launch, \
             patch.dict('dashboard_app.os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token', 'BUGBOUNTY_ALLOW_ACTIVE': '1'}):
            with app.test_client() as client:
                response = client.post('/programs/upload', data={
                    'program_name': 'Demo',
                    'scope_file': (io.BytesIO(b'identifier,asset_type,in_scope\n*.example.com,WILDCARD,true\n'), 'demo-scope.csv'),
                    'guidelines_file': (io.BytesIO(b'No active testing until approved.'), 'terms.md'),
                }, headers={'X-BugBounty-Token': 'test-token'})
                self.assertEqual(response.status_code, 202)
                self.assertEqual(response.get_json()['status'], 'pending_review')
                self.assertIn('No active testing', (Path(directory) / 'programs/demo/rules.md').read_text(encoding='utf-8'))
                blocked = client.post('/jobs/demo-confirm-live-web-assets/rerun', headers={'X-BugBounty-Token': 'test-token'})
                self.assertEqual(blocked.status_code, 409)
                launch.assert_called_once()

    def test_worker_runs_generated_program_without_aa_results(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('demo', ['*.example.com'], root=root)
            legacy = {'assets': [{'domain': 'app.example.com', 'sources': ['public-source'], 'evidence': []}],
                      'discovered': ['app.example.com'], 'targets': ['*.example.com']}
            passive = {'assets': [], 'targets': ['*.example.com']}
            with patch.object(worker, 'ROOT', root), patch.object(worker, 'RESULTS_DIR', root / 'results'), \
                 patch.object(worker, 'RUNNING_DIR', root / 'results' / '.running'), \
                 patch.object(worker, 'JOBS_DIR', root / 'jobs'), \
                 patch('passive_discovery.build_job_output', return_value=legacy) as build, \
                 patch('passive_dns_enrichment.passive_dns_enrichment', return_value=passive) as dns, \
                 patch('sys.argv', ['worker.py', '--program', 'demo']), redirect_stdout(io.StringIO()):
                worker.main()
            build.assert_called_once_with(['*.example.com'], 'demo-passive-web-discovery')
            dns.assert_called_once_with('demo')
            self.assertTrue((root / 'results/demo-passive-web-discovery.json').exists())
            self.assertTrue((root / 'results/demo-passive-dns-discovery.json').exists())
            self.assertFalse((root / 'results/aa-passive-discovery.json').exists())

    def test_passive_worker_does_not_remove_active_job_lock(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('demo', ['*.example.com'], root=root)
            lock = root / 'results/.running/demo-confirm-live-web-assets.lock'
            lock.parent.mkdir(parents=True)
            lock.write_text(str(__import__('os').getpid()), encoding='utf-8')
            with patch.object(worker, 'ROOT', root), patch.object(worker, 'RESULTS_DIR', root / 'results'), \
                 patch.object(worker, 'RUNNING_DIR', lock.parent), \
                 patch.object(worker, 'JOBS_DIR', root / 'jobs'), \
                 patch('passive_discovery.build_job_output', return_value={'assets': [], 'targets': []}), \
                 patch('passive_dns_enrichment.passive_dns_enrichment', return_value={'assets': [], 'targets': []}), \
                 patch('sys.argv', ['worker.py', '--program', 'demo']), redirect_stdout(io.StringIO()):
                worker.main()
            self.assertTrue(lock.exists())

    def test_generated_active_workflow_uses_its_own_dependencies(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('demo', ['*.example.com'], root=root, guidelines='Read-only testing permitted.')
            _, digest = read_guidelines('demo', root=root)
            set_active_approval('demo', True, digest, root=root)
            with patch.object(worker, 'ROOT', root), patch.object(worker, 'RESULTS_DIR', root / 'results'), \
                 patch.object(worker, 'RUNNING_DIR', root / 'results' / '.running'), \
                 patch.object(worker, 'JOBS_DIR', root / 'jobs'), \
                 patch('passive_discovery.build_job_output', return_value={
                     'assets': [{'domain': 'app.example.com', 'sources': ['passive'], 'evidence': []}],
                     'discovered': ['app.example.com'], 'targets': ['*.example.com'],
                 }), \
                 patch('passive_dns_enrichment.passive_dns_enrichment', return_value={'assets': [], 'targets': []}), \
                 patch.object(worker, '_probe_live_web_assets', return_value={
                     'assets': [{'domain': 'app.example.com', 'sources': ['http-probe'], 'evidence': []}]}), \
                 patch.object(worker, '_enumerate_live_services', return_value={
                     'assets': [{'domain': 'app.example.com', 'kind': 'static-site', 'ports': [443]}]}), \
                 patch.object(worker, '_run_vhost_discovery', return_value={'assets': [], 'discovered': [], 'candidates': 0}), \
                 patch.object(worker, '_directory_enumeration', return_value={'assets': [], 'discovered': []}), \
                 patch.object(worker, '_application_security_tests', return_value={'assets': [], 'discovered': []}), \
                 patch.object(worker, '_api_endpoint_tests', return_value={'assets': [], 'discovered': []}), \
                 patch.object(worker, '_port_scan_tests', return_value={'assets': [], 'discovered': []}), \
                 patch('sys.argv', ['worker.py', '--program', 'demo', '--allow-active']), redirect_stdout(io.StringIO()):
                worker.main()
            results = sorted((root / 'results').glob('*.json'))
            self.assertEqual(len(results), 9)
            self.assertTrue(all(path.stem.startswith('demo-') for path in results))
            service = json.loads((root / 'results/demo-service-enumeration.json').read_text(encoding='utf-8'))
            self.assertEqual(service['targets'], ['app.example.com'])
            self.assertEqual(service['depends_on'], ['demo-confirm-live-web-assets'])

    def test_active_approval_is_required_and_invalidated_by_rule_changes(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('demo', ['*.example.com'], root=root, guidelines='Read-only testing permitted.')
            self.assertFalse(active_approved('demo', root=root))
            _, digest = read_guidelines('demo', root=root)
            set_active_approval('demo', True, digest, root=root)
            self.assertTrue(active_approved('demo', root=root))
            (root / 'programs/demo/rules.md').write_text('No active testing permitted.\n', encoding='utf-8')
            self.assertFalse(active_approved('demo', root=root))
            with self.assertRaises(ValueError):
                set_active_approval('demo', True, digest, root=root)
            with patch.object(worker, 'ROOT', root), patch.object(worker, 'RESULTS_DIR', root / 'results'), \
                 patch.object(worker, 'RUNNING_DIR', root / 'results' / '.running'), \
                 patch.object(worker, 'JOBS_DIR', root / 'jobs'), \
                 patch('passive_discovery.build_job_output', return_value={'assets': [], 'targets': []}), \
                 patch('passive_dns_enrichment.passive_dns_enrichment', return_value={'assets': [], 'targets': []}), \
                 patch.object(worker, '_probe_live_web_assets') as probe, \
                 patch('sys.argv', ['worker.py', '--program', 'demo', '--allow-active', '--force']), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                worker.main()
            probe.assert_not_called()
            self.assertFalse((root / 'results/demo-confirm-live-web-assets.json').exists())

    def test_manual_scope_approval_queues_below_existing_program_and_starts_one_step(self):
        with TemporaryDirectory() as directory, \
             patch('dashboard_app.ROOT', Path(directory)), \
             patch('dashboard_app.JOBS_DIR', Path(directory) / 'jobs'), \
             patch('dashboard_app.RESULTS_DIR', Path(directory) / 'results'), \
             patch('dashboard_app.RUNNING_DIR', Path(directory) / 'results' / '.running'), \
             patch('dashboard_app.subprocess.Popen') as launch, \
             patch.dict('dashboard_app.os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token', 'BUGBOUNTY_ALLOW_ACTIVE': '1'}):
            root = Path(directory)
            launch.return_value.pid = 9876
            create_program('zz-existing', ['*.existing.example'], root=root, guidelines='Authorized testing.')
            create_manual_program('aa-manual', 'identifier,asset_type,in_scope\napp.example.com,URL,true\n',
                                  'Maximum 3 requests per second.', {'eligible_asset_types': {'URL': 1}}, root=root)
            _, digest = read_guidelines('aa-manual', root=root)
            headers = {'X-BugBounty-Token': 'test-token'}
            with app.test_client() as client:
                approval = client.post('/programs/aa-manual/active-approval', headers=headers,
                                       json={'approved': True, 'acknowledged': True, 'guidelines_sha256': digest})
                self.assertEqual(approval.status_code, 200)
                self.assertEqual(len(approval.get_json()['manual_jobs']), 9)
                self.assertFalse(approval.get_json()['active_run_started'])
                launch.assert_not_called()
                self.assertFalse((root / 'jobs/generated/aa-manual-passive-web-discovery.yaml').exists())
                page = client.get('/')
                self.assertEqual(page.status_code, 200)
                self.assertNotIn(b'<h2>Manual scope review</h2>', page.data)
                self.assertNotIn(b'class="manual-analysis" data-program="aa-manual"', page.data)
                self.assertNotIn(b'approve-manual-checks', page.data)
                self.assertIn(b'cursor: not-allowed', page.data)
                self.assertIn(b'approved: desiredApproval', page.data)
                self.assertLess(page.data.index(b'data-state-key="program-zz-existing"'),
                                page.data.index(b'data-state-key="program-aa-manual"'))
                self.assertEqual(page.data.count(b'Start step manually'), 9)
                self.assertIn(b'TCP port scanning requires explicit permission', page.data)
                blocked = client.post('/jobs/aa-manual-passive-dns-discovery/rerun', headers=headers)
                self.assertEqual(blocked.status_code, 409)
                self.assertIn('Complete passive-web-discovery', blocked.get_json()['message'])
                launch.assert_not_called()
                started = client.post('/jobs/aa-manual-passive-web-discovery/rerun', headers=headers)
                self.assertEqual(started.status_code, 202)
                command = launch.call_args.args[0]
                self.assertEqual(command[1:], [str(root / 'automation/manual_workflow.py'), 'aa-manual', 'passive-web-discovery'])
                launch.reset_mock()
                with patch('dashboard_app._lock_is_active', return_value=True):
                    self.assertEqual(client.post('/jobs/aa-manual-passive-web-discovery/rerun', headers=headers).status_code, 409)
                    self.assertEqual(client.post('/programs/aa-manual/url-check', headers=headers).status_code, 409)
                launch.assert_not_called()
                client.post('/programs/aa-manual/active-approval', headers=headers,
                            json={'approved': False, 'acknowledged': True, 'guidelines_sha256': digest})
                self.assertIn(b'class="manual-analysis" data-program="aa-manual"', client.get('/').data)
                self.assertEqual(client.post('/jobs/aa-manual-passive-web-discovery/rerun', headers=headers).status_code, 409)
                launch.assert_not_called()

    def test_upload_auto_run_acknowledges_guidelines_and_starts_scoped_worker(self):
        with TemporaryDirectory() as directory, \
             patch('dashboard_app.ROOT', Path(directory)), \
             patch('dashboard_app.JOBS_DIR', Path(directory) / 'jobs'), \
             patch('dashboard_app.RESULTS_DIR', Path(directory) / 'results'), \
             patch('dashboard_app.subprocess.Popen') as launch, \
             patch.dict('dashboard_app.os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token', 'BUGBOUNTY_ALLOW_ACTIVE': '0'}):
            root = Path(directory)
            with app.test_client() as client:
                response = client.post('/programs/upload', headers={'X-BugBounty-Token': 'test-token'}, data={
                    'program_name': 'Third Bounty', 'auto_run': 'true',
                    'scope_file': (io.BytesIO(b'identifier,asset_type,in_scope\n*.example.com,WILDCARD,true\n'), 'scope.csv'),
                    'guidelines_text': 'Automated testing permitted. Port scanning is prohibited.',
                })
                self.assertEqual(response.status_code, 202)
                self.assertEqual(response.get_json()['status'], 'auto_running')
                self.assertEqual(len(response.get_json()['jobs']), 9)
                self.assertEqual(response.get_json()['requests_per_second'], 1)
                self.assertIn('port-scan', response.get_json()['blocked_stages'])
                self.assertTrue(active_approved('third-bounty', root=root))
                self.assertTrue((root / 'programs/third-bounty/.auto-run.json').exists())
                self.assertEqual(launch.call_args.args[0][-3:], ['--program', 'third-bounty', '--auto-run'])
                launch.assert_called_once()

                launch.reset_mock()
                (root / 'programs/third-bounty/rules.md').write_text('Automation allowed. Maximum 0.5 requests per second.')
                _, new_digest = read_guidelines('third-bounty', root=root)
                response = client.post('/programs/third-bounty/active-approval', headers={'X-BugBounty-Token': 'test-token'},
                                       json={'approved': True, 'acknowledged': True, 'guidelines_sha256': new_digest})
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.get_json()['active_run_started'])
                self.assertIn('--auto-run', launch.call_args.args[0])
                profile = json.loads((root / 'programs/third-bounty/.auto-run.json').read_text())
                self.assertEqual(profile['requests_per_second'], 0.5)
                launch.reset_mock()
                with patch('dashboard_app._lock_is_active', return_value=True):
                    response = client.post('/programs/third-bounty/active-approval', headers={'X-BugBounty-Token': 'test-token'},
                                           json={'approved': True, 'acknowledged': True, 'guidelines_sha256': new_digest})
                self.assertFalse(response.get_json()['active_run_started'])
                launch.assert_not_called()
                with patch('dashboard_app._lock_is_active', return_value=True):
                    response = client.post('/jobs/third-bounty-application-testing/rerun', headers={'X-BugBounty-Token': 'test-token'})
                self.assertEqual(response.status_code, 409)
                launch.assert_not_called()

    def test_auto_run_revocation_preserves_partial_results_and_stops_next_stage(self):
        from auto_run import run_auto_pipeline
        from program_builder import configure_auto_run
        with TemporaryDirectory() as directory:
            root = Path(directory)
            create_program('automatic', ['*.example.com'], root=root, guidelines='Automated testing allowed.')
            _, digest = read_guidelines('automatic', root=root)
            set_active_approval('automatic', True, digest, root=root)
            configure_auto_run('automatic', root=root)

            def revoke(job, scope, **kwargs):
                kwargs['progress']({'assets': [{'domain': 'app.example.com', 'evidence': ['partial observation']}], 'discovered': []})
                set_active_approval('automatic', False, digest, root=root)
                return {'status': 'ok', 'assets': []}

            with patch.object(worker, 'ROOT', root), patch.object(worker, 'RESULTS_DIR', root / 'results'), \
                 patch.object(worker, 'RUNNING_DIR', root / 'results/.running'), \
                 patch.object(worker, 'run_passive_job', side_effect=revoke) as run:
                results = run_auto_pipeline('automatic', root=root)
            run.assert_called_once()
            self.assertEqual(results[0]['job_state'], 'stopped')
            self.assertEqual(results[0]['assets'][0]['evidence'], ['partial observation'])
            self.assertFalse((root / 'results/.running/auto-program-automatic.lock').exists())

    def test_auto_run_upload_rejects_bans_or_manual_scope_without_creating_program(self):
        with TemporaryDirectory() as directory, patch('dashboard_app.ROOT', Path(directory)), \
             patch('dashboard_app.subprocess.Popen') as launch, \
             patch.dict('dashboard_app.os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token'}):
            with app.test_client() as client:
                for kind, rules in [('WILDCARD', 'No automated scans.'), ('URL', 'Automation allowed.')]:
                    with self.subTest(kind=kind):
                        response = client.post('/programs/upload', headers={'X-BugBounty-Token': 'test-token'}, data={
                            'program_name': 'Rejected', 'auto_run': 'true',
                            'scope_file': (io.BytesIO(f'identifier,asset_type,in_scope\napp.example.com,{kind},true\n'.encode()), 'scope.csv'),
                            'guidelines_text': rules,
                        })
                        self.assertEqual(response.status_code, 400)
                        self.assertFalse((Path(directory) / 'programs/rejected').exists())
                launch.assert_not_called()

    def test_manual_review_keeps_pending_programs_and_incomplete_workflows(self):
        from manual_workflow import queue_manual_workflow
        with TemporaryDirectory() as directory, \
             patch('dashboard_app.ROOT', Path(directory)), \
             patch('dashboard_app.JOBS_DIR', Path(directory) / 'jobs'), \
             patch('dashboard_app.RESULTS_DIR', Path(directory) / 'results'), \
             patch('dashboard_app.RUNNING_DIR', Path(directory) / 'results/.running'):
            root = Path(directory)
            for slug in ('ready', 'pending'):
                create_manual_program(slug, 'identifier,asset_type,in_scope\napp.example.com,URL,true\n',
                                      'Maximum 3 requests per second.', {'eligible_asset_types': {'URL': 1}}, root=root)
            _, digest = read_guidelines('ready', root=root)
            set_active_approval('ready', True, digest, root=root)
            queue_manual_workflow('ready', root=root)
            with app.test_client() as client:
                page = client.get('/')
                self.assertEqual(page.status_code, 200)
                self.assertNotIn(b'class="manual-analysis" data-program="ready"', page.data)
                self.assertIn(b'class="manual-analysis" data-program="pending"', page.data)
                self.assertIn(b'data-state-key="program-ready"', page.data)
                (root / 'results/ready-port-scan.json').unlink()
                incomplete = client.get('/')
                self.assertIn(b'class="manual-analysis" data-program="ready"', incomplete.data)

    def test_manual_url_check_endpoint_requires_current_approval(self):
        with TemporaryDirectory() as directory, \
             patch('dashboard_app.ROOT', Path(directory)), \
             patch('dashboard_app.RESULTS_DIR', Path(directory) / 'results'), \
             patch('dashboard_app.RUNNING_DIR', Path(directory) / 'results' / '.running'), \
             patch('dashboard_app.subprocess.Popen') as launch, \
             patch.dict('dashboard_app.os.environ', {'BUGBOUNTY_DASHBOARD_TOKEN': 'test-token'}):
            root = Path(directory)
            launch.return_value.pid = 9876
            csv_text = 'identifier,asset_type,in_scope\nportal.example.com,URL,true\n'
            inventory = {'eligible_asset_types': {'URL': 1}, 'total_rows': 1, 'manual_only': True,
                         'display_name': 'Example'}
            create_manual_program('example', csv_text, 'Maximum 3 requests per second.', inventory, root=root)
            headers = {'X-BugBounty-Token': 'test-token'}
            with app.test_client() as client:
                self.assertEqual(client.post('/programs/example/url-check').status_code, 401)
                blocked = client.post('/programs/example/url-check', headers=headers)
                self.assertEqual(blocked.status_code, 409)
                _, digest = read_guidelines('example', root=root)
                set_active_approval('example', True, digest, root=root)
                started = client.post('/programs/example/url-check', headers=headers)
                self.assertEqual(started.status_code, 202)
                command = launch.call_args.args[0]
                self.assertEqual(command[1], str(root / 'automation/manual_url_checker.py'))
                self.assertEqual(command[2], 'example')


if __name__ == '__main__':
    unittest.main()