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

from program_builder import active_approved, create_program, parse_scope, read_guidelines, set_active_approval
from stages import STAGES
from worker import load_job, run_passive_job, job_workflow_dependencies
import worker
from dashboard_app import app, group_jobs_by_program, job_workflow_metadata, list_jobs


class ProgramBuilderTest(unittest.TestCase):
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
                self.assertIn(b'NBA Public', client.get('/').data)
                duplicate = client.post('/programs/upload', data={
                    'program_name': 'NBA Public',
                    'scope_file': (io.BytesIO(scope), 'scope.csv'),
                    'guidelines_text': 'Only known paths permitted.',
                }, headers={'X-BugBounty-Token': 'test-token'})
                self.assertEqual(duplicate.status_code, 409)
                launch.assert_not_called()

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


if __name__ == '__main__':
    unittest.main()