from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit

from manual_url_checker import ApprovedScopeClient
from program_builder import ROOT, active_approved, load_manual_analysis, read_guidelines
from stages import STAGES, STAGE_BY_ID, job_name_for
import worker


def _save(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    temporary.replace(path)


def queue_manual_workflow(slug: str, *, root: Path = ROOT) -> list[str]:
    if not active_approved(slug, root=root):
        raise PermissionError('Review and approve the current manual workflow guidelines first')
    analysis = load_manual_analysis(slug, root=root)
    _, digest = read_guidelines(slug, root=root)
    targets = sorted({asset['host'] for asset in analysis['assets'] if not asset['query_present']})
    names = []
    for stage in STAGES:
        name = job_name_for(slug, stage['stage'])
        names.append(name)
        path = root / 'results' / f'{name}.json'
        if not path.exists():
            _save(path, {'job': name, 'program': slug, 'stage': stage['stage'], 'type': stage['type'],
                         'manual_only': True, 'status': 'queued', 'job_state': 'queued',
                         'targets': targets, 'queued': targets, 'assets': [], 'discovered': [],
                         'source_count': 0, 'guidelines_sha256': digest})
    _save(root / 'programs' / slug / '.manual-workflow.json', {'manual_only': True, 'guidelines_sha256': digest})
    return names


def stage_block_reason(slug: str, stage_id: str, *, root: Path = ROOT) -> str | None:
    if stage_id not in STAGE_BY_ID:
        return 'Unknown manual workflow step'
    if not active_approved(slug, root=root):
        return 'Current program guidelines must be approved'
    rules, digest = read_guidelines(slug, root=root)
    try:
        workflow = json.loads((root / 'programs' / slug / '.manual-workflow.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return 'Approve the manual workflow before starting a step'
    if workflow.get('guidelines_sha256') != digest:
        return 'Guidelines changed; approve the current manual workflow again'
    analysis = load_manual_analysis(slug, root=root)
    if stage_id != 'passive-web-discovery' and analysis['policy']['automated_requests'] != 'manual_approval_required':
        return analysis['policy']['reason']
    bans = {
        'vhost-discovery': r'(?:no|do not|must not)[^.!?\n]{0,40}(?:vhost|virtual.host)',
        'directory-enumeration': r'(?:no|do not|must not)[^.!?\n]{0,40}(?:directory|brute.force|fuzz)',
        'application-testing': r'(?:no|do not|must not)[^.!?\n]{0,40}(?:automated vulnerability|application testing)',
        'api-testing': r'(?:no|do not|must not)[^.!?\n]{0,40}(?:api testing|introspection)',
        'port-scan': r'(?:no|do not|must not)[^.!?\n]{0,40}(?:port.scan|network.scan)',
    }
    if stage_id in bans and re.search(bans[stage_id], rules, re.IGNORECASE):
        return 'The program guidelines prohibit this step'
    if stage_id == 'port-scan':
        if not re.search(r'(?:allow|permit)[^.!?\n]{0,40}port.scan|port.scann?[^.!?\n]{0,20}(?:allow|permit)', rules, re.IGNORECASE):
            return 'TCP port scanning requires explicit permission in the program guidelines'
        if not any(asset['scope_kind'] == 'exact_host' for asset in analysis['assets']):
            return 'URL-only scope does not authorize TCP port scanning'
    for dependency in STAGE_BY_ID[stage_id]['depends_on']:
        path = root / 'results' / f'{job_name_for(slug, dependency)}.json'
        try:
            result = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return f'Complete {dependency} first'
        if result.get('job_state') != 'completed' or result.get('guidelines_sha256') != digest:
            return f'Complete {dependency} under the current guidelines first'
    return None


def _asset_url(asset: dict) -> str:
    port = f":{asset['port']}" if asset['port'] else ''
    return f"{asset['scheme'] or 'https'}://{asset['host']}{port}{asset['path']}"


def run_manual_stage(slug: str, stage_id: str, *, root: Path = ROOT, client=None) -> dict:
    reason = stage_block_reason(slug, stage_id, root=root)
    if reason:
        raise PermissionError(reason)
    analysis = load_manual_analysis(slug, root=root)
    _, digest = read_guidelines(slug, root=root)
    scope_assets = [asset for asset in analysis['assets'] if not asset['query_present']]
    if stage_id not in {'passive-web-discovery', 'passive-dns-discovery', 'confirm-live-web-assets'}:
        live_path = root / 'results' / f'{job_name_for(slug, "confirm-live-web-assets")}.json'
        live_hosts = set(json.loads(live_path.read_text(encoding='utf-8')).get('discovered', []))
        scope_assets = [asset for asset in scope_assets if asset['host'] in live_hosts]
    hosts = sorted({asset['host'] for asset in scope_assets})
    stage = STAGE_BY_ID[stage_id]
    name = job_name_for(slug, stage_id)
    output = root / 'results' / f'{name}.json'
    result = {'job': name, 'program': slug, 'stage': stage_id, 'type': stage['type'], 'manual_only': True,
              'targets': hosts, 'queued': hosts, 'discovered': [], 'assets': [], 'source_count': 0,
              'status': 'running', 'job_state': 'running', 'guidelines_sha256': digest, 'requests_per_second': 1}
    _save(output, result)

    def progress(snapshot):
        result.update(snapshot)
        _save(output, result)

    def fetch(url, *, extra_headers=None, method='GET', data=None, **kwargs):
        if method not in {'GET', 'HEAD'} or data is not None:
            raise URLError('Manual workflow permits GET and HEAD only')
        parsed = urlsplit(url)
        if not client.allows(url) and (parsed.path or '/') == '/':
            exact = next((asset for asset in scope_assets if asset['host'] == parsed.hostname), None)
            if exact:
                url = _asset_url(exact)
        response = client.request(url, method=method, headers=extra_headers, read_body=method == 'GET')
        if response.get('error') or response.get('redirect_stop') or response['status'] is None or response['status'] >= 400:
            raise URLError(response.get('error') or response.get('redirect_stop') or 'No response')
        headers = dict(response['headers'])
        headers['x-final-url'] = response['final_url']
        return response['status'], headers, response['body']

    try:
        if stage_id == 'passive-web-discovery':
            result['assets'] = [{'domain': host, 'status': 'in_scope', 'source': 'uploaded exact scope', 'findings': []} for host in hosts]
            result['discovered'] = hosts
        else:
            client = client or ApprovedScopeClient(slug, root=root)
            if stage_id == 'passive-dns-discovery':
                for host in hosts:
                    client.wait()
                    result['assets'].append({'domain': host, 'ips': sorted(worker._resolve_host_ips(host)),
                                             'source': 'exact-host DNS', 'findings': []})
                    progress({'assets': result['assets']})
                result['discovered'] = hosts
            elif stage_id in {'confirm-live-web-assets', 'service-enumeration', 'vhost-discovery'}:
                if stage_id == 'vhost-discovery':
                    dns_path = root / 'results' / f'{job_name_for(slug, "passive-dns-discovery")}.json'
                    dns_assets = json.loads(dns_path.read_text(encoding='utf-8')).get('assets', [])
                    by_address = {}
                    for record in dns_assets:
                        if record['domain'] in hosts:
                            for address in record.get('ips', []):
                                by_address.setdefault(address, set()).add(record['domain'])
                    shared = {host for group in by_address.values() if len(group) > 1 for host in group}
                    scope_assets = [asset for asset in scope_assets if asset['host'] in shared]
                    result['shared_infrastructure'] = {address: sorted(group) for address, group in by_address.items() if len(group) > 1}
                for asset in scope_assets:
                    response = client.request(_asset_url(asset))
                    record = {'domain': asset['host'], 'status': 'live' if response['status'] and response['status'] < 400 and not response.get('redirect_stop') else 'no_response',
                              'kind': asset['category'], 'ports': [asset['port'] or (80 if asset['scheme'] == 'http' else 443)],
                              'source': 'exact-scope HEAD', 'sources': ['exact-scope HEAD'], 'findings': [],
                              'evidence': [{'url': _asset_url(asset), 'status': response['status'],
                                            'server': response['headers'].get('server', ''), 'redirect_stop': response.get('redirect_stop')}],
                              'source_count': 1}
                    result['assets'].append(record)
                    result['discovered'] = sorted({item['domain'] for item in result['assets'] if item['status'] == 'live'})
                    progress({'assets': result['assets'], 'discovered': result['discovered']})
                if stage_id == 'vhost-discovery':
                    result['note'] = 'Only uploaded hostnames are checked; no IP-targeted or fabricated Host-header probes'
            elif stage_id == 'directory-enumeration':
                for asset in scope_assets:
                    paths = worker.DEFAULT_CONTENT_WORDLIST if asset['scope_kind'] == 'exact_host' else [asset['path']]
                    found = []
                    for path in paths:
                        target = _asset_url({**asset, 'path': path})
                        response = client.request(target)
                        if response['status'] in {200, 401, 403} and not response.get('redirect_stop'):
                            found.append({'path': path, 'url': target, 'status_code': response['status']})
                    result['assets'].append({'domain': asset['host'], 'paths': found, 'findings': [], 'source': 'bounded exact-scope directory check'})
                    progress({'assets': result['assets']})
                result['discovered'] = sorted({item['domain'] for item in result['assets'] if item['paths']})
            elif stage_id == 'application-testing':
                result.update(worker._application_security_tests(hosts, fetch=fetch, write_reports=False, workers=1, progress=progress))
                for record in result['assets']:
                    exact = next((asset for asset in scope_assets if asset['host'] == record['domain']), None)
                    if exact:
                        for finding in record.get('findings', []):
                            finding.setdefault('path', exact['path'])
                        for evidence in record.get('evidence', []):
                            evidence['url'] = _asset_url(exact)
            elif stage_id == 'api-testing':
                result.update(worker._api_endpoint_tests(hosts, fetch=fetch, workers=1, progress=progress))
            elif stage_id == 'port-scan':
                exact_hosts = sorted({asset['host'] for asset in scope_assets if asset['scope_kind'] == 'exact_host'})
                for host in exact_hosts:
                    findings = []
                    for address in sorted(worker._resolve_host_ips(host)):
                        for port, (service, severity) in sorted(worker._UNEXPECTED_PORTS.items()):
                            client.wait()
                            if worker._tcp_port_open(address, port):
                                findings.append({'type': 'open_port', 'ip': address, 'port': port, 'service': service, 'severity': severity})
                    result['assets'].append({'domain': host, 'findings': findings, 'source': 'explicitly permitted paced TCP checks'})
                    progress({'assets': result['assets']})
                result['discovered'] = [item['domain'] for item in result['assets'] if item['findings']]
            client.check_approval()
        _, current_digest = read_guidelines(slug, root=root)
        if current_digest != digest or not active_approved(slug, root=root):
            raise PermissionError('Approval revoked or guidelines changed')
        result['source_count'] = sum(len(item.get('findings', [])) for item in result['assets'])
        result['status'] = 'ok'
        result['job_state'] = 'completed'
    except Exception as exc:
        result['status'] = 'stopped'
        result['job_state'] = 'stopped'
        result['error'] = str(exc)
    _save(output, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description='Run one approved manual-scope step')
    parser.add_argument('program')
    parser.add_argument('stage', choices=STAGE_BY_ID)
    args = parser.parse_args()
    reason = stage_block_reason(args.program, args.stage)
    if reason:
        raise SystemExit(reason)
    lock = ROOT / 'results' / '.running' / f'manual-program-{args.program}.lock'
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise SystemExit('Another manual check for this program is running')
    with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
        handle.write(str(os.getpid()))
    try:
        run_manual_stage(args.program, args.stage)
    finally:
        lock.unlink(missing_ok=True)


if __name__ == '__main__':
    main()