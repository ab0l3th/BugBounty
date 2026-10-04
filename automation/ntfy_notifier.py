from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import stat
import time
from urllib import request
from urllib.parse import urlencode, urlsplit

from program_builder import ROOT, program_identity
from shopify_policy import apply_finding_eligibility


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def load_configuration(path=None) -> dict:
    path = Path(path or os.environ.get('BUGBOUNTY_NTFY_CONFIG', Path.home() / '.ssh/ntfy_sh'))
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_uid != os.getuid():
        raise ValueError('ntfy configuration must be an owner-only regular file')
    if metadata.st_size > 16384:
        raise ValueError('ntfy configuration is too large')
    config = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:]
        if '=' not in line:
            raise ValueError('Invalid ntfy configuration assignment')
        key, raw = line.split('=', 1)
        parts = shlex.split(raw, comments=True)
        if len(parts) != 1 or not re.fullmatch(r'BUGBOUNTY_[A-Z_]+', key.strip()):
            raise ValueError('Invalid ntfy configuration assignment')
        config[key.strip()] = parts[0]
    for key in ('BUGBOUNTY_NTFY_URL', 'BUGBOUNTY_NTFY_TOPIC', 'BUGBOUNTY_NTFY_TOKEN', 'BUGBOUNTY_DASHBOARD_URL'):
        if not config.get(key):
            raise ValueError('ntfy configuration is incomplete')
    parsed = urlsplit(config['BUGBOUNTY_NTFY_URL'])
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('ntfy server must be an HTTPS URL without embedded credentials')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', config['BUGBOUNTY_NTFY_TOPIC']):
        raise ValueError('Invalid ntfy topic name')
    if any(char in config['BUGBOUNTY_NTFY_TOKEN'] for char in '\r\n'):
        raise ValueError('Invalid ntfy token')
    dashboard = urlsplit(config['BUGBOUNTY_DASHBOARD_URL'])
    if dashboard.scheme not in {'http', 'https'} or not dashboard.hostname or dashboard.username or dashboard.password or dashboard.query or dashboard.fragment:
        raise ValueError('Invalid dashboard URL')
    return config


def topic_is_private(config: dict, *, open_request=None) -> bool:
    req = request.Request(config['BUGBOUNTY_NTFY_URL'].rstrip('/') + '/v1/account',
                          headers={'Authorization': 'Bearer ' + config['BUGBOUNTY_NTFY_TOKEN']})
    opener = open_request or request.build_opener(NoRedirect()).open
    try:
        with opener(req, timeout=8) as response:
            data = json.loads(response.read(65536))
        for entry in data.get('reservations', []) if isinstance(data, dict) else []:
            if isinstance(entry, dict) and entry.get('topic') == config['BUGBOUNTY_NTFY_TOPIC'] and entry.get('everyone') in {'deny-all', 'write-only'}:
                return True
    except Exception:
        pass
    return False


def finding_signals(payload: dict, *, root: Path = ROOT) -> list[dict]:
    payload = apply_finding_eligibility(payload, root)
    program = payload.get('program', '')
    job = payload.get('job', '')
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', program) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,159}', job):
        return []
    generation = program_identity(program, root=root)
    signals = []
    for asset in payload.get('assets', []) or []:
        if not isinstance(asset, dict):
            continue
        host = asset.get('domain', '')
        if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', host) or '..' in host:
            continue
        for finding in asset.get('findings', []) or []:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get('severity', '')).lower()
            kind = str(finding.get('type', ''))
            if severity not in {'high', 'critical'} or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', kind):
                continue
            identity = [generation, program, job, host, severity, kind,
                        str(finding.get('path', '')).split('?', 1)[0].split('#', 1)[0], finding.get('port'), finding.get('ip')]
            signal_id = hashlib.sha256(json.dumps(identity, sort_keys=True).encode('utf-8')).hexdigest()
            signals.append({'id': signal_id, 'program': program, 'job': job, 'host': host, 'severity': severity,
                            'kind': kind, 'confidence': 'medium' if kind in {'error_disclosure', 'graphql_introspection'} else 'low'})
    return signals


def state_database(root: Path):
    path = root / 'results' / '.notifications' / 'ntfy.sqlite3'
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    os.chmod(path, 0o600)
    connection.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    connection.execute('CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, program TEXT, payload TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, retry_at REAL NOT NULL DEFAULT 0)')
    return connection


def _saved_results(root: Path, signatures=None):
    for path in sorted((root / 'results').glob('*.json')):
        if path.name.startswith('.'):
            continue
        try:
            info = path.stat()
            version = (info.st_mtime_ns, info.st_size)
            if signatures is not None and signatures.get(str(path)) == version:
                continue
            payload = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if isinstance(payload, dict):
            yield path, payload, version


def collect_findings(root: Path, *, signatures=None) -> dict:
    signatures = signatures if signatures is not None else {}
    connection = state_database(root)
    new_count = 0
    try:
        with connection:
            baseline = connection.execute('SELECT value FROM metadata WHERE key = ?', ('initialized',)).fetchone() is None
            for path, payload, version in _saved_results(root, None if baseline else signatures):
                for signal in finding_signals(payload, root=root):
                    cursor = connection.execute('INSERT OR IGNORE INTO alerts (id, program, payload, state) VALUES (?, ?, ?, ?)',
                                                (signal['id'], signal['program'], json.dumps(signal), 'baseline' if baseline else 'pending'))
                    if not baseline:
                        new_count += cursor.rowcount
                signatures[str(path)] = version
            if baseline:
                connection.execute('INSERT INTO metadata (key, value) VALUES (?, ?)', ('initialized', '1'))
        return {'baseline': baseline, 'new_alerts': new_count}
    finally:
        connection.close()


def _publish(config: dict, payload: dict, *, open_request=None) -> int:
    req = request.Request(config['BUGBOUNTY_NTFY_URL'].rstrip('/') + '/',
                          data=json.dumps({'topic': config['BUGBOUNTY_NTFY_TOPIC'], **payload}).encode('utf-8'),
                          headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + config['BUGBOUNTY_NTFY_TOKEN']}, method='POST')
    opener = open_request or request.build_opener(NoRedirect()).open
    with opener(req, timeout=8) as response:
        code = response.getcode()
        if not 200 <= code < 300:
            raise RuntimeError('ntfy delivery was not accepted')
        response.read(1024)
        return code


def deliver_pending(root: Path, config: dict, *, open_request=None, now=None) -> dict:
    now = time.time() if now is None else now
    connection = state_database(root)
    sent = 0
    failed = 0
    try:
        programs = connection.execute('SELECT DISTINCT program FROM alerts WHERE state = ? AND retry_at <= ?', ('pending', now)).fetchall()
        for (program,) in programs[:10]:
            cooldown = connection.execute('SELECT value FROM metadata WHERE key = ?', ('sent_at:' + program,)).fetchone()
            if cooldown and now - float(cooldown[0]) < 60:
                continue
            rows = connection.execute('SELECT id, payload, attempts FROM alerts WHERE state = ? AND program = ? AND retry_at <= ? ORDER BY id LIMIT 20', ('pending', program, now)).fetchall()
            signals = [json.loads(row[1]) for row in rows]
            if not signals:
                continue
            critical = any(signal['severity'] == 'critical' for signal in signals)
            lines = ['Unverified scanner signals; manual verification required.']
            for signal in signals[:5]:
                lines.append(f"{signal['severity'].upper()} | {signal['host']} | {signal['kind']} | confidence {signal['confidence']} | {signal['job']}")
            if len(signals) > 5:
                lines.append(f'{len(signals) - 5} additional signals in this batch.')
            link = config['BUGBOUNTY_DASHBOARD_URL'].rstrip('/') + '/review?' + urlencode({'program': program, 'minimum': 'medium'})
            payload = {'title': f"{'CRITICAL' if critical else 'HIGH'} scanner signals: {program} ({len(signals)})",
                       'message': '\n'.join(lines), 'priority': 5 if critical else 4, 'tags': ['warning'], 'click': link}
            if not config.get('_private_topic', False):
                payload = {'title': f"{'CRITICAL' if critical else 'HIGH'} scanner signals ({len(signals)})",
                           'message': 'New unverified HIGH/CRITICAL scanner signals need manual verification. Open your private dashboard to review. Bounty details are withheld because topic privacy is not verified.',
                           'priority': 5 if critical else 4, 'tags': ['warning']}
            try:
                _publish(config, payload, open_request=open_request)
            except Exception:
                with connection:
                    for identity, _, attempts in rows:
                        delay = min(3600, 30 * (2 ** min(attempts, 7)))
                        connection.execute('UPDATE alerts SET attempts = attempts + 1, retry_at = ? WHERE id = ?', (now + delay, identity))
                failed += 1
                continue
            with connection:
                connection.executemany('UPDATE alerts SET state = ? WHERE id = ?', [('sent', row[0]) for row in rows])
                connection.execute('INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)', ('sent_at:' + program, str(now)))
            sent += len(rows)
        return {'sent': sent, 'failed_batches': failed}
    finally:
        connection.close()


def send_test(config: dict, *, open_request=None) -> int:
    return _publish(config, {'title': 'BugBounty ntfy connection test', 'message': 'Test only: HIGH/CRITICAL scanner alerts are configured. Findings will still require manual verification.',
                             'priority': 3, 'tags': ['white_check_mark']}, open_request=open_request)


def main():
    parser = argparse.ArgumentParser(description='Deliver deduplicated HIGH/CRITICAL finding notifications')
    parser.add_argument('--config', default=None)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--test', action='store_true')
    args = parser.parse_args()
    config = load_configuration(args.config)
    if args.test:
        print(json.dumps({'test_notification_status': send_test(config)}))
        return
    signatures = {}
    privacy_checked = 0
    previous_configuration = None
    private_topic = False
    while True:
        try:
            config = load_configuration(args.config)
            current_configuration = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
            if current_configuration != previous_configuration or time.monotonic() - privacy_checked >= 300:
                private_topic = topic_is_private(config)
                privacy_checked = time.monotonic()
                previous_configuration = current_configuration
            config['_private_topic'] = private_topic
            collected = collect_findings(ROOT, signatures=signatures)
            delivered = deliver_pending(ROOT, config)
            if collected['baseline'] or collected['new_alerts'] or delivered['sent'] or delivered['failed_batches']:
                print(json.dumps({**collected, **delivered, 'detailed_alerts': private_topic}), flush=True)
        except Exception as exc:
            print(json.dumps({'notifier_error_type': type(exc).__name__}), flush=True)
        if args.once:
            return
        time.sleep(10)


if __name__ == '__main__':
    main()