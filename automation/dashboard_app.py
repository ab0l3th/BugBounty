#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, render_template_string, request

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / 'results'
RUNNING_DIR = RESULTS_DIR / '.running'
JOBS_DIR = ROOT / 'jobs'

app = Flask(__name__)

# Jobs that make live connections to targets and must be launched in active mode.
ACTIVE_JOBS = {'confirm-live-web-assets', 'service-enumeration-live-hosts', 'vhost-discovery-shared-infra', 'directory-enumeration-live-hosts', 'application-security-testing', 'api-endpoint-testing'}

WORKFLOW_SEQUENCE = {
    'aa-passive-discovery': {
        'step': 1,
        'label': 'Passive Web Discovery',
        'depends_on': [],
    },
    'american-airlines-passive-dns': {
        'step': 2,
        'label': 'Passive DNS Discovery',
        'depends_on': ['aa-passive-discovery'],
    },
    'confirm-live-web-assets': {
        'step': 3,
        'label': 'Confirm Live Web Assets',
        'depends_on': ['aa-passive-discovery', 'american-airlines-passive-dns'],
    },
    'service-enumeration-live-hosts': {
        'step': 4,
        'label': 'Service Enumeration',
        'depends_on': ['confirm-live-web-assets'],
    },
    'vhost-discovery-shared-infra': {
        'step': 5,
        'label': 'Vhost Discovery',
        'depends_on': ['service-enumeration-live-hosts'],
    },
    'directory-enumeration-live-hosts': {
        'step': 6,
        'label': 'Directory Enumeration',
        'depends_on': ['service-enumeration-live-hosts', 'vhost-discovery-shared-infra'],
    },
    'application-security-testing': {
        'step': 7,
        'label': 'Application Testing',
        'depends_on': ['directory-enumeration-live-hosts'],
    },
    'api-endpoint-testing': {
        'step': 8,
        'label': 'API Testing',
        'depends_on': ['directory-enumeration-live-hosts'],
    },
}


def job_workflow_metadata(name: str) -> Dict[str, Any]:
    clean_name = (name or '').strip()
    if clean_name in WORKFLOW_SEQUENCE:
        return dict(WORKFLOW_SEQUENCE[clean_name])
    return {'step': 99, 'label': job_title_label(clean_name), 'depends_on': []}


# A lock whose PID is dead (or a legacy lock older than this) is treated as stale.
STALE_LOCK_SECONDS = 1800


def _cleanup_stale_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink()
    except OSError:
        pass


def _lock_is_active(job_name: str) -> bool:
    """A run is active only if its lock's PID is alive; orphaned locks are cleaned up."""
    if not RUNNING_DIR.exists():
        return False
    lock_path = RUNNING_DIR / f'{job_name}.lock'
    if not lock_path.exists():
        return False
    try:
        content = lock_path.read_text(encoding='utf-8').strip()
    except OSError:
        return False
    try:
        pid = int(content)
    except ValueError:
        pid = None
    if pid and pid > 0:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            _cleanup_stale_lock(lock_path)
            return False
        except PermissionError:
            return True
        except OSError:
            return False
    # Legacy timestamp-based lock: fall back to age.
    try:
        age = time.time() - lock_path.stat().st_mtime
    except OSError:
        return False
    if age > STALE_LOCK_SECONDS:
        _cleanup_stale_lock(lock_path)
        return False
    return True


def _job_state_for(job_name: str, payload: Dict[str, Any] | None = None) -> str:
    if _lock_is_active(job_name):
        return 'running'
    if payload and payload.get('status') == 'waiting_on_dependencies':
        return 'waiting_on_dependencies'
    if payload and payload.get('job_state') == 'waiting_on_dependencies':
        return 'waiting_on_dependencies'
    if payload and payload.get('status') == 'queued':
        return 'queued'
    if payload and payload.get('job_state') == 'queued':
        return 'queued'
    if payload and payload.get('job_state') == 'completed':
        return 'completed'
    if payload and payload.get('status') in {'ok', 'no_new_assets', 'no_in_scope_targets', 'no_shared_infra', 'no_paths', 'no_activity'}:
        return 'completed'
    return 'queued'


def summarize_jobs(jobs: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {'total': len(jobs), 'queued': 0, 'running': 0, 'completed': 0, 'waiting_on_dependencies': 0}
    for job in jobs:
        state = job.get('job_state', 'queued')
        if state in summary:
            summary[state] += 1
    return summary


def program_label(value: str) -> str:
    text = (value or 'unknown').replace('_', '-').strip()
    if not text:
        return 'Unknown Program'
    lowered = text.lower()
    if lowered in {'aa', 'american-airlines'}:
        return 'American Airlines'
    if lowered in {'github', 'git-hub'}:
        return 'GitHub'
    parts = [part for part in text.split('-') if part]
    return ' '.join(part.capitalize() for part in parts) if parts else 'Unknown Program'


def job_title_label(value: str) -> str:
    text = (value or '').lower().replace('_', '-')
    if 'github' in text and 'monitor' in text:
        return 'GitHub Monitor'
    if 'confirm-live-web-assets' in text or ('live' in text and 'web' in text and 'assets' in text):
        return 'Confirm Live Web Assets'
    if 'service' in text and 'enumeration' in text:
        return 'Service Enumeration'
    if 'vhost' in text or 'virtual-host' in text:
        return 'Vhost Discovery'
    if 'directory' in text and 'enumeration' in text:
        return 'Directory Enumeration'
    if 'application' in text and ('security' in text or 'testing' in text):
        return 'Application Testing'
    if text.startswith('api-') or 'api-endpoint' in text or ('api' in text and 'testing' in text):
        return 'API Testing'
    if 'aa-passive-discovery' in text:
        return 'Passive Web Discovery'
    if 'passive-dns' in text or ('passive' in text and 'dns' in text and 'discovery' not in text):
        return 'Passive DNS Discovery'
    if 'passive' in text and 'discovery' in text:
        return 'Passive Discovery'
    if 'github' in text:
        return 'GitHub Monitor'
    if 'dns' in text:
        return 'Passive DNS Discovery'
    return value.replace('_', ' ').replace('-', ' ').title()


def merged_live_asset_targets() -> List[str]:
    merged: List[str] = []
    seen: set[str] = set()
    for result_name in ('aa-passive-discovery', 'american-airlines-passive-dns'):
        path = RESULTS_DIR / f'{result_name}.json'
        if not path.exists():
            continue
        payload = read_result_file(path)
        if not payload:
            continue
        for item in (payload.get('discovered', []) or []) + (payload.get('targets', []) or []):
            if item and item not in seen:
                seen.add(item)
                merged.append(item)
    return merged


def live_web_asset_targets_from_step3() -> List[str]:
    """Only the hosts Step 3 confirmed live, not the full candidate pool it was fed."""
    path = RESULTS_DIR / 'confirm-live-web-assets.json'
    if not path.exists():
        return []
    payload = read_result_file(path)
    if not payload:
        return []
    live = list(payload.get('discovered', []) or [])
    if not live:
        live = [a.get('domain') for a in (payload.get('assets', []) or []) if isinstance(a, dict) and a.get('domain')]
    merged: List[str] = []
    seen: set[str] = set()
    for item in live:
        if item and item not in seen:
            seen.add(item)
            merged.append(item)
    return merged


def vhost_targets_from_step4() -> List[str]:
    """Hosts that Step 4 enumerated as live services, used as the pool to evaluate for shared infra."""
    path = RESULTS_DIR / 'service-enumeration-live-hosts.json'
    if not path.exists():
        return []
    payload = read_result_file(path)
    if not payload:
        return []
    hosts = list(payload.get('discovered', []) or [])
    if not hosts:
        hosts = [a.get('domain') for a in (payload.get('assets', []) or []) if isinstance(a, dict) and a.get('domain')]
    merged: List[str] = []
    seen: set[str] = set()
    for item in hosts:
        if item and item not in seen:
            seen.add(item)
            merged.append(item)
    return merged


def combined_live_roots_from_step4_and_step5() -> List[str]:
    """Union of Step 4 service-enum live hosts and Step 5 confirmed vhosts, order-preserving."""
    merged: List[str] = []
    seen: set[str] = set()
    for result_name in ('service-enumeration-live-hosts', 'vhost-discovery-shared-infra'):
        path = RESULTS_DIR / f'{result_name}.json'
        if not path.exists():
            continue
        payload = read_result_file(path)
        if not payload:
            continue
        hosts = list(payload.get('discovered', []) or [])
        if not hosts:
            hosts = [a.get('domain') for a in (payload.get('assets', []) or []) if isinstance(a, dict) and a.get('domain')]
        for item in hosts:
            if item and item not in seen:
                seen.add(item)
                merged.append(item)
    return merged


_API_PATH_HINTS = ('/api', '/swagger', '/graphql', '/openapi', '/v2/api-docs', '/v3/api-docs', '/actuator')


def api_candidate_hosts_from_step4_and_step6() -> List[str]:
    """API hosts: Step 4 api-gateway classifications plus Step 6 hosts exposing API-ish paths."""
    candidates: List[str] = []
    seen: set[str] = set()
    step4 = read_result_file(RESULTS_DIR / 'service-enumeration-live-hosts.json')
    for asset in (step4.get('assets', []) or []):
        if isinstance(asset, dict) and asset.get('kind') == 'api-gateway' and asset.get('domain'):
            host = asset['domain']
            if host not in seen:
                seen.add(host)
                candidates.append(host)
    step6 = read_result_file(RESULTS_DIR / 'directory-enumeration-live-hosts.json')
    for asset in (step6.get('assets', []) or []):
        if not isinstance(asset, dict) or not asset.get('domain'):
            continue
        paths = [p.get('path', '') for p in (asset.get('paths', []) or []) if isinstance(p, dict)]
        if any(any(path.startswith(hint) for hint in _API_PATH_HINTS) for path in paths):
            host = asset['domain']
            if host not in seen:
                seen.add(host)
                candidates.append(host)
    return candidates


def group_jobs_by_program(jobs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for job in jobs:
        program = job.get('program', 'unknown')
        name = (job.get('name') or '')
        # Suppress GitHub monitoring jobs from the dashboard view.
        if 'github' in program.lower() or 'github' in name.lower():
            continue
        grouped.setdefault(program, []).append(job)
    return dict(sorted(grouped.items(), key=lambda item: program_label(item[0])))


def summarize_program_jobs(jobs: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {'jobs': 0, 'targets': 0, 'discovered': 0, 'passive_dns_jobs': 0, 'completed': 0, 'running': 0}
    for job in jobs:
        summary['jobs'] += 1
        summary['targets'] += len(job.get('targets', []) or [])
        summary['discovered'] += len(job.get('discovered', []) or [])
        state = (job.get('job_state') or '').lower()
        if state == 'completed':
            summary['completed'] += 1
        elif state == 'running':
            summary['running'] += 1
        if 'passive dns discovery' in job_title_label(job.get('name', '')).lower():
            summary['passive_dns_jobs'] += 1
    return summary


def read_result_file(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return {}


def read_job_definition(path: Path) -> Dict[str, Any]:
    data: Dict[str, Any] = {'name': path.stem, 'program': 'unknown', 'type': 'passive', 'targets': [], 'depends_on': [], 'order': 99}
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except Exception:
        return data
    for line in lines:
        clean = line.strip()
        if not clean or clean.startswith('#'):
            continue
        if clean.startswith('name:'):
            data['name'] = clean.split(':', 1)[1].strip()
        elif clean.startswith('program:'):
            data['program'] = clean.split(':', 1)[1].strip()
        elif clean.startswith('type:'):
            data['type'] = clean.split(':', 1)[1].strip()
        elif clean.startswith('order:'):
            try:
                data['order'] = int(clean.split(':', 1)[1].strip())
            except ValueError:
                data['order'] = 99
        elif clean.startswith('depends_on:'):
            value = clean.split(':', 1)[1].strip()
            if value:
                parsed = value.strip('[]')
                if parsed:
                    data['depends_on'] = [item.strip().strip("'\"") for item in parsed.split(',') if item.strip()]
                else:
                    data['depends_on'] = []
        elif clean.startswith('targets:'):
            continue
        elif clean.startswith('- '):
            data['targets'].append(clean[2:].strip().strip("'\""))
    if not data.get('depends_on'):
        meta = job_workflow_metadata(data['name'])
        data['depends_on'] = meta.get('depends_on', [])
    data['order'] = min(data.get('order', 99), job_workflow_metadata(data['name']).get('step', 99))
    return data


def list_jobs() -> List[Dict[str, Any]]:
    jobs: List[Dict[str, Any]] = []
    seen: set[str] = set()

    if JOBS_DIR.exists():
        for path in sorted(JOBS_DIR.glob('*.yaml')) + sorted(JOBS_DIR.glob('*.yml')):
            job_name = path.stem
            seen.add(job_name)
            definition = read_job_definition(path)
            payload = read_result_file(RESULTS_DIR / f'{job_name}.json')
            job_state = _job_state_for(job_name, payload if payload else None)
            metadata = job_workflow_metadata(definition.get('name', job_name))
            if job_name == 'confirm-live-web-assets':
                queued_targets = merged_live_asset_targets()
            elif job_name == 'service-enumeration-live-hosts':
                queued_targets = live_web_asset_targets_from_step3()
            elif job_name == 'vhost-discovery-shared-infra':
                queued_targets = vhost_targets_from_step4()
            elif job_name == 'directory-enumeration-live-hosts':
                queued_targets = combined_live_roots_from_step4_and_step5()
            elif job_name == 'application-security-testing':
                queued_targets = combined_live_roots_from_step4_and_step5()
            elif job_name == 'api-endpoint-testing':
                queued_targets = api_candidate_hosts_from_step4_and_step6()
            else:
                queued_targets = definition.get('targets', [])
            if payload:
                assets = payload.get('assets') or [
                    {'domain': host, 'status': 'in_scope', 'sources': [], 'source': ''}
                    for host in payload.get('discovered', [])
                ]
                jobs.append({
                    'name': payload.get('job', definition.get('name', job_name)),
                    'path': path.name,
                    'status': payload.get('status', 'unknown'),
                    'job_state': job_state,
                    'type': payload.get('type', definition.get('type', 'unknown')),
                    'program': payload.get('program', definition.get('program', 'unknown')),
                    'discovered': payload.get('discovered', []),
                    'assets': assets,
                    'targets': payload.get('targets', queued_targets),
                    'queued': payload.get('queued', queued_targets),
                    'skipped': payload.get('skipped', []),
                    'source_count': payload.get('source_count', 0),
                    'workflow_step': metadata.get('step', definition.get('order', 99)),
                    'depends_on': metadata.get('depends_on', definition.get('depends_on', [])),
                    'raw': payload,
                })
            else:
                jobs.append({
                    'name': definition.get('name', job_name),
                    'path': path.name,
                    'status': 'running' if job_state == 'running' else ('waiting_on_dependencies' if job_state == 'waiting_on_dependencies' else 'queued'),
                    'job_state': job_state,
                    'type': definition.get('type', 'passive'),
                    'program': definition.get('program', 'unknown'),
                    'discovered': [],
                    'assets': [],
                    'targets': queued_targets,
                    'queued': queued_targets,
                    'skipped': [],
                    'source_count': 0,
                    'workflow_step': metadata.get('step', definition.get('order', 99)),
                    'depends_on': metadata.get('depends_on', definition.get('depends_on', [])),
                    'raw': {'job': definition.get('name', job_name), 'job_state': job_state},
                })

    if not RESULTS_DIR.exists():
        return sorted(jobs, key=lambda item: item['name'])

    for path in sorted(RESULTS_DIR.glob('*.json')):
        if path.name.startswith('.') or path.stem in seen:
            continue
        payload = read_result_file(path)
        if not payload:
            continue
        assets = payload.get('assets') or [
            {'domain': host, 'status': 'in_scope', 'sources': [], 'source': ''}
            for host in payload.get('discovered', [])
        ]
        metadata = job_workflow_metadata(payload.get('job', path.stem))
        jobs.append({
            'name': payload.get('job', path.stem),
            'path': path.name,
            'status': payload.get('status', 'unknown'),
            'job_state': _job_state_for(path.stem, payload),
            'type': payload.get('type', 'unknown'),
            'program': payload.get('program', 'unknown'),
            'discovered': payload.get('discovered', []),
            'assets': assets,
            'targets': payload.get('targets', []),
            'queued': payload.get('queued', []),
            'skipped': payload.get('skipped', []),
            'source_count': payload.get('source_count', 0),
            'workflow_step': metadata.get('step', 99),
            'depends_on': metadata.get('depends_on', []),
            'raw': payload,
        })
    return sorted(jobs, key=lambda item: (item.get('workflow_step', 99), item['name']))


def verify_github_signature(payload: bytes, signature: str | None, secret: str) -> bool:
    if not secret or not signature or not signature.startswith('sha256='):
        return False
    expected = 'sha256=' + hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def _authorized_for_state_change() -> bool:
    """Require a shared-secret header for state-changing endpoints; fail closed if unset."""
    token = os.environ.get('BUGBOUNTY_DASHBOARD_TOKEN', '').strip()
    if not token:
        return False
    provided = request.headers.get('X-BugBounty-Token', '')
    return hmac.compare_digest(provided, token)


def trigger_repo_sync_on_push() -> None:
    commands = [
        ['git', 'fetch', '--all', '--prune'],
        ['git', 'reset', '--hard', 'origin/main'],
        ['git', 'clean', '-fd'],
        [sys.executable, str(ROOT / 'automation' / 'runner.py')],
    ]
    for command in commands:
        subprocess.run(command, cwd=str(ROOT), check=True)


def rerun_job(job_name: str) -> Dict[str, Any]:
    jobs = list_jobs()
    match = next((job for job in jobs if job.get('name') == job_name), None)
    if not match:
        raise KeyError(f'Unknown job: {job_name}')

    program = match.get('program', 'unknown')
    result_path = RESULTS_DIR / f'{job_name}.json'
    result_path.parent.mkdir(parents=True, exist_ok=True)
    if job_name == 'confirm-live-web-assets':
        queued_targets = merged_live_asset_targets()
    elif job_name == 'service-enumeration-live-hosts':
        queued_targets = live_web_asset_targets_from_step3()
    elif job_name == 'vhost-discovery-shared-infra':
        queued_targets = vhost_targets_from_step4()
    elif job_name == 'directory-enumeration-live-hosts':
        queued_targets = combined_live_roots_from_step4_and_step5()
    elif job_name == 'application-security-testing':
        queued_targets = combined_live_roots_from_step4_and_step5()
    elif job_name == 'api-endpoint-testing':
        queued_targets = api_candidate_hosts_from_step4_and_step6()
    else:
        queued_targets = []
    result_path.write_text(json.dumps({
        'job': job_name,
        'program': program,
        'type': 'passive',
        'targets': queued_targets,
        'queued': queued_targets,
        'skipped': [],
        'discovered': [],
        'assets': [],
        'status': 'queued',
        'job_state': 'queued',
        'source_count': 0,
        'queued_at': int(time.time()),
    }, indent=2), encoding='utf-8')

    RUNNING_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = RUNNING_DIR / f'{job_name}.lock'
    lock_path.write_text(str(int(time.time())), encoding='utf-8')

    command = [sys.executable, str(ROOT / 'automation' / 'worker.py'), '--force', '--job', job_name]
    if job_name in ACTIVE_JOBS:
        command.append('--allow-active')
    if program and program != 'unknown':
        command.extend(['--program', str(program)])

    launched = subprocess.Popen(
        command,
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    # Record the worker PID so a crash leaves a detectably-stale lock, not a permanent "running".
    lock_path.write_text(str(launched.pid), encoding='utf-8')
    return {
        'status': 'queued',
        'job': job_name,
        'program': program,
        'pid': launched.pid,
    }


@app.route('/webhook/github', methods=['POST'])
def github_webhook():
    raw = request.get_data(cache=True, as_text=False)
    signature = request.headers.get('X-Hub-Signature-256', '')
    secret = os.environ.get('BUGBOUNTY_GITHUB_WEBHOOK_SECRET', '').strip()
    if not secret:
        return jsonify({'status': 'error', 'message': 'missing webhook secret'}), 500
    if not verify_github_signature(raw, signature, secret):
        return jsonify({'status': 'error', 'message': 'invalid signature'}), 401

    event = request.headers.get('X-GitHub-Event', '')
    payload = request.get_json(silent=True) or {}
    ref = payload.get('ref', '')
    if event != 'push':
        return jsonify({'status': 'ignored', 'event': event}), 202
    if ref != 'refs/heads/main':
        return jsonify({'status': 'ignored', 'ref': ref}), 202

    try:
        trigger_repo_sync_on_push()
    except subprocess.CalledProcessError as exc:
        return jsonify({'status': 'error', 'message': 'repo sync failed', 'returncode': exc.returncode}), 500

    return jsonify({'status': 'ok', 'event': event, 'ref': ref}), 200


@app.route('/about')
def about_overview():
    return render_template_string('''
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>BugBounty Workflow Overview</title>
      <style>
        body { font-family: Arial, sans-serif; background: #111827; color: #e5e7eb; margin: 0; padding: 32px; }
        .wrap { max-width: 1100px; margin: 0 auto; }
        .topbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }
        .brand { font-size: 32px; font-weight: bold; margin: 0; }
        .nav { display: flex; gap: 10px; flex-wrap: wrap; }
        .nav a { text-decoration: none; color: #e2e8f0; background: #1f2937; border: 1px solid #334155; border-radius: 8px; padding: 8px 12px; }
        .card { background: #1f2937; border: 1px solid #374151; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 8px 20px rgba(0,0,0,0.18); }
        h1 { margin-top: 0; margin-bottom: 20px; }
        h2 { margin-top: 0; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 18px; }
        .step { background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 16px; }
        .step .num { font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; color: #93c5fd; }
        .step h3 { margin: 8px 0 10px; }
        .step p { margin: 0; color: #cbd5e1; line-height: 1.5; }
        ul { margin: 10px 0 0 20px; line-height: 1.7; color: #dbeafe; }
        code { background: #0b1120; border-radius: 4px; padding: 2px 6px; }
        a { color: #7dd3fc; }
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="topbar">
          <div class="brand">BugBounty Dashboard</div>
          <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/about">About</a>
          </div>
        </div>

        <div class="card">
          <h1>BugBounty Workflow Overview</h1>
          <p>This dashboard is a structured recon pipeline designed to move from passive discovery to live validation and then into targeted application and API testing. The workflow is intentionally evidence-based: each step narrows the scope using the output of the previous stage instead of scanning everything blindly.</p>
          <p>The goal is to find realistic, high-signal assets and manually validate them before writing a report or investing time in deep exploitation.</p>
        </div>

        <div class="card">
          <h2>How the workflow works</h2>
          <div class="grid">
            <div class="step">
              <div class="num">Step 1</div>
              <h3>Passive Web Discovery</h3>
              <p>Collect likely target domains and web surfaces from public and passive sources. This is the broadest reconnaissance stage and intentionally avoids active probing.</p>
            </div>
            <div class="step">
              <div class="num">Step 2</div>
              <h3>Passive DNS Discovery</h3>
              <p>Expand and enrich the target list through DNS and certificate intelligence to find related hosts, aliases, and subdomains that may be in scope.</p>
            </div>
            <div class="step">
              <div class="num">Step 3</div>
              <h3>Confirm Live Web Assets</h3>
              <p>Take the deduplicated output from the passive stages and verify which assets actually respond over HTTP or HTTPS. This step is what turns a candidate list into a real, reachable target set.</p>
            </div>
            <div class="step">
              <div class="num">Step 4</div>
              <h3>Service Enumeration</h3>
              <p>Inspect confirmed live hosts to fingerprint services, ports, and protocols. The purpose is to answer: what is actually listening and how is the host serving traffic?</p>
            </div>
            <div class="step">
              <div class="num">Step 5</div>
              <h3>Vhost Discovery</h3>
              <p>Look for virtual hosts, shared infrastructure, or alternate app surfaces that sit behind the same IP or proxy stack. This is useful when a single origin is hosting multiple domains or apps.</p>
            </div>
            <div class="step">
              <div class="num">Step 6</div>
              <h3>Targeted Directory Enumeration</h3>
              <p>Run narrow, evidence-driven directory discovery only for hosts that are already validated. This avoids noisy scans against everything and keeps the scope relevant.</p>
            </div>
            <div class="step">
              <div class="num">Step 7</div>
              <h3>Application Security Testing</h3>
              <p>Assess the app surface for misconfigurations, exposed admin/debug routes, stack disclosure, login issues, unsafe paths, and app-level findings that deserve manual validation.</p>
            </div>
            <div class="step">
              <div class="num">Step 8</div>
              <h3>API Endpoint Testing</h3>
              <p>Inspect live APIs for auth issues, debug endpoints, GraphQL, OpenAPI docs, and other high-value paths that can leak data or reveal vulnerabilities. This is where API-specific routes are validated.</p>
            </div>
          </div>
        </div>

        <div class="card">
          <h2>What happens in the app testing stage</h2>
          <p>The application testing pass focuses on confirmed live web apps, not raw domain lists. It checks:</p>
          <ul>
            <li>Base app pages and common admin routes</li>
            <li>Framework and version disclosure via headers or HTML</li>
            <li>Debug, management, or health endpoints</li>
            <li>Obvious misconfigurations and exposed config paths</li>
            <li>Login or access flows that reveal weak protections</li>
            <li>Server-side error patterns or verbose stack traces</li>
          </ul>
          <p>Findings are prioritized for manual validation because the stage is meant to reduce noise, not flood the queue with weak or duplicate signals.</p>
        </div>

        <div class="card">
          <h2>What happens in the API testing stage</h2>
          <p>API testing starts only after we have a clear indication that the host is serving an API or API-like surface. The workflow looks for JSON responses, Swagger/OpenAPI docs, GraphQL endpoints, and common API base paths like <code>/api</code>, <code>/graphql</code>, and <code>/v1</code>.</p>
          <p>From there, it inspects for:</p>
          <ul>
            <li>Unauthenticated or weakly authenticated debug routes</li>
            <li>Swagger and OpenAPI docs that expose internal paths</li>
            <li>GraphQL introspection or schema disclosure</li>
            <li>Actuator, metrics, and environment endpoints</li>
            <li>Sensitive JSON endpoints returning config, metadata, or user data</li>
          </ul>
          <p>Any credible item is documented with reproduction steps and evidence so it can be manually verified by the operator.</p>
        </div>

        <div class="card">
          <h2>Operating principles</h2>
          <ul>
            <li>Passive first, active second.</li>
            <li>Only test hosts that were confirmed alive.</li>
            <li>Use previous stage output to narrow the target list.</li>
            <li>Prefer high-signal checks over noisy broad scanning.</li>
            <li>Manually confirm issues before escalating them into a full finding.</li>
            <li>Capture evidence and reproduction steps in clean, readable output.</li>
          </ul>
        </div>
      </div>
    </body>
    </html>
    ''')


@app.route('/')
def index():
    jobs = list_jobs()
    summary = summarize_jobs(jobs)
    grouped_jobs = group_jobs_by_program(jobs)
    workflow_order = [job_workflow_metadata(job_name) for job_name in ['aa-passive-discovery', 'american-airlines-passive-dns', 'confirm-live-web-assets', 'service-enumeration-live-hosts', 'vhost-discovery-shared-infra', 'directory-enumeration-live-hosts', 'application-security-testing', 'api-endpoint-testing']]
    return render_template_string('''
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>BugBounty Dashboard</title>
      <style>
        body { font-family: Arial, sans-serif; background: #111827; color: #e5e7eb; margin: 0; padding: 32px; }
        h1 { margin-bottom: 24px; }
        .wrap { max-width: 1200px; margin: 0 auto; }
        .card { background: #1f2937; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 8px 20px rgba(0,0,0,0.2); }
        .summary-row { display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 16px; margin-bottom: 20px; }
        .pill { background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 16px; text-align: center; }
        .pill strong { display: block; font-size: 28px; margin-top: 8px; }
        .program-group { margin-bottom: 24px; }
        .program-header { margin: 0 0 12px; font-size: 28px; cursor: pointer; list-style: none; display: flex; align-items: center; gap: 10px; }
        .program-header::-webkit-details-marker { display: none; }
        .program-header::before { content: '\\25B6'; font-size: 15px; color: #7dd3fc; transition: transform 0.15s ease; display: inline-block; }
        details.program-group[open] > .program-header::before { transform: rotate(90deg); }
        .program-count { font-size: 16px; color: #94a3b8; font-weight: normal; }
        .program-summary-card { background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
        .program-summary-card h3 { margin: 0 0 6px; font-size: 18px; }
        .program-summary-card .meta { color: #cbd5e1; font-size: 14px; }
        .job { margin-bottom: 18px; padding: 0; background: #0f172a; border-left: 4px solid #38bdf8; border-radius: 8px; overflow: hidden; }
        summary { list-style: none; cursor: pointer; padding: 16px; display: block; }
        summary::-webkit-details-marker { display: none; }
        .job-header { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
        .job-title-wrap { flex: 1; }
        .job-name { margin: 0; font-size: 20px; }
        .job-summary { font-size: 14px; color: #cbd5e1; margin-top: 4px; }
        .job-content { padding: 0 16px 16px; }
        .status { display: inline-block; padding: 4px 8px; border-radius: 999px; font-size: 12px; font-weight: bold; }
        .ok { background: #14532d; color: #dcfce7; }
        .warn { background: #78350f; color: #fef3c7; }
        .bad { background: #7f1d1d; color: #fee2e2; }
        .rerun-form { margin-top: 8px; }
        .rerun-button { background: #0ea5e9; color: #082f49; border: none; border-radius: 6px; padding: 8px 12px; font-weight: bold; cursor: pointer; }
        ul { margin: 10px 0 0 20px; }
        code { background: #0b1120; border-radius: 4px; padding: 2px 6px; }
        a { color: #7dd3fc; }
        .evidence-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
        .evidence-item { background: #111827; border: 1px solid #334155; border-radius: 6px; padding: 6px 8px; }
        .evidence-item a { text-decoration: none; }
        .collapsible-list { margin-top: 12px; background: #111827; border: 1px solid #334155; border-radius: 8px; overflow: hidden; }
        .collapsible-list summary { list-style: none; cursor: pointer; padding: 10px 12px; font-weight: bold; color: #e2e8f0; }
        .collapsible-list summary::-webkit-details-marker { display: none; }
        .collapsible-list ul { padding: 0 12px 12px; margin: 0; max-height: 260px; overflow-y: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; vertical-align: top; padding: 8px; border-bottom: 1px solid #334155; }
        @media (max-width: 640px) {
          body { padding: 16px; }
          .summary-row { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
          .pill strong { font-size: 22px; }
          .program-header { font-size: 24px; }
          .job { padding: 0; }
          .job-header { flex-direction: column; align-items: flex-start; }
          summary { padding: 12px; }
          .job-content { padding: 0 12px 12px; }
          table, thead, tbody, th, td, tr { display: block; }
          thead { display: none; }
          tr { margin-bottom: 10px; border-bottom: 1px solid #334155; padding-bottom: 8px; }
          td { border-bottom: none; padding: 6px 0; }
        }
      </style>
    </head>
    <body>
      <div class="wrap">
        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:20px;">
          <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
            <h1 style="margin:0;">BugBounty Dashboard</h1>
            <a href="/about" style="color:#7dd3fc; text-decoration:none; background:#1f2937; border:1px solid #334155; border-radius:8px; padding:7px 10px; font-size:14px;">About</a>
          </div>
          <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; background:#1f2937; border:1px solid #334155; border-radius:10px; padding:8px 12px;">
            <label for="refresh-interval" style="font-size:14px; color:#cbd5e1;">Auto refresh</label>
            <select id="refresh-interval" style="background:#0f172a; color:#e5e7eb; border:1px solid #475569; border-radius:6px; padding:6px 8px;">
              <option value="0">Off</option>
              <option value="15">15 sec</option>
              <option value="30">30 sec</option>
              <option value="60" selected>60 sec</option>
              <option value="120">2 min</option>
              <option value="300">5 min</option>
            </select>
            <button id="refresh-now" type="button" style="background:#0ea5e9; color:#082f49; border:none; border-radius:6px; padding:8px 12px; font-weight:bold; cursor:pointer;">Refresh data</button>
            <span id="last-refreshed" style="font-size:12px; color:#cbd5e1;">Last refreshed: --:--:--</span>
          </div>
        </div>
        <div class="card" style="margin-bottom:20px;">
          <h2 style="margin-top:0; margin-bottom:12px;">Workflow order</h2>
          <div style="display:flex; flex-wrap:wrap; gap:10px;">
            {% for step in workflow_order %}
              <div style="min-width:180px; background:#0f172a; border:1px solid #334155; border-radius:10px; padding:10px 12px;">
                <div style="font-size:11px; letter-spacing:0.08em; text-transform:uppercase; color:#94a3b8;">Step {{ step.step }}</div>
                <div style="font-weight:bold; margin-top:4px;">{{ step.label }}</div>
              </div>
            {% endfor %}
          </div>
        </div>
        <div class="summary-row">
          <div class="pill">
            <div>Total jobs</div>
            <strong>{{ summary.total }}</strong>
          </div>
          <div class="pill">
            <div>Queued</div>
            <strong>{{ summary.queued }}</strong>
          </div>
          <div class="pill">
            <div>Running</div>
            <strong>{{ summary.running }}</strong>
          </div>
          <div class="pill">
            <div>Completed</div>
            <strong>{{ summary.completed }}</strong>
          </div>
        </div>
        {% if jobs %}
          {% for program_name, program_jobs in grouped_jobs.items() %}
            {% set program_summary = summarize_program_jobs(program_jobs) %}
            <details class="program-group" open>
              <summary class="program-header">{{ program_label(program_name) }} <span class="program-count">({{ program_summary.jobs }} jobs)</span></summary>
              {% if program_summary.passive_dns_jobs %}
                <div class="program-summary-card">
                  <h3>Passive DNS</h3>
                  <div class="meta">{{ program_summary.passive_dns_jobs }} jobs &nbsp; | &nbsp; Targets: {{ program_summary.targets }} &nbsp; | &nbsp; Discovered: {{ program_summary.discovered }} &nbsp; | &nbsp; {{ program_summary.completed }}/{{ program_summary.passive_dns_jobs }} complete</div>
                </div>
              {% endif %}
              {% for job in program_jobs %}
                <details class="job">
                  <summary>
                    <div class="job-header">
                      <div class="job-title-wrap">
                        <h3 class="job-name">{{ job_title_label(job.name) }}</h3>
                        <div class="job-summary"><strong>Targets:</strong> {{ job.targets|length }} &nbsp; <strong>Discovered:</strong> {{ job.discovered|length }} &nbsp; <strong>Status:</strong> {{ job.job_state }}</div>
                      </div>
                      <div class="status {{ 'ok' if job.job_state == 'completed' else 'warn' if job.job_state == 'running' else 'bad' }}">{{ job.job_state }}</div>
                    </div>
                  </summary>
                  <div class="job-content">
                    <div class="rerun-form">
                      <button class="rerun-button" type="button" onclick="rerunJob('{{ job.name }}', this)">Re-run job</button>
                    </div>
                    <p><strong>Program:</strong> {{ program_label(job.program) }}</p>
                    <p><strong>Type:</strong> {{ job.type }}</p>
                    <p><strong>Pipeline status:</strong> {{ job.status }}</p>
                    <p><strong>Source count:</strong> {{ job.source_count }}</p>
                    <p><strong>Targets:</strong> {{ job.targets|length }}</p>
                    <p><strong>Discovered:</strong> {{ job.discovered|length }}</p>

                    {% set probe_log = (job.raw.probe_log if job.raw else []) %}
                    {% set thread_status = (job.raw.thread_status if job.raw else []) %}
                    {% if probe_log or thread_status %}
                      <details class="collapsible-list">
                        <summary>Thread progress ({{ thread_status|length }})</summary>
                        <ul>
                          {% for item in thread_status %}
                            <li><code>{{ item.host }}</code> — {{ item.status }}{% if item.url %} / {{ item.url }}{% endif %}{% if item.thread_id %} [{{ item.thread_id }}]{% endif %}</li>
                          {% endfor %}
                        </ul>
                      </details>
                    {% endif %}

                    <h3>Discovered assets</h3>
                    <table style="width:100%; border-collapse: collapse; margin-top: 10px;">
                      <thead>
                        <tr>
                          <th align="left">Domain</th>
                          <th align="left">Source</th>
                          <th align="left">Service</th>
                          <th align="left">Ports</th>
                          <th align="left">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {% for asset in job.assets %}
                          <tr>
                            <td><code>{{ asset.domain }}</code></td>
                            <td>
                              {% if asset.evidence %}
                                <div class="evidence-list">
                                  {% for item in asset.evidence %}
                                    <span class="evidence-item"><a href="{{ item.url }}" target="_blank" rel="noopener">{{ item.source }}</a></span>
                                  {% endfor %}
                                </div>
                              {% else %}
                                {{ asset.source or asset.sources|join(', ') }}
                              {% endif %}
                              {% if asset.report_url %}
                                <div style="margin-top:6px;"><a href="{{ asset.report_url }}" target="_blank" rel="noopener">📄 View write-up ({{ asset.findings|length }} finding{{ 's' if asset.findings|length != 1 else '' }})</a></div>
                              {% endif %}
                            </td>
                            <td>{% if asset.kind %}<code>{{ asset.kind }}</code>{% else %}—{% endif %}</td>
                            <td>{% if asset.ports %}{{ asset.ports|join(', ') }}{% else %}—{% endif %}</td>
                            <td>{{ asset.status }}</td>
                          </tr>
                        {% else %}
                          <tr><td colspan="5">No newly discovered assets.</td></tr>
                        {% endfor %}
                      </tbody>
                    </table>

                    <details class="collapsible-list">
                      <summary>In-scope targets ({{ job.targets|length }})</summary>
                      <ul>
                        {% for item in job.targets %}
                          <li><code>{{ item }}</code></li>
                        {% endfor %}
                      </ul>
                    </details>

                    <details class="collapsible-list">
                      <summary>Queued ({{ job.queued|length }})</summary>
                      <ul>
                        {% for item in job.queued %}
                          <li><code>{{ item }}</code></li>
                        {% endfor %}
                      </ul>
                    </details>
                    {% if job.skipped %}
                      <details class="collapsible-list">
                        <summary>Skipped ({{ job.skipped|length }})</summary>
                        <ul>
                          {% for item in job.skipped %}
                            <li><code>{{ item }}</code></li>
                          {% endfor %}
                        </ul>
                      </details>
                    {% endif %}
                  </div>
                </details>
              {% endfor %}
            </details>
          {% endfor %}
        {% else %}
          <div class="card">
            <p>No result files have been generated yet.</p>
            <p>Run the worker and a result file will appear in <code>results/</code>.</p>
          </div>
        {% endif %}
      </div>
      <script>
        const TOKEN_KEY = 'bugbounty-dashboard-token';

        function getToken(forcePrompt) {
          let token = localStorage.getItem(TOKEN_KEY) || '';
          if (!token || forcePrompt) {
            token = (window.prompt('Enter dashboard token (X-BugBounty-Token):', '') || '').trim();
            if (token) {
              localStorage.setItem(TOKEN_KEY, token);
            }
          }
          return token;
        }

        async function rerunJob(jobName, button) {
          const token = getToken(false);
          if (!token) {
            return;
          }
          const original = button ? button.textContent : '';
          if (button) {
            button.disabled = true;
            button.textContent = 'Queuing…';
          }
          try {
            const resp = await fetch('/jobs/' + encodeURIComponent(jobName) + '/rerun', {
              method: 'POST',
              headers: { 'X-BugBounty-Token': token },
            });
            if (resp.status === 401) {
              localStorage.removeItem(TOKEN_KEY);
              alert('Unauthorized. Re-enter the dashboard token.');
              getToken(true);
              return;
            }
            if (!resp.ok) {
              const detail = await resp.json().catch(() => ({}));
              alert('Re-run failed: ' + (detail.message || resp.status));
              return;
            }
            window.location.reload();
          } catch (err) {
            alert('Re-run request error: ' + err);
          } finally {
            if (button) {
              button.disabled = false;
              button.textContent = original;
            }
          }
        }

        const refreshSelect = document.getElementById('refresh-interval');
        const refreshButton = document.getElementById('refresh-now');
        const lastRefreshedLabel = document.getElementById('last-refreshed');
        const savedValue = localStorage.getItem('bugbounty-refresh-interval') || '60';
        if (refreshSelect) {
          refreshSelect.value = savedValue;
        }

        function formatTime(date) {
          return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }

        function setLastRefreshed() {
          const stamp = new Date();
          localStorage.setItem('bugbounty-last-refreshed', stamp.toISOString());
          if (lastRefreshedLabel) {
            lastRefreshedLabel.textContent = 'Last refreshed: ' + formatTime(stamp);
          }
        }

        const savedRefresh = localStorage.getItem('bugbounty-last-refreshed');
        if (savedRefresh && lastRefreshedLabel) {
          lastRefreshedLabel.textContent = 'Last refreshed: ' + formatTime(new Date(savedRefresh));
        } else {
          setLastRefreshed();
        }

        let refreshTimer = null;
        function applyRefreshInterval() {
          const value = Number(refreshSelect ? refreshSelect.value : 60);
          localStorage.setItem('bugbounty-refresh-interval', String(value));
          if (refreshTimer) {
            clearInterval(refreshTimer);
            refreshTimer = null;
          }
          if (value > 0) {
            refreshTimer = setInterval(() => {
              window.location.reload();
            }, value * 1000);
          }
        }

        if (refreshSelect) {
          refreshSelect.addEventListener('change', applyRefreshInterval);
        }
        if (refreshButton) {
          refreshButton.addEventListener('click', () => {
            setLastRefreshed();
            window.location.reload();
          });
        }
        applyRefreshInterval();
      </script>
    </body>
    </html>
    ''', jobs=jobs, summary=summary, grouped_jobs=grouped_jobs, program_label=program_label, job_title_label=job_title_label, summarize_program_jobs=summarize_program_jobs, workflow_order=workflow_order)


@app.route('/jobs/<job_name>/rerun', methods=['POST'])
def rerun_job_endpoint(job_name: str):
    if not _authorized_for_state_change():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
    try:
        result = rerun_job(job_name)
    except KeyError:
        return jsonify({'status': 'error', 'message': f'Unknown job: {job_name}'}), 404
    return jsonify(result), 202


@app.route('/api/jobs')
def api_jobs():
    return jsonify(list_jobs())


@app.route('/reports/<job_name>/<host>')
def view_report(job_name: str, host: str):
    safe_job = re.sub(r'[^a-z0-9\-]', '', job_name.lower())
    safe_host = re.sub(r'[^a-z0-9.\-]', '', host.lower())
    reports_dir = (RESULTS_DIR / 'reports').resolve()
    path = (reports_dir / safe_job / f'{safe_host}.html').resolve()
    if not str(path).startswith(str(reports_dir)) or not path.exists():
        return jsonify({'status': 'error', 'message': 'report not found'}), 404
    return path.read_text(encoding='utf-8'), 200, {'Content-Type': 'text/html; charset=utf-8'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BugBounty LAN dashboard')
    parser.add_argument('--port', type=int, default=8001, help='Port to bind for the local LAN UI')
    parser.add_argument('--host', default='127.0.0.1', help='Host interface to bind (default localhost; pass 0.0.0.0 to expose on the LAN)')
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=False)
