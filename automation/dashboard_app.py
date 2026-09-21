#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
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
}


def job_workflow_metadata(name: str) -> Dict[str, Any]:
    clean_name = (name or '').strip()
    if clean_name in WORKFLOW_SEQUENCE:
        return dict(WORKFLOW_SEQUENCE[clean_name])
    return {'step': 99, 'label': job_title_label(clean_name), 'depends_on': []}


def _job_state_for(job_name: str, payload: Dict[str, Any] | None = None) -> str:
    if RUNNING_DIR.exists() and (RUNNING_DIR / f'{job_name}.lock').exists():
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
    if payload and payload.get('status') in {'ok', 'no_new_assets', 'no_in_scope_targets'}:
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


def group_jobs_by_program(jobs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for job in jobs:
        program = job.get('program', 'unknown')
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
            queued_targets = merged_live_asset_targets() if job_name == 'confirm-live-web-assets' else definition.get('targets', [])
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
    queued_targets = merged_live_asset_targets() if job_name == 'confirm-live-web-assets' else []
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
    (RUNNING_DIR / f'{job_name}.lock').write_text(str(int(time.time())), encoding='utf-8')

    command = [sys.executable, str(ROOT / 'automation' / 'worker.py'), '--force']
    if program and program != 'unknown':
        command.extend(['--program', str(program)])

    launched = subprocess.Popen(
        command,
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
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


@app.route('/')
def index():
    jobs = list_jobs()
    summary = summarize_jobs(jobs)
    grouped_jobs = group_jobs_by_program(jobs)
    workflow_order = [job_workflow_metadata(job_name) for job_name in ['aa-passive-discovery', 'american-airlines-passive-dns', 'confirm-live-web-assets']]
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
        .program-header { margin: 0 0 12px; font-size: 28px; }
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
          <h1 style="margin:0;">BugBounty Dashboard</h1>
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
            <div class="program-group">
              <h2 class="program-header">{{ program_label(program_name) }}</h2>
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
                    <form class="rerun-form" action="/jobs/{{ job.name }}/rerun" method="post">
                      <button class="rerun-button" type="submit">Re-run job</button>
                    </form>
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
                            </td>
                            <td>{{ asset.status }}</td>
                          </tr>
                        {% else %}
                          <tr><td colspan="3">No newly discovered assets.</td></tr>
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
            </div>
          {% endfor %}
        {% else %}
          <div class="card">
            <p>No result files have been generated yet.</p>
            <p>Run the worker and a result file will appear in <code>results/</code>.</p>
          </div>
        {% endif %}
      </div>
      <script>
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
    try:
        result = rerun_job(job_name)
    except KeyError:
        return jsonify({'status': 'error', 'message': f'Unknown job: {job_name}'}), 404
    return jsonify(result), 202


@app.route('/api/jobs')
def api_jobs():
    return jsonify(list_jobs())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BugBounty LAN dashboard')
    parser.add_argument('--port', type=int, default=8001, help='Port to bind for the local LAN UI')
    parser.add_argument('--host', default='0.0.0.0', help='Host interface to bind')
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=False)
