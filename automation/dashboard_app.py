#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import functools
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
from urllib.parse import quote

from flask import Flask, jsonify, render_template_string, request

AUTOMATION_DIR = Path(__file__).resolve().parent
if str(AUTOMATION_DIR) not in sys.path:
  sys.path.insert(0, str(AUTOMATION_DIR))

from program_builder import active_approved, create_manual_program, create_program, csv_scope_inventory, load_manual_analysis, parse_scope, read_guidelines, set_active_approval, slug_from_program_name
from stages import ACTIVE_STAGES, STAGE_BY_ID, STAGES, job_name_for, stage_for_job_name

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / 'results'
RUNNING_DIR = RESULTS_DIR / '.running'
JOBS_DIR = ROOT / 'jobs'
REVIEW_FILE = RESULTS_DIR / '.finding-reviews.json'
REVIEW_LOCK = RESULTS_DIR / '.finding-reviews.lock'

app = Flask(__name__)

# Jobs that make live connections to targets and must be launched in active mode.
ACTIVE_JOBS = {'confirm-live-web-assets', 'service-enumeration-live-hosts', 'vhost-discovery-shared-infra', 'directory-enumeration-live-hosts', 'application-security-testing', 'api-endpoint-testing', 'port-scan-live-hosts'}

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
    'port-scan-live-hosts': {
        'step': 9,
        'label': 'Port Scan',
      'depends_on': ['vhost-discovery-shared-infra', 'directory-enumeration-live-hosts', 'application-security-testing'],
    },
}


# Caps on how many rows are rendered per job on the dashboard home page. The full
# data stays in the result JSON; these only bound the HTML payload so the page
# stays small enough to auto-refresh without timing out.
ASSET_RENDER_CAP = 150
EVIDENCE_RENDER_CAP = 15
THREAD_RENDER_CAP = 100


def job_workflow_metadata(name: str) -> Dict[str, Any]:
    clean_name = (name or '').strip()
    if clean_name in WORKFLOW_SEQUENCE:
        return dict(WORKFLOW_SEQUENCE[clean_name])
    canonical_stage = stage_for_job_name(clean_name)
    if canonical_stage and clean_name.endswith('-' + canonical_stage):
      program = clean_name[:-(len(canonical_stage) + 1)]
      stage_metadata = STAGE_BY_ID[canonical_stage]
      return {'step': stage_metadata['step'], 'label': stage_metadata['label'],
          'depends_on': [job_name_for(program, dependency) for dependency in stage_metadata['depends_on']]}
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
    if payload and payload.get('manual_only') and payload.get('job_state') == 'running':
        return 'running' if _lock_is_active(f"manual-program-{payload['program']}") else 'stopped'
    if payload and payload.get('manual_only') and payload.get('job_state') == 'stopped':
        return 'stopped'
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


_SEVERITY_ORDER = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}


def highest_severity(findings: List[Dict[str, Any]] | None) -> str | None:
    """Return the highest-ranked severity label among an asset's findings, or None."""
    best_rank = 0
    best = None
    for finding in findings or []:
        sev = str((finding or {}).get('severity', '')).lower()
        rank = _SEVERITY_ORDER.get(sev, 0)
        if rank > best_rank:
            best_rank = rank
            best = sev
    return best.capitalize() if best else None


def review_candidates(jobs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates = []
    seen: set[str] = set()
    for job in jobs:
        for asset in job.get('assets', []) or []:
            if not isinstance(asset, dict) or not asset.get('domain'):
                continue
            for finding in asset.get('findings', []) or []:
                if not isinstance(finding, dict) or not finding.get('type'):
                    continue
                evidence = {key: finding[key] for key in ('type', 'path', 'ip', 'port', 'service', 'severity') if key in finding}
                identity = json.dumps([job['name'], asset['domain'], evidence], sort_keys=True)
                if identity in seen:
                    continue
                seen.add(identity)
                finding_type = finding['type']
                host = asset['domain']
                target_url = None
                report_url = None
                if isinstance(host, str) and re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?', host) and '..' not in host:
                  path = finding.get('path')
                  if isinstance(path, str) and path.startswith('/') and not path.startswith('//'):
                    target_url = f'https://{host}{quote(path, safe="/%-._~")}'
                  elif finding_type == 'open_port' and finding.get('service') == 'https-alt' and finding.get('port') == 8443:
                    target_url = f'https://{host}:8443/'
                  elif finding_type == 'open_port' and finding.get('service') in {'http-alt', 'http-dev'} and finding.get('port') in {8000, 8080, 8888}:
                    target_url = f"http://{host}:{finding['port']}/"
                  else:
                    target_url = f'https://{host}/'
                  expected_report = f"/reports/{job['name']}/{host}"
                  if asset.get('report_url') == expected_report:
                    report_url = expected_report
                candidates.append({
                    'id': hashlib.sha256(identity.encode('utf-8')).hexdigest(),
                  'program': job.get('program', 'unknown'),
                    'job': job['name'],
                    'host': asset['domain'],
                    'target_url': target_url,
                    'report_url': report_url,
                    'evidence': evidence,
                    'finding': finding,
                    'severity': str(finding.get('severity', 'unknown')).lower(),
                    'confidence': 'medium' if finding_type in {'error_disclosure', 'graphql_introspection'} else 'low',
                    'scope': 'needs verification',
                })
    return candidates


def read_reviews() -> Dict[str, Any]:
    try:
        payload = json.loads(REVIEW_FILE.read_text(encoding='utf-8'))
        return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError):
        return {}


def write_reviews(reviews: Dict[str, Any]) -> None:
    REVIEW_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = REVIEW_FILE.with_name(f'.{REVIEW_FILE.name}.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(reviews, indent=2), encoding='utf-8')
    temporary.replace(REVIEW_FILE)


@app.route('/review')
def review_queue():
    reviews = read_reviews()
    candidates = review_candidates(list_jobs())
    programs = sorted({item['program'] for item in candidates})
    program = request.args.get('program')
    job = request.args.get('job')
    if not program and len(programs) == 1:
        program = programs[0]
    if not program:
        return render_template_string('''<h1>Choose a program</h1>
      {% for program in programs %}<p><a href="{{ url_for('review_queue', program=program) }}">{{ program_label(program) }}</a></p>
      {% else %}<p>No scanner findings to review.</p>{% endfor %}''', programs=programs, program_label=program_label)
    candidates = [item for item in candidates if item['program'] == program and (not job or item['job'] == job)]
    for candidate in candidates:
        decision = reviews.get(candidate['id'], {})
        candidate['decision'] = decision.get('status', 'needs_review')
        candidate['scope'] = decision.get('scope', 'needs_verification')
    minimum = request.args.get('minimum', 'all')
    if minimum == 'medium':
      candidates = [item for item in candidates if _SEVERITY_ORDER.get(item['severity'], 0) >= 3]
    sort = request.args.get('sort', 'severity')
    direction = request.args.get('direction', 'desc' if sort in {'severity', 'confidence'} else 'asc')
    sorters = {'host': lambda item: item['host'], 'job': lambda item: item['job'],
           'type': lambda item: item['evidence']['type'],
           'severity': lambda item: _SEVERITY_ORDER.get(item['severity'], 0),
           'confidence': lambda item: {'low': 1, 'medium': 2, 'high': 3}.get(item['confidence'], 0),
           'scope': lambda item: item['scope'], 'decision': lambda item: item['decision']}
    candidates.sort(key=sorters.get(sort, sorters['severity']), reverse=direction == 'desc')
    columns = [('host', 'Asset'), ('job', 'Job'), ('type', 'Observed evidence'), ('severity', 'Scanner severity'),
           ('confidence', 'Confidence'), ('scope', 'Scope'), ('decision', 'Review')]
    return render_template_string('''<!doctype html>
  <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Finding Review</title><style>
  body { background:#111827; color:#e5e7eb; font-family:Arial,sans-serif; margin:0; padding:24px; }
  main { max-width:1200px; margin:auto; } a { color:#7dd3fc; }
  table { width:100%; border-collapse:collapse; } th,td { text-align:left; vertical-align:top; border-bottom:1px solid #334155; padding:10px; }
  select,button { background:#1f2937; color:#e5e7eb; border:1px solid #475569; padding:7px; }
  code { overflow-wrap:anywhere; } .meta { color:#94a3b8; } .row { display:flex; flex-wrap:wrap; gap:6px; }
  .badge { display:inline-block; padding:3px 7px; border:1px solid currentColor; border-radius:4px; }
  .severity-critical,.severity-high { color:#fca5a5; background:#450a0a; }
  .severity-medium,.confidence-medium { color:#fde68a; background:#422006; }
  .severity-low,.confidence-low { color:#93c5fd; background:#172554; }
  .severity-info,.severity-unknown { color:#cbd5e1; background:#334155; }
  .confidence-high { color:#86efac; background:#052e16; }
  form { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:12px; }
  form label { display:flex; align-items:center; flex-wrap:wrap; gap:6px; }
  @media(max-width:700px) { table,tbody,tr,td { display:block; } thead { display:none; } tr { padding:10px 0; } td { border:0; padding:4px; }
    td:nth-child(4)::before { content:'Scanner severity: '; } td:nth-child(5)::before { content:'Confidence: '; } }
  </style></head><body><main><p><a href="/">← Dashboard</a></p><h1>{{ program_label(program) }} finding review</h1>
  {% if job %}<p>{{ job }}</p>{% endif %}
  <p class="meta">Scanner signals need manual verification. Confidence is a triage estimate, not a confirmed vulnerability rating. Scope must be checked against program rules.</p>
  <form method="get"><input type="hidden" name="program" value="{{ program }}">{% if job %}<input type="hidden" name="job" value="{{ job }}">{% endif %}
  <label>Scanner severity <select name="minimum" onchange="this.form.submit()"><option value="all">All severities</option><option value="medium" {% if minimum == 'medium' %}selected{% endif %}>MEDIUM and above</option></select></label>
  <label>Sort <select name="sort" onchange="this.form.submit()">{% for key,label in columns %}<option value="{{ key }}" {% if sort == key %}selected{% endif %}>{{ label }}</option>{% endfor %}</select></label>
  <label>Order <select name="direction" onchange="this.form.submit()"><option value="desc" {% if direction == 'desc' %}selected{% endif %}>Descending</option><option value="asc" {% if direction == 'asc' %}selected{% endif %}>Ascending</option></select></label></form>
  <table><thead><tr>{% for key,label in columns %}<th aria-sort="{{ ('descending' if direction == 'desc' else 'ascending') if sort == key else 'none' }}"><a href="{{ url_for('review_queue', program=program, job=job, minimum=minimum, sort=key, direction='asc' if sort == key and direction == 'desc' else 'desc') }}">{{ label }}</a></th>{% endfor %}</tr></thead><tbody>
  {% for item in candidates %}<tr><td>{% if item.target_url %}<a href="{{ item.target_url }}" target="_blank" rel="noopener noreferrer"><code>{{ item.host }}</code></a>{% else %}<code>{{ item.host }}</code>{% endif %}</td><td>{{ item.job }}</td>
  <td><strong>{{ item.evidence.type }}</strong><br>{% for key, value in item.evidence.items() if key != 'type' %}<small>{{ key }}: {{ value }}</small><br>{% endfor %}{% if item.target_url and item.evidence.path %}<a href="{{ item.target_url }}" target="_blank" rel="noopener noreferrer">Open path</a><br>{% elif item.target_url and item.evidence.type == 'open_port' %}<a href="{{ item.target_url }}" target="_blank" rel="noopener noreferrer">Open host</a><br>{% endif %}<a href="{{ url_for('finding_writeup', slug=item.program, finding_id=item.id) }}">View write-up</a>{% if item.report_url %}<br><a href="{{ item.report_url }}" target="_blank" rel="noopener noreferrer">Scanner report</a>{% endif %}</td>
  <td><span class="badge severity-{{ item.severity if item.severity in ['critical','high','medium','low','info'] else 'unknown' }}">{{ item.severity|upper }}</span></td>
  <td><span class="badge confidence-{{ item.confidence }}">{{ item.confidence|upper }}</span></td><td><select class="scope" aria-label="Scope for {{ item.host }}">
  {% for value, label in [('needs_verification', 'Needs verification'), ('in_scope', 'In scope'), ('out_of_scope', 'Out of scope')] %}
  <option value="{{ value }}" {% if item.scope == value %}selected{% endif %}>{{ label }}</option>{% endfor %}</select></td>
  <td><div class="row"><select class="decision" aria-label="Review status for {{ item.host }}">
  {% for value, label in [('needs_review', 'Needs review'), ('needs_account', 'Needs account'), ('confirmed', 'Confirmed'), ('false_positive', 'False positive')] %}
  <option value="{{ value }}" {% if item.decision == value %}selected{% endif %}>{{ label }}</option>{% endfor %}</select>
  <button type="button" data-id="{{ item.id }}">Save</button></div></td></tr>
  {% else %}<tr><td colspan="7">No scanner findings to review.</td></tr>{% endfor %}
  </tbody></table></main><script>
  document.querySelectorAll('button[data-id]').forEach(button => button.addEventListener('click', async () => {
    const row = button.closest('tr');
    const token = localStorage.getItem('bugbounty-dashboard-token') || window.prompt('Dashboard token:');
    if (!token) return;
    localStorage.setItem('bugbounty-dashboard-token', token);
    button.disabled = true;
    try {
    const response = await fetch('/review/' + button.dataset.id, {method:'POST', headers:{'Content-Type':'application/json', 'X-BugBounty-Token':token},
      body:JSON.stringify({status:row.querySelector('.decision').value, scope:row.querySelector('.scope').value})});
    if (!response.ok) { alert('Review was not saved (' + response.status + ')'); return; }
    button.textContent = 'Saved';
    } catch (error) { alert('Review was not saved'); } finally { button.disabled = false; }
  }));
    </script></body></html>''', candidates=candidates, program=program, program_label=program_label,
                   job=job, minimum=minimum, sort=sort, direction=direction, columns=columns)


@app.route('/programs/<slug>/findings/<finding_id>/writeup')
def finding_writeup(slug: str, finding_id: str):
    candidate = next((item for item in review_candidates(list_jobs())
              if item['program'] == slug and item['id'] == finding_id), None)
    if candidate is None:
      return 'Finding not found', 404
    decision = read_reviews().get(finding_id, {})
    checks = {
        'open_port': 'Confirm the reported TCP port and service only if port checks are explicitly allowed. A reachable port does not prove unauthenticated access or impact.',
        'missing_security_headers': 'Inspect response headers at the exact observed URL. Record missing headers and demonstrate relevant application impact; missing headers alone may be ineligible.',
        'tech_disclosure': 'Confirm the exact advertised header and version. Check report eligibility; a version banner alone does not demonstrate an exploitable vulnerability.',
        'insecure_cookie': 'Inspect the observed Set-Cookie attributes. Establish whether the cookie is security-sensitive without exposing another user\'s session.',
        'error_disclosure': 'Confirm the observed error or stack trace using a permitted request. Identify what sensitive information is disclosed and redact it in the report.',
        'cors_misconfig': 'Confirm the returned origin and credentials headers. Use your own test account to establish whether unauthorized cross-origin reads are actually possible.',
        'debug_endpoint': 'Confirm the exact observed endpoint is not a login page, then establish whether it exposes sensitive data without collecting unnecessary records.',
        'graphql_introspection': 'Check whether introspection testing is permitted. Confirm the observation and establish distinct, demonstrable impact rather than reporting introspection alone.',
        'unauthenticated_endpoint': 'Confirm the documented endpoint requires authorization and that the returned data is not intentionally public. Use only your own account and minimal records.',
    }
    verification = checks.get(candidate['evidence']['type'], 'Independently verify the recorded scanner observation and demonstrate impact using only permitted, non-destructive checks.')
    draft = '\n'.join([
      '# Manual verification and reporting draft', '',
      f"Program: {program_label(slug)}", f"Job: {candidate['job']}",
      f"Asset: {candidate['host']}", f"Finding: {candidate['evidence']['type']}",
      f"Scanner severity (unverified): {candidate['severity'].upper()}",
      f"Confidence: {candidate['confidence'].upper()}",
      f"Review status: {decision.get('status', 'needs_review')}",
      f"Scope status: {decision.get('scope', 'needs_verification')}", '',
      '## Observed scanner evidence', '```json', json.dumps(candidate['finding'], indent=2), '```', '',
      '## Manual verification',
      '1. Review the current program scope, exclusions, testing restrictions, and request limit.',
      '2. Verify the exact asset and observed path are authorized before making any request.',
      f"3. Independently reproduce the scanner observation on {candidate['target_url'] or candidate['host']} using only permitted tests and your own accounts.",
      '4. Record the exact request, response, timestamp, prerequisites, and sanitized evidence.',
      '5. Rule out login redirects, false positives, and intended behavior.', '',
      '## Finding-specific checks', verification, '',
      '## Confirmed reproduction steps', '[Analyst: enter verified steps and prerequisites]', '',
      '## Expected and actual behavior', '[Analyst: enter independently verified behavior]', '',
      '## Demonstrated impact', '[Analyst: enter proven impact; do not infer impact from scanner severity]', '',
      '## Remediation', '[Analyst: propose a fix after confirming the root cause]', '',
      '## Reporting decision',
      'Unverified draft only. Manually confirm scope, impact, and report eligibility before submitting.',
      'Manual verification does not authorize prohibited automated testing.',
    ])
    if request.args.get('download') == '1':
      return app.response_class(draft, mimetype='text/markdown',
                    headers={'Content-Disposition': f'attachment; filename="finding-{finding_id}.md"'})
    return render_template_string('''<!doctype html><html lang="en"><meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Manual verification draft</title><style>body {font-family:Arial,sans-serif;margin:24px;} pre {white-space:pre-wrap;overflow-wrap:anywhere;max-width:1000px;}</style>
      <p><a href="{{ url_for('review_queue', program=slug) }}">Program findings</a> | <a href="?download=1">Download Markdown</a></p>
      <pre>{{ draft }}</pre></html>''', draft=draft, slug=slug)


@app.route('/review/<finding_id>', methods=['POST'])
def update_review(finding_id: str):
    if not _authorized_for_state_change():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    if data.get('status') not in {'needs_review', 'needs_account', 'confirmed', 'false_positive'} or data.get('scope') not in {'needs_verification', 'in_scope', 'out_of_scope'}:
        return jsonify({'status': 'error', 'message': 'invalid decision'}), 400
    if finding_id not in {item['id'] for item in review_candidates(list_jobs())}:
        return jsonify({'status': 'error', 'message': 'finding not found'}), 404
    REVIEW_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with REVIEW_LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        reviews = read_reviews()
        reviews[finding_id] = {'status': data['status'], 'scope': data['scope'], 'reviewed_at': int(time.time())}
        write_reviews(reviews)
    return jsonify(reviews[finding_id])


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
        if name == 'github-monitor' or job.get('type') in {'github', 'monitor'}:
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


@functools.lru_cache(maxsize=64)
def _read_result_cached(path_str: str, mtime: float, size: int) -> Dict[str, Any]:
    try:
        return json.loads(Path(path_str).read_text(encoding='utf-8'))
    except Exception:
        return {}


def read_result_file(path: Path) -> Dict[str, Any]:
    # Cache by path+mtime+size so large result files are parsed once per page load,
    # not once per helper that inspects them (was O(jobs) reparses of multi-MB files).
    try:
        stat = path.stat()
    except OSError:
        return {}
    return _read_result_cached(str(path), stat.st_mtime, stat.st_size)


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
        elif clean.startswith('stage:'):
          data['stage'] = clean.split(':', 1)[1].strip()
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


def program_stage_targets(program: str, stage_id: str) -> List[str]:
    if stage_id in {'passive-web-discovery', 'passive-dns-discovery'}:
        return []
    sources = {
        'confirm-live-web-assets': ('passive-web-discovery', 'passive-dns-discovery'),
        'service-enumeration': ('confirm-live-web-assets',),
        'vhost-discovery': ('service-enumeration',),
        'directory-enumeration': ('service-enumeration', 'vhost-discovery'),
        'application-testing': ('service-enumeration', 'vhost-discovery'),
        'api-testing': ('service-enumeration', 'directory-enumeration'),
        'port-scan': ('service-enumeration', 'vhost-discovery'),
    }.get(stage_id, ())
    hosts: List[str] = []
    for source in sources:
        payload = read_result_file(RESULTS_DIR / f'{job_name_for(program, source)}.json')
        if source == 'service-enumeration' and stage_id == 'api-testing':
            hosts.extend(asset['domain'] for asset in payload.get('assets', []) or []
                         if isinstance(asset, dict) and asset.get('kind') == 'api-gateway' and asset.get('domain'))
        elif source == 'directory-enumeration' and stage_id == 'api-testing':
            for asset in payload.get('assets', []) or []:
                if isinstance(asset, dict) and asset.get('domain') and any(
                    str(path.get('path', '')).startswith(_API_PATH_HINTS)
                    for path in asset.get('paths', []) or [] if isinstance(path, dict)
                ):
                    hosts.append(asset['domain'])
        else:
            hosts.extend(payload.get('discovered', []) or [])
    return list(dict.fromkeys(hosts))


def list_jobs() -> List[Dict[str, Any]]:
    jobs: List[Dict[str, Any]] = []
    seen: set[str] = set()

    if JOBS_DIR.exists():
        for path in sorted(JOBS_DIR.glob('*.yaml')) + sorted(JOBS_DIR.glob('*.yml')) + sorted((JOBS_DIR / 'generated').glob('*.yaml')):
            job_name = path.stem
            seen.add(job_name)
            definition = read_job_definition(path)
            payload = read_result_file(RESULTS_DIR / f'{job_name}.json')
            job_state = _job_state_for(job_name, payload if payload else None)
            metadata = job_workflow_metadata(definition.get('name', job_name))
            if definition.get('program') != 'american-airlines' and definition.get('stage') in STAGE_BY_ID:
              queued_targets = (definition.get('targets', []) if definition['stage'] in {'passive-web-discovery', 'passive-dns-discovery'}
                        else program_stage_targets(definition['program'], definition['stage']))
            elif job_name == 'confirm-live-web-assets':
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
            elif job_name == 'port-scan-live-hosts':
                queued_targets = combined_live_roots_from_step4_and_step5()
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
      return sorted(jobs, key=lambda item: (item.get('workflow_step', 99), item['name']))

    for path in sorted(RESULTS_DIR.glob('*.json')):
        if path.name.startswith('.') or path.name.startswith('manual-url-check-') or path.stem in seen:
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
    if match.get('raw', {}).get('manual_only'):
      from manual_workflow import stage_block_reason
      stage_id = stage_for_job_name(job_name)
      reason = stage_block_reason(program, stage_id, root=ROOT)
      if reason:
        raise PermissionError(reason)
      if _lock_is_active(f'manual-program-{program}') or _lock_is_active(f'manual-url-check-{program}'):
        raise PermissionError('Another manual check for this program is running')
      process = subprocess.Popen([sys.executable, str(ROOT / 'automation' / 'manual_workflow.py'), program, stage_id],
                     cwd=str(ROOT), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
      return {'status': 'queued', 'job': job_name, 'program': program, 'pid': process.pid}
    if program != 'american-airlines' and stage_for_job_name(job_name) in ACTIVE_STAGES and not active_approved(program, root=ROOT):
      raise PermissionError('Program guidelines have not been approved')
    result_path = RESULTS_DIR / f'{job_name}.json'
    result_path.parent.mkdir(parents=True, exist_ok=True)
    stage_id = stage_for_job_name(job_name)
    if program != 'american-airlines' and stage_id in STAGE_BY_ID:
      queued_targets = (match.get('targets', []) if stage_id in {'passive-web-discovery', 'passive-dns-discovery'}
                else program_stage_targets(program, stage_id))
    elif job_name == 'confirm-live-web-assets':
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
    elif job_name == 'port-scan-live-hosts':
        queued_targets = combined_live_roots_from_step4_and_step5()
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
    if stage_id in ACTIVE_STAGES:
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
          <p>This dashboard runs a separate nine-stage recon pipeline for each program, moving from passive discovery to live validation and targeted application, API, and port testing. Each stage narrows its program's scope using earlier results.</p>
          <p>The goal is to find realistic, high-signal assets and manually validate them before writing a report or investing time in deep exploitation.</p>
        </div>

        <div class="card">
          <h2>Adding a program</h2>
          <p>Enter a unique program name and upload a HackerOne or Bugcrowd CSV, or a Markdown scope file, from New program on the dashboard. That name supplies the separate program folder and job names. Only explicitly in-scope domain entries become targets; unsupported assets must be reviewed manually.</p>
          <p>Domain and wildcard scopes generate nine jobs. URL- and app-only CSVs are kept as manual-only inventories with no scans queued. Generated active stages remain blocked until an operator reviews the guidelines and confirms the pipeline's checks are permitted. The server's active-testing opt-in is also required. Prose rules are not automatically translated into scanner limits or exclusions.</p>
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
            <div class="step">
              <div class="num">Step 9</div>
              <h3>Port Scan</h3>
              <p>Check bounded ports on IPs behind confirmed in-scope web hosts after application testing. Open ports are triage signals, not confirmed vulnerabilities.</p>
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
    workflow_order = STAGES
    manual_programs = []
    manual_job_names = {job['name'] for job in jobs if job.get('raw', {}).get('manual_only')}
    programs_dir = ROOT / 'programs'
    if programs_dir.exists():
      for inventory_path in sorted(programs_dir.glob('*/scope-inventory.json')):
        try:
          inventory = json.loads(inventory_path.read_text(encoding='utf-8'))
          manual_programs.append({'slug': inventory_path.parent.name,
                      'name': inventory.get('display_name', inventory_path.parent.name),
                      'approved': active_approved(inventory_path.parent.name, root=ROOT),
                        'workflow_queued': (inventory_path.parent / '.manual-workflow.json').exists() and all(
                          job_name_for(inventory_path.parent.name, stage['stage']) in manual_job_names for stage in STAGES),
                      'eligible_asset_types': inventory['eligible_asset_types']})
        except (OSError, ValueError, KeyError, TypeError):
          continue
      manual_slugs = {item['slug'] for item in manual_programs}
      grouped_jobs = {**{program: entries for program, entries in grouped_jobs.items() if program not in manual_slugs},
              **{program: entries for program, entries in grouped_jobs.items() if program in manual_slugs}}
      from manual_workflow import stage_block_reason
      for job in jobs:
        if job.get('raw', {}).get('manual_only'):
          job['blocked_reason'] = stage_block_reason(job['program'], stage_for_job_name(job['name']), root=ROOT)
    generated_programs = {job['program'] for job in jobs if
                (JOBS_DIR / 'generated' / f"{job['program']}-passive-web-discovery.yaml").exists()}
    approved_programs = {program for program in generated_programs if active_approved(program, root=ROOT)}
    pending_manual_programs = [item for item in manual_programs if not (item['approved'] and item['workflow_queued'])]
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
        .upload-area { border: 1px dashed #64748b; background: #1f2937; padding: 16px 20px; margin-bottom: 20px; }
        .upload-area.dragging { border-color: #38bdf8; background: #253645; }
        .upload-area form { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; }
        .upload-area h2 { margin: 0 0 12px; font-size: 18px; }
        .upload-area input { max-width: 100%; }
        .upload-area input[type=text] { background: #0f172a; color: #e5e7eb; border: 1px solid #475569; padding: 8px; }
        .upload-area textarea { width: min(100%, 600px); min-height: 90px; background: #0f172a; color: #e5e7eb; border: 1px solid #475569; }
        .upload-area button { background: #0ea5e9; color: #082f49; border: 0; padding: 8px 12px; font-weight: bold; cursor: pointer; }
        .upload-area button:disabled { opacity: .6; cursor: not-allowed; }
        .upload-area button[aria-busy=true] { cursor: progress; }
        #upload-status { color: #cbd5e1; font-size: 14px; }
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
        .program-rules { border-top: 1px solid #334155; border-bottom: 1px solid #334155; margin: 0 0 16px; padding: 8px 0; }
        .program-rules summary { padding: 8px 0; }
        .program-rules pre { background: #0f172a; padding: 12px; max-height: 300px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
        .program-rules button { background: #1f2937; color: #e5e7eb; border: 1px solid #475569; padding: 7px 10px; cursor: pointer; }
        .program-rules button:disabled { opacity: .55; cursor: not-allowed; }
        .manual-analysis { margin: 8px 0 18px; }
        .manual-analysis button { background: #1f2937; color: #e5e7eb; border: 1px solid #475569; padding: 7px 10px; cursor: pointer; }
        .manual-analysis table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .manual-analysis th, .manual-analysis td { text-align: left; padding: 6px; border-bottom: 1px solid #334155; }
        .analysis-policy { color: #fbbf24; }
        .manual-analysis pre { background: #0f172a; padding: 12px; max-height: 240px; overflow: auto; white-space: pre-wrap; }
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
        <section class="upload-area" id="scope-drop">
          <h2>New program</h2>
          <form id="program-upload">
            <label for="program-name">Program name</label>
            <input id="program-name" name="program_name" type="text" maxlength="80" required>
            <label for="scope-file">Scope file</label>
            <input id="scope-file" name="scope_file" type="file" accept=".csv,.md,text/csv,text/markdown" required>
            <label for="guidelines-file">Program guidelines</label>
            <input id="guidelines-file" name="guidelines_file" type="file" accept=".md,.txt,text/plain,text/markdown">
            <label for="guidelines-text">Or paste guidelines</label>
            <textarea id="guidelines-text" name="guidelines_text"></textarea>
            <button type="submit">Upload scope</button>
            <span id="upload-status" role="status" aria-live="polite"></span>
          </form>
        </section>
        {% if pending_manual_programs %}
          <section class="upload-area" id="manual-scope-review">
            <h2>Manual scope review</h2>
            {% for item in pending_manual_programs %}
              <div class="manual-review-entry">
              <p><strong>{{ item.name }}</strong> — {{ 'Nine manual steps queued below existing programs.' if item.workflow_queued else 'No scans queued.' }}
                {% for asset_type, count in item.eligible_asset_types.items() %}
                  <span>{{ asset_type }}: {{ count }}</span>{% if not loop.last %}, {% endif %}
                {% endfor %}
              </p>
              <div class="manual-analysis" data-program="{{ item.slug }}" data-approved="{{ 'true' if item.approved else 'false' }}">
                <button type="button" class="analyze-manual-program">Start {{ item.name }} scope analysis</button>
                <button type="button" class="review-manual-guidelines">Review guidelines</button>
                <pre class="manual-guidelines" hidden></pre>
                <label><input type="checkbox" class="manual-guidelines-ack" {% if item.approved %}checked{% endif %}> I confirm these rules permit the manually started workflow and bounded GET/HEAD checks; queue the nine manual steps</label>
                <button type="button" class="start-manual-check" disabled>Start exact-URL check</button>
                <span class="manual-analysis-status" role="status" aria-live="polite"></span>
                <div class="manual-analysis-results"></div>
              </div>
              </div>
            {% endfor %}
          </section>
        {% endif %}
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
            <details class="program-group" data-state-key="program-{{ program_name }}" open>
              <summary class="program-header">{{ program_label(program_name) }} <span class="program-count">({{ program_summary.jobs }} jobs)</span></summary>
              <p><a href="{{ url_for('review_queue', program=program_name) }}">Review {{ program_label(program_name) }} findings</a></p>
              {% if program_name in generated_programs %}
                <details class="program-rules" data-state-key="rules-{{ program_name }}" data-program="{{ program_name }}">
                  <summary>Program guidelines: <span class="approval-status">{{ 'Active approved' if program_name in approved_programs else 'Review required' }}</span></summary>
                  <button type="button" class="view-guidelines">View guidelines</button>
                  <pre hidden></pre>
                  <label><input type="checkbox" class="rules-acknowledged"> I confirm this program permits the active checks in this pipeline</label>
                  <button type="button" class="approve-active" disabled>Approve active</button>
                  <button type="button" class="revoke-active" disabled>Revoke approval</button>
                  <span class="rules-message" role="status" aria-live="polite"></span>
                </details>
              {% endif %}
              {% if program_summary.passive_dns_jobs %}
                <div class="program-summary-card">
                  <h3>Passive DNS</h3>
                  <div class="meta">{{ program_summary.passive_dns_jobs }} jobs &nbsp; | &nbsp; Targets: {{ program_summary.targets }} &nbsp; | &nbsp; Discovered: {{ program_summary.discovered }} &nbsp; | &nbsp; {{ program_summary.completed }}/{{ program_summary.passive_dns_jobs }} complete</div>
                </div>
              {% endif %}
              {% for job in program_jobs %}
                <details class="job" data-state-key="job-{{ job.name }}">
                  <summary>
                    <div class="job-header">
                      <div class="job-title-wrap">
                        <h3 class="job-name">{{ job_title_label(job.name) }}</h3>
                        <div class="job-summary"><strong>Targets:</strong> {{ job.targets|length }} &nbsp; <strong>Discovered:</strong> {{ job.discovered|length }}{% if job.raw.total_candidates is defined %} &nbsp; <strong>Checked:</strong> {{ job.raw.processed_count or 0 }} / {{ job.raw.total_candidates }}{% endif %} &nbsp; <strong>Status:</strong> {{ job.job_state }}</div>
                      </div>
                      <div class="status {{ 'ok' if job.job_state == 'completed' else 'warn' if job.job_state == 'running' else 'bad' }}">{{ job.job_state }}</div>
                    </div>
                  </summary>
                  <div class="job-content">
                    <p><a href="{{ url_for('review_queue', program=job.program, job=job.name) }}">Review job findings</a></p>
                    <div class="rerun-form">
                      <button class="rerun-button" type="button" onclick="rerunJob('{{ job.name }}', this)" {% if job.blocked_reason %}disabled title="{{ job.blocked_reason }}"{% elif job.program in generated_programs and job.type == 'active' and job.program not in approved_programs %}disabled title="Review guidelines before active testing"{% endif %}>{{ 'Start step manually' if job.raw.manual_only else 'Re-run job' }}</button>
                      {% if job.blocked_reason %}<span class="meta">{{ job.blocked_reason }}</span>{% endif %}
                    </div>
                    <p><strong>Program:</strong> {{ program_label(job.program) }}</p>
                    <p><strong>Type:</strong> {{ job.type }}</p>
                    <p><strong>Pipeline status:</strong> {{ job.status }}</p>
                    <p><strong>Source count:</strong> {{ job.source_count }}</p>
                    <p><strong>Targets:</strong> {{ job.targets|length }}</p>
                    {% if job.raw.total_candidates is defined %}<p><strong>Coverage:</strong> {{ job.raw.processed_count or 0 }} / {{ job.raw.total_candidates }} hosts checked, {{ job.raw.remaining_count or 0 }} remaining</p>{% endif %}
                    <p><strong>Discovered:</strong> {{ job.discovered|length }}</p>

                    {% set probe_log = (job.raw.probe_log if job.raw else []) %}
                    {% set thread_status = (job.raw.thread_status if job.raw else []) %}
                    {% set login_redirects = probe_log|selectattr('status', 'equalto', 'login_redirect')|list %}
                    {% if probe_log or thread_status %}
                      <details class="collapsible-list" data-state-key="threads-{{ job.name }}">
                        <summary>Thread progress ({{ thread_status|length }})</summary>
                        <ul>
                          {% for item in thread_status[:thread_render_cap] %}
                            <li><code>{{ item.host }}</code> — {{ item.status }}{% if item.url %} / {{ item.url }}{% endif %}{% if item.thread_id %} [{{ item.thread_id }}]{% endif %}</li>
                          {% endfor %}
                          {% if thread_status|length > thread_render_cap %}
                            <li>… {{ thread_status|length - thread_render_cap }} more not shown</li>
                          {% endif %}
                        </ul>
                      </details>
                    {% endif %}
                    {% if login_redirects %}
                      <details class="collapsible-list" data-state-key="login-redirects-{{ job.name }}">
                        <summary>Login redirects ({{ login_redirects|length }})</summary>
                        <ul>
                          {% for item in login_redirects %}
                            <li><code>{{ item.host }}</code> — {{ item.classification or 'unknown_login' }}{% if item.final_host %} → <code>{{ item.final_host }}{{ item.final_path or '/' }}</code>{% endif %}{% if item.title %} — {{ item.title }}{% endif %}</li>
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
                          <th align="left">Scanner severity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {% for asset in job.assets[:asset_render_cap] %}
                          <tr>
                            <td><code>{{ asset.domain }}</code></td>
                            <td>
                              {% if asset.evidence %}
                                <div class="evidence-list">
                                  {% for item in asset.evidence[:evidence_render_cap] %}
                                    <span class="evidence-item"><a href="{{ item.url }}" target="_blank" rel="noopener">{{ item.source }}</a></span>
                                  {% endfor %}
                                  {% if asset.evidence|length > evidence_render_cap %}
                                    <span class="evidence-item">+{{ asset.evidence|length - evidence_render_cap }} more</span>
                                  {% endif %}
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
                            <td>
                              {% set sev = highest_severity(asset.findings) %}
                              {% if sev %}
                                <span class="status {{ 'bad' if sev in ['Critical', 'High'] else 'warn' if sev == 'Medium' else 'ok' }}">{{ sev }}</span>
                              {% else %}—{% endif %}
                            </td>
                          </tr>
                        {% else %}
                          <tr><td colspan="6">No newly discovered assets.</td></tr>
                        {% endfor %}
                      </tbody>
                    </table>
                    {% if job.assets|length > asset_render_cap %}
                      <p style="margin-top:8px; color:#9ca3af;">Showing first {{ asset_render_cap }} of {{ job.assets|length }} assets. Full data in the result file.</p>
                    {% endif %}

                    <details class="collapsible-list" data-state-key="targets-{{ job.name }}">
                      <summary>In-scope targets ({{ job.targets|length }})</summary>
                      <ul>
                        {% for item in job.targets %}
                          <li><code>{{ item }}</code></li>
                        {% endfor %}
                      </ul>
                    </details>

                    <details class="collapsible-list" data-state-key="queued-{{ job.name }}">
                      <summary>Queued ({{ job.queued|length }})</summary>
                      <ul>
                        {% for item in job.queued %}
                          <li><code>{{ item }}</code></li>
                        {% endfor %}
                      </ul>
                    </details>
                    {% if job.skipped %}
                      <details class="collapsible-list" data-state-key="skipped-{{ job.name }}">
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
            {% if manual_programs %}<p>No automated jobs for these scopes.</p>
            {% else %}<p>No result files have been generated yet.</p>
            <p>Run the worker and a result file will appear in <code>results/</code>.</p>{% endif %}
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

        const uploadForm = document.getElementById('program-upload');
        const programName = document.getElementById('program-name');
        const scopeDrop = document.getElementById('scope-drop');
        const scopeFile = document.getElementById('scope-file');
        const guidelinesFile = document.getElementById('guidelines-file');
        const guidelinesText = document.getElementById('guidelines-text');
        const uploadStatus = document.getElementById('upload-status');
        document.querySelectorAll('.manual-analysis').forEach(panel => {
          const analyzeButton = panel.querySelector('.analyze-manual-program');
          const rulesButton = panel.querySelector('.review-manual-guidelines');
          const guidelinesPre = panel.querySelector('.manual-guidelines');
          const guidelinesAck = panel.querySelector('.manual-guidelines-ack');
          const startButton = panel.querySelector('.start-manual-check');
          const status = panel.querySelector('.manual-analysis-status');
          const output = panel.querySelector('.manual-analysis-results');
          let currentAnalysis = null;
          let approvedState = panel.dataset.approved === 'true';

          function renderCheckProgress(check) {
            if (!check) return;
            let results = output.querySelector('.manual-check-results');
            if (!results) {
              results = document.createElement('div');
              results.className = 'manual-check-results';
              output.append(results);
            }
            results.replaceChildren();
            const table = document.createElement('table');
            table.innerHTML = '<thead><tr><th>Host</th><th>Exact path</th><th>Status</th><th>Service</th><th>Redirect</th></tr></thead><tbody></tbody>';
            const body = table.querySelector('tbody');
            check.results.forEach(item => {
              const row = document.createElement('tr');
              const redirect = item.redirect ? item.redirect.host + item.redirect.path + (item.redirect.query_present ? ' (query redacted)' : '') : 'None';
              [item.host, item.path, item.status || item.error || 'No response', item.server || item.content_type || 'Unknown', redirect].forEach(value => {
                const cell = document.createElement('td');
                cell.textContent = value;
                row.append(cell);
              });
              body.append(row);
            });
            results.append(table);
            status.textContent = check.state === 'stopped'
              ? 'Exact-URL check stopped: ' + check.stopped_reason + '. ' + check.checked + ' checked, ' + check.remaining + ' remaining.'
              : check.complete
              ? 'Exact-URL check complete: ' + check.checked + ' checked; ' + check.skipped_query_urls + ' query URLs skipped.'
              : 'Exact-URL check running: ' + check.checked + ' checked, ' + check.remaining + ' remaining; ' + check.skipped_query_urls + ' query URLs skipped.';
          }

          async function loadAnalysis() {
            const token = getToken(false);
            if (!token) return null;
            status.textContent = 'Analyzing saved inventory and guidelines locally...';
            const response = await fetch('/programs/' + encodeURIComponent(panel.dataset.program) + '/analysis',
              {headers: {'X-BugBounty-Token': token}});
            const analysis = await response.json();
            if (!response.ok) {
              if (response.status === 401) localStorage.removeItem(TOKEN_KEY);
              throw new Error(analysis.message || 'Analysis unavailable');
            }
            currentAnalysis = analysis;
            approvedState = analysis.approved;
            return analysis;
          }

          async function refreshCheckProgress() {
            try {
              const analysis = await loadAnalysis();
              renderCheckProgress(analysis.url_check);
              if (analysis.url_check && !analysis.url_check.complete && analysis.url_check.state !== 'stopped') setTimeout(refreshCheckProgress, 5000);
            } catch (error) {
              status.textContent = error.message || 'Progress unavailable';
            }
          }

          analyzeButton.addEventListener('click', async () => {
            analyzeButton.disabled = true;
            output.replaceChildren();
            try {
              const analysis = await loadAnalysis();
              const policy = document.createElement('p');
              policy.className = 'analysis-policy';
              policy.textContent = 'Offline analysis only; no target requests sent. Automated requests: ' +
                analysis.policy.automated_requests + '. ' + analysis.policy.reason +
                (analysis.policy.stated_max_requests_per_second ? ' Program limit: ' + analysis.policy.stated_max_requests_per_second + ' requests/second; this checker caps at 1 request/second.' : '');
              output.append(policy);
              const counts = document.createElement('p');
              counts.textContent = analysis.eligible_urls + ' eligible exact URLs (' + Object.entries(analysis.categories).map(([key, value]) => key + ': ' + value).join(', ') + '); ' +
                analysis.app_ids + ' app IDs; ' + analysis.invalid_urls + ' invalid URLs skipped.';
              output.append(counts);
              const table = document.createElement('table');
              table.innerHTML = '<thead><tr><th>Exact host</th><th>Path</th><th>Surface</th><th>Query</th></tr></thead><tbody></tbody>';
              const tbody = table.querySelector('tbody');
              analysis.assets.forEach(asset => {
                const row = document.createElement('tr');
                const hostCell = document.createElement('td');
                const hostLink = document.createElement('a');
                hostLink.href = (asset.scheme || 'https') + '://' + asset.host + (asset.port ? ':' + asset.port : '') + asset.path;
                hostLink.target = '_blank';
                hostLink.rel = 'noopener noreferrer';
                hostLink.textContent = asset.host;
                hostCell.append(hostLink);
                row.append(hostCell);
                [asset.path, asset.category, asset.query_present ? 'Present (redacted)' : 'None'].forEach(value => {
                  const cell = document.createElement('td');
                  cell.textContent = value;
                  row.append(cell);
                });
                tbody.append(row);
              });
              output.append(table);
              analysis.app_assets.forEach(asset => {
                const item = document.createElement('p');
                item.textContent = asset.platform + ' app ID: ' + asset.identifier;
                output.append(item);
              });
              status.textContent = 'Offline analysis complete';
              renderCheckProgress(analysis.url_check);
              const canStart = analysis.policy.automated_requests === 'manual_approval_required' && analysis.approved;
              startButton.disabled = !canStart;
              if (analysis.approved) {
                guidelinesAck.checked = true;
                rulesButton.textContent = 'Guidelines approved';
              }
              if (analysis.url_check && !analysis.url_check.complete && analysis.url_check.state !== 'stopped') setTimeout(refreshCheckProgress, 5000);
            } catch (error) {
              status.textContent = error.message || 'Analysis unavailable';
            } finally {
              analyzeButton.disabled = false;
            }
          });

          async function loadManualGuidelines(preserveAcknowledgement = false) {
            const token = getToken(false);
            if (!token) throw new Error('Dashboard token required to load current guidelines');
            status.textContent = 'Loading current program guidelines...';
            const response = await fetch('/programs/' + encodeURIComponent(panel.dataset.program) + '/guidelines',
              {headers: {'X-BugBounty-Token': token}});
            const rules = await response.json();
            if (!response.ok) {
              if (response.status === 401) localStorage.removeItem(TOKEN_KEY);
              throw new Error(rules.message || 'Guidelines unavailable');
            }
            panel.dataset.digest = rules.guidelines_sha256;
            guidelinesPre.textContent = rules.text;
            guidelinesPre.hidden = false;
            approvedState = rules.approved;
            if (!preserveAcknowledgement) guidelinesAck.checked = rules.approved;
            if (currentAnalysis) currentAnalysis.approved = rules.approved;
            startButton.disabled = !rules.approved || !currentAnalysis || currentAnalysis.policy.automated_requests !== 'manual_approval_required';
            status.textContent = rules.approved ? 'Current guidelines approved' : 'Review the displayed rules, then check the confirmation to queue nine manual steps';
          }

          rulesButton.addEventListener('click', async () => {
            try {
              await loadManualGuidelines();
            } catch (error) {
              status.textContent = error.message || 'Guidelines unavailable';
            }
          });

          guidelinesAck.addEventListener('change', async () => {
            const desiredApproval = guidelinesAck.checked;
            let decisionSaved = false;
            guidelinesAck.disabled = true;
            guidelinesAck.setAttribute('aria-busy', 'true');
            rulesButton.disabled = true;
            analyzeButton.disabled = true;
            startButton.disabled = true;
            try {
              await loadManualGuidelines(true);
              await loadAnalysis();
              const token = getToken(false);
              if (!token) throw new Error('Dashboard token required to save approval');
              status.textContent = desiredApproval ? 'Saving approval and queueing nine manual steps...' : 'Revoking manual scope approval...';
              const response = await fetch('/programs/' + encodeURIComponent(panel.dataset.program) + '/active-approval', {
                method: 'POST', headers: {'Content-Type': 'application/json', 'X-BugBounty-Token': token},
                body: JSON.stringify({approved: desiredApproval, acknowledged: true, guidelines_sha256: panel.dataset.digest}),
              });
              const result = await response.json();
              if (!response.ok) throw new Error(result.message || 'Approval failed');
              decisionSaved = true;
              approvedState = desiredApproval;
              guidelinesAck.checked = approvedState;
              currentAnalysis.approved = approvedState;
              status.textContent = approvedState ? 'Manual scope approved; nine steps queued below existing programs' : 'Approval revoked; manual scan starts are blocked';
              if (approvedState) {
                const queuedLink = document.createElement('a');
                queuedLink.href = '#manual-workflow-' + panel.dataset.program;
                queuedLink.textContent = ' Go to queued steps';
                status.append(queuedLink);
              }
              const workflowResponse = await fetch('/');
              if (!workflowResponse.ok) throw new Error('Queue refresh unavailable');
              const documentCopy = new DOMParser().parseFromString(await workflowResponse.text(), 'text/html');
              const key = 'program-' + panel.dataset.program;
              const queued = documentCopy.querySelector('[data-state-key="' + key + '"]');
              if (queued) {
                queued.id = 'manual-workflow-' + panel.dataset.program;
                const existing = document.querySelector('[data-state-key="' + key + '"]');
                if (existing) existing.replaceWith(queued);
                else document.querySelector('.wrap').append(queued);
                if (approvedState) {
                  queued.open = true;
                  queued.scrollIntoView({behavior: 'smooth', block: 'start'});
                  const reviewSection = panel.closest('#manual-scope-review');
                  panel.closest('.manual-review-entry').remove();
                  if (!reviewSection.querySelector('.manual-review-entry')) reviewSection.remove();
                }
              }
            } catch (error) {
              guidelinesAck.checked = approvedState;
              status.textContent = decisionSaved ? 'Approval decision saved; reload the dashboard to refresh queued steps' : error.message || 'Approval failed';
            } finally {
              guidelinesAck.disabled = false;
              guidelinesAck.removeAttribute('aria-busy');
              rulesButton.disabled = false;
              analyzeButton.disabled = false;
              startButton.disabled = !approvedState || !currentAnalysis || currentAnalysis.policy.automated_requests !== 'manual_approval_required';
            }
          });

          startButton.addEventListener('click', async () => {
            const token = getToken(false);
            if (!token) return;
            startButton.disabled = true;
            status.textContent = 'Starting exact-URL HEAD checks...';
            try {
              const response = await fetch('/programs/' + encodeURIComponent(panel.dataset.program) + '/url-check', {
                method: 'POST', headers: {'X-BugBounty-Token': token},
              });
              const result = await response.json();
              if (!response.ok) throw new Error(result.message || 'URL check could not start');
              status.textContent = 'Running at ' + result.requests_per_second + ' request/second; ' + result.skipped_query_urls + ' query URLs skipped.';
              setTimeout(refreshCheckProgress, 2000);
            } catch (error) {
              status.textContent = error.message || 'URL check could not start';
              startButton.disabled = false;
            }
          });
        });
        let uploadInProgress = false;
        let uploadComplete = false;
        function uploadDraftPending() {
          return !uploadComplete && (uploadInProgress || scopeFile.files.length > 0 ||
            guidelinesFile.files.length > 0 || !!programName.value.trim() || !!guidelinesText.value.trim());
        }
        ['dragenter', 'dragover'].forEach(eventName => scopeDrop.addEventListener(eventName, event => {
          event.preventDefault();
          scopeDrop.classList.add('dragging');
        }));
        ['dragleave', 'drop'].forEach(eventName => scopeDrop.addEventListener(eventName, event => {
          event.preventDefault();
          scopeDrop.classList.remove('dragging');
          if (eventName === 'drop' && event.dataTransfer.files.length) {
            scopeFile.files = event.dataTransfer.files;
          }
        }));
        uploadForm.addEventListener('submit', async event => {
          event.preventDefault();
          const token = getToken(false);
          if (!token || !programName.value.trim() || !scopeFile.files.length) return;
          if (!guidelinesFile.files.length && !guidelinesText.value.trim()) {
            uploadStatus.textContent = 'Program guidelines are required';
            return;
          }
          const button = uploadForm.querySelector('button');
          button.disabled = true;
          uploadInProgress = true;
          uploadStatus.textContent = 'Uploading...';
          try {
            const response = await fetch('/programs/upload', { method: 'POST',
              headers: {'X-BugBounty-Token': token}, body: new FormData(uploadForm) });
            const result = await response.json();
            if (!response.ok) {
              if (response.status === 401) localStorage.removeItem(TOKEN_KEY);
              uploadStatus.textContent = result.message || 'Upload failed';
              return;
            }
            uploadStatus.textContent = result.message || (result.program + ' awaiting rules review');
            uploadComplete = true;
            saveViewState();
            window.location.reload();
          } catch (error) {
            uploadStatus.textContent = 'Upload failed';
          } finally {
            uploadInProgress = false;
            button.disabled = false;
          }
        });

        document.querySelectorAll('.program-rules').forEach(panel => {
          const slug = panel.dataset.program;
          const message = panel.querySelector('.rules-message');
          const documentView = panel.querySelector('pre');
          const acknowledgment = panel.querySelector('.rules-acknowledged');
          const approve = panel.querySelector('.approve-active');
          const revoke = panel.querySelector('.revoke-active');
          const view = panel.querySelector('.view-guidelines');
          view.addEventListener('click', async () => {
            const token = getToken(false);
            if (!token) return;
            try {
              const response = await fetch('/programs/' + encodeURIComponent(slug) + '/guidelines',
                {headers: {'X-BugBounty-Token': token}});
              const result = await response.json();
              if (!response.ok) {
                if (response.status === 401) localStorage.removeItem(TOKEN_KEY);
                message.textContent = result.message || 'Guidelines unavailable';
                return;
              }
              documentView.textContent = result.text;
              documentView.hidden = false;
              panel.dataset.digest = result.guidelines_sha256;
              acknowledgment.checked = false;
              approve.disabled = true;
              revoke.disabled = !result.approved;
              message.textContent = '';
            } catch (error) {
              message.textContent = 'Guidelines unavailable';
            }
          });
          acknowledgment.addEventListener('change', () => {
            approve.disabled = !panel.dataset.digest || !acknowledgment.checked;
          });
          async function setApproval(approved) {
            const token = getToken(false);
            if (!token || !panel.dataset.digest) return;
            approve.disabled = true;
            revoke.disabled = true;
            try {
              const response = await fetch('/programs/' + encodeURIComponent(slug) + '/active-approval', {
                method: 'POST', headers: {'Content-Type': 'application/json', 'X-BugBounty-Token': token},
                body: JSON.stringify({approved, acknowledged: true, guidelines_sha256: panel.dataset.digest}),
              });
              const result = await response.json();
              if (!response.ok) {
                if (response.status === 401) localStorage.removeItem(TOKEN_KEY);
                message.textContent = result.message || 'Decision not saved';
                return;
              }
              if (uploadDraftPending()) {
                uploadStatus.textContent = 'Refresh paused while an upload is staged';
                return;
              }
              saveViewState();
              window.location.reload();
            } catch (error) {
              message.textContent = 'Decision not saved';
            } finally {
              approve.disabled = !acknowledgment.checked;
              revoke.disabled = false;
            }
          }
          approve.addEventListener('click', () => setApproval(true));
          revoke.addEventListener('click', () => setApproval(false));
        });

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
            if (uploadDraftPending()) {
              uploadStatus.textContent = 'Refresh paused while an upload is staged';
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

        const viewStateKey = 'bugbounty-dashboard-view-state';
        function saveViewState() {
          const open = {};
          document.querySelectorAll('details[data-state-key]').forEach((element) => {
            open[element.dataset.stateKey] = element.open;
          });
          sessionStorage.setItem(viewStateKey, JSON.stringify({ open, scrollY: window.scrollY }));
        }

        function restoreViewState() {
          try {
            const state = JSON.parse(sessionStorage.getItem(viewStateKey) || '{}');
            const open = state.open || {};
            document.querySelectorAll('details[data-state-key]').forEach((element) => {
              if (Object.prototype.hasOwnProperty.call(open, element.dataset.stateKey)) {
                element.open = Boolean(open[element.dataset.stateKey]);
              }
            });
            if (Number.isFinite(state.scrollY)) {
              requestAnimationFrame(() => window.scrollTo(0, state.scrollY));
            }
          } catch (err) {
            sessionStorage.removeItem(viewStateKey);
          }
        }

        restoreViewState();
        window.addEventListener('beforeunload', saveViewState);
        window.addEventListener('beforeunload', event => {
          if (!uploadDraftPending()) return;
          event.preventDefault();
          event.returnValue = '';
        });

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
              if (uploadDraftPending()) return;
              saveViewState();
              window.location.reload();
            }, value * 1000);
          }
        }

        if (refreshSelect) {
          refreshSelect.addEventListener('change', applyRefreshInterval);
        }
        if (refreshButton) {
          refreshButton.addEventListener('click', () => {
            if (uploadDraftPending()) {
              uploadStatus.textContent = 'Refresh paused while an upload is staged';
              return;
            }
            saveViewState();
            setLastRefreshed();
            window.location.reload();
          });
        }
        applyRefreshInterval();
      </script>
    </body>
    </html>
    ''', jobs=jobs, summary=summary, grouped_jobs=grouped_jobs, manual_programs=manual_programs, pending_manual_programs=pending_manual_programs, generated_programs=generated_programs, approved_programs=approved_programs, program_label=program_label, job_title_label=job_title_label, summarize_program_jobs=summarize_program_jobs, workflow_order=workflow_order, highest_severity=highest_severity, asset_render_cap=ASSET_RENDER_CAP, evidence_render_cap=EVIDENCE_RENDER_CAP, thread_render_cap=THREAD_RENDER_CAP)


@app.route('/jobs/<job_name>/rerun', methods=['POST'])
def rerun_job_endpoint(job_name: str):
    if not _authorized_for_state_change():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
    try:
        result = rerun_job(job_name)
    except KeyError:
        return jsonify({'status': 'error', 'message': f'Unknown job: {job_name}'}), 404
    except PermissionError as exc:
      return jsonify({'status': 'error', 'message': str(exc)}), 409
    return jsonify(result), 202


@app.route('/programs/upload', methods=['POST'])
def upload_program():
    if not _authorized_for_state_change():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
    try:
        slug = slug_from_program_name(request.form.get('program_name', ''))
    except ValueError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    uploaded = request.files.get('scope_file')
    if not uploaded or not uploaded.filename:
        return jsonify({'status': 'error', 'message': 'A scope file is required'}), 400
    contents = uploaded.stream.read(2 * 1024 * 1024 + 1)
    if len(contents) > 2 * 1024 * 1024:
        return jsonify({'status': 'error', 'message': 'Scope file exceeds 2 MB'}), 413
    rules_file = request.files.get('guidelines_file')
    if rules_file and rules_file.filename:
        if Path(rules_file.filename).suffix.lower() not in {'.md', '.txt'}:
            return jsonify({'status': 'error', 'message': 'Guidelines must be Markdown or plain text'}), 400
        raw_rules = rules_file.stream.read(256 * 1024 + 1)
        if len(raw_rules) > 256 * 1024:
            return jsonify({'status': 'error', 'message': 'Guidelines exceed 256 KB'}), 413
        try:
            guidelines = raw_rules.decode('utf-8-sig')
        except UnicodeDecodeError:
            return jsonify({'status': 'error', 'message': 'Guidelines must use UTF-8'}), 400
    else:
        guidelines = request.form.get('guidelines_text', '')
    if not guidelines.strip() or len(guidelines.encode('utf-8')) > 256 * 1024:
        return jsonify({'status': 'error', 'message': 'Program guidelines are required (max 256 KB)'}), 400
    try:
        scope_content = contents.decode('utf-8-sig')
        if Path(uploaded.filename).suffix.lower() == '.csv':
          inventory = dict(csv_scope_inventory(scope_content), display_name=request.form['program_name'].strip())
          if inventory['manual_only']:
              create_manual_program(slug, scope_content, guidelines, inventory, root=ROOT)
              return jsonify({'status': 'manual_review', 'program': slug, 'jobs': [],
                                'eligible_assets': sum(inventory['eligible_asset_types'].values()),
                                'message': 'Manual-only inventory created; no scans queued'}), 202
        _, targets = parse_scope(uploaded.filename, scope_content)
        jobs = create_program(slug, targets, root=ROOT, guidelines=guidelines)
    except (UnicodeDecodeError, ValueError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except FileExistsError:
        return jsonify({'status': 'error', 'message': 'Program already exists'}), 409

    command = [sys.executable, str(ROOT / 'automation' / 'worker.py'), '--program', slug]
    subprocess.Popen(command, cwd=str(ROOT), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return jsonify({'status': 'pending_review', 'program': slug, 'targets': len(targets), 'jobs': jobs}), 202


@app.route('/programs/<slug>/guidelines')
def program_guidelines(slug: str):
    if not _authorized_for_state_change():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
    if not _program_exists(slug):
        return jsonify({'status': 'error', 'message': 'Program not found'}), 404
    try:
        text, digest = read_guidelines(slug, root=ROOT)
    except (OSError, ValueError):
        return jsonify({'status': 'error', 'message': 'Guidelines unavailable'}), 404
    return jsonify({'program': slug, 'text': text, 'guidelines_sha256': digest,
                    'approved': active_approved(slug, root=ROOT)})


@app.route('/programs/<slug>/analysis')
def manual_program_analysis(slug: str):
    if not _authorized_for_state_change():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
    try:
        analysis = load_manual_analysis(slug, root=ROOT)
    except (OSError, ValueError):
        return jsonify({'status': 'error', 'message': 'Program analysis unavailable'}), 404
    check_path = RESULTS_DIR / f'manual-url-check-{slug}.json'
    if check_path.exists():
      try:
        analysis['url_check'] = json.loads(check_path.read_text(encoding='utf-8'))
      except (OSError, ValueError):
        analysis['url_check'] = None
    else:
      analysis['url_check'] = None
    analysis['approved'] = active_approved(slug, root=ROOT)
    return jsonify(analysis)


@app.route('/programs/<slug>/active-approval', methods=['POST'])
def approve_program_active(slug: str):
    if not _authorized_for_state_change():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
    if not _program_exists(slug):
        return jsonify({'status': 'error', 'message': 'Program not found'}), 404
    data = request.get_json(silent=True) or {}
    if data.get('acknowledged') is not True or type(data.get('approved')) is not bool:
        return jsonify({'status': 'error', 'message': 'Rules review and explicit decision required'}), 400
    try:
        set_active_approval(slug, data['approved'], data.get('guidelines_sha256', ''), root=ROOT)
    except (OSError, ValueError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 409
    started = False
    manual_program = (ROOT / 'programs' / slug / 'scope-inventory.json').is_file()
    manual_jobs = []
    if data['approved'] and manual_program:
      from manual_workflow import queue_manual_workflow
      manual_jobs = queue_manual_workflow(slug, root=ROOT)
    if data['approved'] and not manual_program and os.environ.get('BUGBOUNTY_ALLOW_ACTIVE', '').strip().lower() in {'1', 'true', 'yes', 'on'}:
        subprocess.Popen([sys.executable, str(ROOT / 'automation' / 'worker.py'), '--program', slug, '--allow-active'],
                         cwd=str(ROOT), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
        started = True
    return jsonify({'status': 'approved' if data['approved'] else 'revoked', 'active_run_started': started,
            'manual_jobs': manual_jobs})


def _program_exists(slug: str) -> bool:
    return ((JOBS_DIR / 'generated' / f'{slug}-passive-web-discovery.yaml').is_file()
            or (ROOT / 'programs' / slug / 'scope-inventory.json').is_file())


@app.route('/programs/<slug>/url-check', methods=['POST'])
def start_manual_url_check(slug: str):
    if not _authorized_for_state_change():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
    if not (ROOT / 'programs' / slug / 'scope-inventory.json').is_file():
        return jsonify({'status': 'error', 'message': 'Manual program not found'}), 404
    try:
        analysis = load_manual_analysis(slug, root=ROOT)
    except (OSError, ValueError):
        return jsonify({'status': 'error', 'message': 'Program analysis unavailable'}), 404
    if analysis['policy']['automated_requests'] != 'manual_approval_required':
        return jsonify({'status': 'error', 'message': analysis['policy']['reason']}), 409
    if not active_approved(slug, root=ROOT):
        return jsonify({'status': 'error', 'message': 'Review the current guidelines and explicitly approve these exact-URL checks first'}), 409
    if _lock_is_active(f'manual-url-check-{slug}') or _lock_is_active(f'manual-program-{slug}'):
        return jsonify({'status': 'error', 'message': 'URL check already running'}), 409
    try:
      process = subprocess.Popen([sys.executable, str(ROOT / 'automation' / 'manual_url_checker.py'), slug],
                     cwd=str(ROOT), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError as exc:
        return jsonify({'status': 'error', 'message': f'Could not start URL check: {exc}'}), 500
    return jsonify({'status': 'running', 'pid': process.pid, 'requests_per_second': 1,
            'method': 'HEAD', 'targets': analysis['eligible_urls'],
            'skipped_query_urls': sum(1 for asset in analysis['assets'] if asset['query_present'])}), 202


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
