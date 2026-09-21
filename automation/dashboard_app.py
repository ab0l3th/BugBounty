#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, render_template_string

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / 'results'
RUNNING_DIR = RESULTS_DIR / '.running'
JOBS_DIR = ROOT / 'jobs'

app = Flask(__name__)


def _job_state_for(job_name: str, payload: Dict[str, Any] | None = None) -> str:
    if RUNNING_DIR.exists() and (RUNNING_DIR / f'{job_name}.lock').exists():
        return 'running'
    if payload and payload.get('job_state') == 'completed':
        return 'completed'
    if payload and payload.get('status') in {'ok', 'no_new_assets', 'no_in_scope_targets'}:
        return 'completed'
    return 'queued'


def summarize_jobs(jobs: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {'total': len(jobs), 'queued': 0, 'running': 0, 'completed': 0}
    for job in jobs:
        state = job.get('job_state', 'queued')
        if state in summary:
            summary[state] += 1
    return summary


def read_result_file(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return {}


def list_jobs() -> List[Dict[str, Any]]:
    jobs: List[Dict[str, Any]] = []
    seen: set[str] = set()

    if JOBS_DIR.exists():
        for path in sorted(JOBS_DIR.glob('*.yaml')) + sorted(JOBS_DIR.glob('*.yml')):
            job_name = path.stem
            seen.add(job_name)
            payload = read_result_file(RESULTS_DIR / f'{job_name}.json')
            job_state = _job_state_for(job_name, payload if payload else None)
            if payload:
                assets = payload.get('assets') or [
                    {'domain': host, 'status': 'in_scope', 'sources': [], 'source': ''}
                    for host in payload.get('discovered', [])
                ]
                jobs.append({
                    'name': payload.get('job', job_name),
                    'path': path.name,
                    'status': payload.get('status', 'unknown'),
                    'job_state': job_state,
                    'type': payload.get('type', 'unknown'),
                    'program': payload.get('program', 'unknown'),
                    'discovered': payload.get('discovered', []),
                    'assets': assets,
                    'targets': payload.get('targets', []),
                    'queued': payload.get('queued', []),
                    'skipped': payload.get('skipped', []),
                    'source_count': payload.get('source_count', 0),
                    'raw': payload,
                })
            else:
                jobs.append({
                    'name': job_name,
                    'path': path.name,
                    'status': 'queued',
                    'job_state': 'queued',
                    'type': 'passive',
                    'program': 'unknown',
                    'discovered': [],
                    'assets': [],
                    'targets': [],
                    'queued': [],
                    'skipped': [],
                    'source_count': 0,
                    'raw': {'job': job_name, 'job_state': 'queued'},
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
            'raw': payload,
        })
    return sorted(jobs, key=lambda item: item['name'])


@app.route('/')
def index():
    jobs = list_jobs()
    summary = summarize_jobs(jobs)
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
        .job { margin-bottom: 18px; padding: 0; background: #0f172a; border-left: 4px solid #38bdf8; border-radius: 8px; overflow: hidden; }
        summary { list-style: none; cursor: pointer; padding: 16px; display: block; }
        summary::-webkit-details-marker { display: none; }
        .job-header { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
        .job-content { padding: 0 16px 16px; }
        .status { display: inline-block; padding: 4px 8px; border-radius: 999px; font-size: 12px; font-weight: bold; }
        .ok { background: #14532d; color: #dcfce7; }
        .warn { background: #78350f; color: #fef3c7; }
        .bad { background: #7f1d1d; color: #fee2e2; }
        ul { margin: 10px 0 0 20px; }
        code { background: #0b1120; border-radius: 4px; padding: 2px 6px; }
        a { color: #7dd3fc; }
        .evidence-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
        .evidence-item { background: #111827; border: 1px solid #334155; border-radius: 6px; padding: 6px 8px; }
        .evidence-item a { text-decoration: none; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; vertical-align: top; padding: 8px; border-bottom: 1px solid #334155; }
        @media (max-width: 640px) {
          body { padding: 16px; }
          .summary-row { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
          .pill strong { font-size: 22px; }
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
        <h1>BugBounty Dashboard</h1>
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
          {% for job in jobs %}
            <details class="job">
              <summary>
                <div class="job-header">
                  <h2>{{ job.name }}</h2>
                  <div class="status {{ 'ok' if job.job_state == 'completed' else 'warn' if job.job_state == 'running' else 'bad' }}">{{ job.job_state }}</div>
                </div>
              </summary>
              <div class="job-content">
                <p><strong>Program:</strong> {{ job.program }}</p>
                <p><strong>Type:</strong> {{ job.type }}</p>
                <p><strong>Pipeline status:</strong> {{ job.status }}</p>
                <p><strong>Source count:</strong> {{ job.source_count }}</p>
                <p><strong>Targets:</strong> {{ job.targets|length }}</p>
                <p><strong>Discovered:</strong> {{ job.discovered|length }}</p>

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

                <h3>In-scope targets</h3>
                <ul>
                  {% for item in job.targets %}
                    <li><code>{{ item }}</code></li>
                  {% endfor %}
                </ul>

                <h3>Queued</h3>
                <ul>
                  {% for item in job.queued %}
                    <li><code>{{ item }}</code></li>
                  {% endfor %}
                </ul>
                {% if job.skipped %}
                  <h3>Skipped</h3>
                  <ul>
                    {% for item in job.skipped %}
                      <li><code>{{ item }}</code></li>
                    {% endfor %}
                  </ul>
                {% endif %}
              </div>
            </details>
          {% endfor %}
        {% else %}
          <div class="card">
            <p>No result files have been generated yet.</p>
            <p>Run the worker and a result file will appear in <code>results/</code>.</p>
          </div>
        {% endif %}
      </div>
    </body>
    </html>
    ''', jobs=jobs, summary=summary)


@app.route('/api/jobs')
def api_jobs():
    return jsonify(list_jobs())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BugBounty LAN dashboard')
    parser.add_argument('--port', type=int, default=8001, help='Port to bind for the local LAN UI')
    parser.add_argument('--host', default='0.0.0.0', help='Host interface to bind')
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=False)
