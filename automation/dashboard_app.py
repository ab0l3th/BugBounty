#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, render_template_string

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / 'results'

app = Flask(__name__)


def read_result_file(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return {}


def list_jobs() -> List[Dict[str, Any]]:
    jobs: List[Dict[str, Any]] = []
    if not RESULTS_DIR.exists():
        return jobs

    for path in sorted(RESULTS_DIR.glob('*.json')):
        if path.name.startswith('.'): 
            continue
        payload = read_result_file(path)
        if not payload:
            continue
        jobs.append({
            'name': payload.get('job', path.stem),
            'path': path.name,
            'status': payload.get('status', 'unknown'),
            'type': payload.get('type', 'unknown'),
            'discovered': payload.get('discovered', []),
            'targets': payload.get('targets', []),
            'queued': payload.get('queued', []),
            'skipped': payload.get('skipped', []),
            'raw': payload,
        })
    return jobs


@app.route('/')
def index():
    jobs = list_jobs()
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
        .job { margin-bottom: 18px; padding: 16px; background: #0f172a; border-left: 4px solid #38bdf8; border-radius: 8px; }
        .status { display: inline-block; padding: 4px 8px; border-radius: 999px; font-size: 12px; font-weight: bold; }
        .ok { background: #14532d; color: #dcfce7; }
        .warn { background: #78350f; color: #fef3c7; }
        .bad { background: #7f1d1d; color: #fee2e2; }
        ul { margin: 10px 0 0 20px; }
        code { background: #0b1120; border-radius: 4px; padding: 2px 6px; }
        a { color: #7dd3fc; }
      </style>
    </head>
    <body>
      <div class="wrap">
        <h1>BugBounty Dashboard</h1>
        {% if jobs %}
          {% for job in jobs %}
            <div class="job">
              <h2>{{ job.name }}</h2>
              <div class="status {{ 'ok' if job.status == 'ok' else 'warn' if job.status == 'no_new_assets' else 'bad' }}">{{ job.status }}</div>
              <p><strong>Type:</strong> {{ job.type }}</p>
              <p><strong>Targets:</strong> {{ job.targets|length }}</p>
              <p><strong>Discovered:</strong> {{ job.discovered|length }}</p>
              <h3>In-scope targets</h3>
              <ul>
                {% for item in job.targets %}
                  <li><code>{{ item }}</code></li>
                {% endfor %}
              </ul>
              <h3>Discovered assets</h3>
              <ul>
                {% for item in job.discovered %}
                  <li><code>{{ item }}</code></li>
                {% else %}
                  <li>No newly discovered assets.</li>
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
    ''', jobs=jobs)


@app.route('/api/jobs')
def api_jobs():
    return jsonify(list_jobs())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BugBounty LAN dashboard')
    parser.add_argument('--port', type=int, default=8001, help='Port to bind for the local LAN UI')
    parser.add_argument('--host', default='0.0.0.0', help='Host interface to bind')
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=False)
