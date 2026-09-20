#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path


def send(webhook: str, job: str, payload: dict) -> None:
    body = json.dumps({
        'event': 'bugbounty_result_change',
        'job': job,
        'payload': payload,
    }).encode('utf-8')

    request = urllib.request.Request(
        webhook,
        data=body,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(request, timeout=15) as resp:
        resp.read()


if __name__ == '__main__':
    webhook = os.environ.get('BUGBOUNTY_WEBHOOK_URL')
    if not webhook:
        raise SystemExit('BUGBOUNTY_WEBHOOK_URL is not set.')

    job = os.environ.get('BUGBOUNTY_JOB', 'manual')
    payload = json.loads(Path(os.environ.get('BUGBOUNTY_PAYLOAD_FILE', '/tmp/bugbounty-result.json')).read_text())
    send(webhook, job, payload)
