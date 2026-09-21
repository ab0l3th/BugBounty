#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any
from urllib import request


def fetch_url(url: str, timeout: int = 20) -> str:
    headers = {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'BugBountyPassiveRecon/1.0',
    }
    req = request.Request(url, headers=headers)
    with request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='replace')


def github_activity(repo: str = 'ab0l3th/BugBounty') -> dict[str, Any]:
    repo = (repo or 'ab0l3th/BugBounty').strip()
    url = f'https://api.github.com/repos/{repo}/commits?per_page=10'
    payload = fetch_url(url)
    try:
        rows = json.loads(payload)
    except Exception:
        rows = []

    discovered: list[str] = []
    assets: list[dict[str, Any]] = []
    for item in rows if isinstance(rows, list) else []:
        if not isinstance(item, dict):
            continue
        sha = item.get('sha') or item.get('id')
        message = (item.get('commit') or {}).get('message', 'No message').split('\n', 1)[0]
        author = (item.get('author') or {}).get('login') or 'unknown'
        timestamp = ((item.get('commit') or {}).get('author') or {}).get('date') or 'unknown'
        html_url = item.get('html_url') or f'https://github.com/{repo}/commit/{sha}'
        if sha:
            discovered.append(sha)
            assets.append({
                'domain': sha,
                'status': 'active',
                'source': 'github',
                'sources': ['github'],
                'source_count': 1,
                'evidence': [{
                    'source': 'github',
                    'url': html_url,
                    'message': message,
                    'author': author,
                    'timestamp': timestamp,
                }],
            })

    result = {
        'job': 'github-monitor',
        'program': 'github',
        'type': 'github',
        'targets': [repo],
        'queued': [repo],
        'skipped': [],
        'status': 'ok' if discovered else 'no_activity',
        'discovered': discovered,
        'assets': assets,
        'source_count': 1 if discovered else 0,
    }
    return result


if __name__ == '__main__':
    print(json.dumps(github_activity(), indent=2))
