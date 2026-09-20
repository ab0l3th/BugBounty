#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Iterable, List, Set
from urllib import request

ROOT = Path(__file__).resolve().parent.parent
AUTOMATION_DIR = Path(__file__).resolve().parent
if str(AUTOMATION_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOMATION_DIR))

from scope_validator import is_in_scope, parse_scope_pattern

SCOPE_FILE = ROOT / 'programs' / 'american-airlines' / 'scope.md'


def load_allowed_domains() -> List[str]:
    rows: List[str] = []
    if not SCOPE_FILE.exists():
        return rows
    for line in SCOPE_FILE.read_text(encoding='utf-8').splitlines():
        value = line.strip()
        if value.startswith('- '):
            pattern = parse_scope_pattern(value[2:].strip())
            if pattern:
                rows.append(pattern)
    return rows


def fetch_url(url: str, timeout: int = 15) -> str:
    try:
        with request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='replace')
    except Exception:
        return ''


def extract_domains(text: str) -> Set[str]:
    pattern = re.compile(r'(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b')
    matches = set(pattern.findall(text))
    return {m.lower() for m in matches}


def filter_scope(domains: Iterable[str], allowed_patterns: Iterable[str]) -> List[str]:
    in_scope: List[str] = []
    for domain in sorted(set(domains)):
        if is_in_scope(domain, allowed_patterns):
            in_scope.append(domain)
    return in_scope


def public_sources_for(domain: str) -> List[str]:
    return [
        f'https://crt.sh/?q=%25.{domain}&output=json',
        f'https://www.google.com/search?q=site%3A{domain}',
        f'https://dns.google/resolve?name={domain}&type=A',
    ]


def source_label_for(url: str) -> str:
    lowered = url.lower()
    if 'crt.sh' in lowered:
        return 'crt.sh'
    if 'google' in lowered and 'search' in lowered:
        return 'google-search'
    if 'dns.google' in lowered:
        return 'dns.google'
    if 'https://' in lowered:
        return url.split('://', 1)[1].split('/', 1)[0]
    return 'public-source'


def discover_passive_assets(domain: str) -> List[str]:
    observed: Set[str] = set()
    for url in public_sources_for(domain):
        data = fetch_url(url)
        if not data:
            continue
        observed |= extract_domains(data)
    return sorted(observed)


def build_job_output() -> dict:
    allowed = load_allowed_domains()
    evidence_by_host: dict[str, list[dict]] = {}
    source_by_host: dict[str, set[str]] = {}
    all_found: Set[str] = set()
    for domain in allowed:
        if domain.startswith('*.'):
            base = domain[2:]
        else:
            base = domain
        for url in public_sources_for(base):
            data = fetch_url(url)
            if not data:
                continue
            for found in extract_domains(data):
                if not is_in_scope(found, allowed):
                    continue
                all_found.add(found)
                label = source_label_for(url)
                source_by_host.setdefault(found, set()).add(label)
                evidence_by_host.setdefault(found, []).append({'source': label, 'url': url})

    filtered = filter_scope(all_found, allowed)
    assets = []
    for host in filtered:
        sources = sorted(source_by_host.get(host, set()))
        evidence = evidence_by_host.get(host, [])
        assets.append({
            'domain': host,
            'status': 'in_scope',
            'source': ', '.join(sources),
            'sources': sources,
            'source_count': len(sources),
            'evidence': evidence,
        })

    return {
        'job': 'aa-passive-discovery',
        'type': 'passive',
        'targets': allowed,
        'discovered': sorted(filtered),
        'assets': assets,
        'status': 'ok' if filtered else 'no_new_assets',
        'source_count': len({source for item in assets for source in item.get('sources', [])}),
    }


if __name__ == '__main__':
    print(json.dumps(build_job_output(), indent=2))
