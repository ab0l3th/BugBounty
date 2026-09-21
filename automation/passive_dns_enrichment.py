#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Set
from urllib import request
from urllib.error import HTTPError

from asset_normalizer import extract_domains, filter_scope, normalize_assets
from scope_validator import is_in_scope, parse_scope_pattern

ROOT = Path(__file__).resolve().parent.parent
PROGRAMS_DIR = ROOT / 'programs'


def load_allowed_patterns(program_name: str) -> List[str]:
    scope_path = PROGRAMS_DIR / program_name / 'scope.md'
    if not scope_path.exists():
        return []
    result: List[str] = []
    for line in scope_path.read_text(encoding='utf-8').splitlines():
        item = line.strip()
        if item.startswith('- '):
            value = parse_scope_pattern(item[2:].strip())
            if value:
                result.append(value)
    return result


def fetch_url(url: str, timeout: int = 8, retries: int = 2) -> str:
    headers = {'User-Agent': 'BugBountyPassiveRecon/1.0'}
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            req = request.Request(url, headers=headers)
            with request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode('utf-8', errors='replace')
        except HTTPError as exc:
            last_error = exc
            if exc.code not in {429, 500, 502, 503, 504}:
                break
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            break
        except Exception as exc:
            last_error = exc
            break
    return ''


def crt_sh_candidates(domain: str) -> Set[str]:
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    data = fetch_url(url)
    if not data:
        return set()
    try:
        payload = json.loads(data)
    except Exception:
        return set()
    found: Set[str] = set()
    for entry in payload:
        for key in ('name_value', 'common_name'):
            value = entry.get(key)
            if not value:
                continue
            found |= extract_domains(str(value))
    return found


def dns_google_candidates(domain: str) -> Set[str]:
    url = f'https://dns.google/resolve?name={domain}&type=A'
    data = fetch_url(url)
    if not data:
        return set()
    try:
        payload = json.loads(data)
    except Exception:
        return set()
    answers = payload.get('Answer', [])
    found: Set[str] = set()
    for item in answers:
        if isinstance(item, dict):
            name = item.get('name')
            if name:
                found |= extract_domains(str(name))
        elif isinstance(item, str):
            found |= extract_domains(item)
    return found


def certspotter_candidates(domain: str) -> Set[str]:
    url = f'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names'
    data = fetch_url(url)
    if not data:
        return set()
    try:
        payload = json.loads(data)
    except Exception:
        return set()
    found: Set[str] = set()
    for item in payload:
        dns_names = item.get('dns_names', []) if isinstance(item, dict) else []
        if isinstance(dns_names, list):
            for name in dns_names:
                found |= extract_domains(str(name))
    return found


def hackertarget_candidates(domain: str) -> Set[str]:
    url = f'https://api.hackertarget.com/hostsearch/?q={domain}'
    data = fetch_url(url)
    if not data:
        return set()
    found: Set[str] = set()
    for line in data.splitlines():
        if not line.strip() or ',' not in line:
            continue
        candidate = line.split(',', 1)[0].strip()
        if candidate:
            found |= extract_domains(candidate)
    return found


def source_urls(domain: str) -> Dict[str, str]:
    return {
        'crt.sh': f'https://crt.sh/?q=%25.{domain}&output=json',
        'dns.google': f'https://dns.google/resolve?name={domain}&type=A',
        'certspotter': f'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names',
        'hackertarget': f'https://api.hackertarget.com/hostsearch/?q={domain}',
    }


def candidate_sources(domain: str) -> Dict[str, Set[str]]:
    sources: Dict[str, Set[str]] = {}
    source_factories = [
        ('certspotter', certspotter_candidates),
        ('hackertarget', hackertarget_candidates),
        ('crt.sh', crt_sh_candidates),
        ('dns.google', dns_google_candidates),
    ]
    for name, builder in source_factories:
        try:
            candidates = builder(domain)
        except Exception:
            continue
        if candidates:
            sources[name] = candidates
    return sources


def passive_dns_enrichment(program_name: str) -> Dict[str, object]:
    patterns = load_allowed_patterns(program_name)
    if not patterns:
        return {
            'job': f'{program_name}-passive-dns',
            'type': 'passive',
            'program': program_name,
            'targets': [],
            'discovered': [],
            'assets': [],
            'status': 'no_scope',
            'source_count': 0,
        }

    seen: Dict[str, set[str]] = {}
    for pattern in patterns:
        domain = pattern[2:] if pattern.startswith('*.') else pattern
        if not domain:
            continue
        for source_name, candidates in candidate_sources(domain).items():
            for candidate in candidates:
                if not candidate or not is_in_scope(candidate, patterns):
                    continue
                seen.setdefault(candidate, set()).add(source_name)

    discovered = normalize_assets(seen.keys())
    assets = []
    for host in discovered:
        sources = sorted(seen.get(host, set()))
        evidence = []
        for source in sources:
            evidence.append({
                'source': source,
                'url': source_urls(host).get(source, ''),
            })
        assets.append({
            'domain': host,
            'status': 'in_scope',
            'source': ', '.join(sources),
            'sources': sources,
            'source_count': len(sources),
            'evidence': evidence,
        })

    return {
        'job': f'{program_name}-passive-dns',
        'type': 'passive',
        'program': program_name,
        'targets': patterns,
        'discovered': discovered,
        'assets': assets,
        'status': 'ok' if discovered else 'no_new_assets',
        'source_count': len({s for row in assets for s in row['sources']}),
    }


if __name__ == '__main__':
    print(json.dumps(passive_dns_enrichment('american-airlines'), indent=2))
