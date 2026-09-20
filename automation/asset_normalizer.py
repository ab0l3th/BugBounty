#!/usr/bin/env python3
from __future__ import annotations

import re
from typing import Iterable, List, Set, Tuple

DOMAIN_RE = re.compile(r'(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])\.)+[a-z]{2,}\b')


def normalize_host(host: str) -> str:
    value = host.strip().lower().rstrip('.')
    if not value:
        return ''
    if value.startswith('http://'):
        value = value.split('://', 1)[1]
    if value.startswith('https://'):
        value = value.split('://', 1)[1]
    if '/' in value:
        value = value.split('/', 1)[0]
    return value


def extract_domains(text: str) -> Set[str]:
    return {normalize_host(match) for match in DOMAIN_RE.findall(text)}


def normalize_assets(raw_hosts: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for host in raw_hosts:
        candidate = normalize_host(str(host))
        if not candidate:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        ordered.append(candidate)
    return sorted(ordered)


def filter_scope(hosts: Iterable[str], patterns: Iterable[str]) -> List[str]:
    allowed = list(patterns)
    in_scope: List[str] = []
    for host in normalize_assets(hosts):
        if host == '':
            continue
        ok = False
        for pattern in allowed:
            normalized = normalize_host(pattern)
            if normalized == host:
                ok = True
                break
            if normalized.startswith('*.'):
                suffix = normalized[2:]
                if host.endswith('.' + suffix) or host == suffix:
                    ok = True
                    break
            elif host.endswith('.' + normalized) or host == normalized:
                ok = True
                break
        if ok:
            in_scope.append(host)
    return sorted(set(in_scope))
