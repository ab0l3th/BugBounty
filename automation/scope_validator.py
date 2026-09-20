from __future__ import annotations

import fnmatch
from typing import Iterable, List, Optional


def normalize_domain(domain: str) -> str:
    return domain.strip().strip("'\"").lower().rstrip('.')


def parse_scope_pattern(value: str) -> Optional[str]:
    """Accept only domain-like entries from the scope file and ignore prose."""
    candidate = normalize_domain(value)
    if not candidate:
        return None

    if candidate.startswith('*.'):
        suffix = candidate[2:]
    elif candidate.startswith('*'):
        suffix = candidate[1:]
    else:
        suffix = candidate

    if not suffix or '.' not in suffix:
        return None
    if suffix.startswith('.') or suffix.endswith('.'):
        return None
    if any(ch in suffix for ch in (' ', '/', '\\', ':', '@', '?', '#')):
        return None
    if '*' in suffix:
        return None

    labels = suffix.split('.')
    if len(labels) < 2:
        return None
    for label in labels:
        if not label or label.startswith('-') or label.endswith('-'):
            return None
        if any(ch not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for ch in label):
            return None

    if value.startswith('*.'):
        return f'*.{suffix}'
    if value.startswith('*'):
        return suffix
    return suffix


def is_in_scope(candidate: str, allowed_patterns: Iterable[str]) -> bool:
    """Return True if a candidate matches any in-scope wildcard or exact domain."""
    normalized = normalize_domain(candidate)
    for pattern in allowed_patterns:
        allowed = normalize_domain(pattern)
        if allowed == normalized:
            return True
        if '*' in allowed:
            if fnmatch.fnmatch(normalized, allowed):
                return True
        elif normalized.endswith('.' + allowed):
            return True
    return False


def load_scope(scope_file: List[str]) -> List[str]:
    scope = []
    for line in scope_file:
        value = line.strip()
        if value and not value.startswith('#'):
            parsed = parse_scope_pattern(value)
            if parsed:
                scope.append(parsed)
    return scope


if __name__ == '__main__':
    samples = [
        'www.aa.com',
        'api.aa.com',
        'foo.example.com',
    ]
    scope = ['*.aa.com', '*.cloud.aa.com', 'aavacations.com']
    for sample in samples:
        print(f'{sample}: {is_in_scope(sample, scope)}')
