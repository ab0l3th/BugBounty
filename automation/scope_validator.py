from __future__ import annotations

import fnmatch
from typing import Iterable, List


def normalize_domain(domain: str) -> str:
    return domain.strip().strip("'\"").lower().rstrip('.')


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
            scope.append(value)
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
