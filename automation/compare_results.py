#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / 'results'
STATE_DIR = RESULTS_DIR / '.state'


def load_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def diff(current: dict, previous: dict) -> dict:
    return {
        'added': sorted(set(current.get('discovered', [])) - set(previous.get('discovered', []))),
        'removed': sorted(set(previous.get('discovered', [])) - set(current.get('discovered', []))),
        'current_count': len(current.get('discovered', [])),
        'previous_count': len(previous.get('discovered', [])),
    }


def main() -> None:
    current_path = RESULTS_DIR / 'aa-passive-discovery.json'
    previous_path = STATE_DIR / 'aa-passive-discovery.json'
    current = load_json(current_path)
    previous = load_json(previous_path)
    if current is None:
        raise SystemExit('No current results available.')
    if previous is None:
        print(json.dumps({'status': 'initial', 'current': current}, indent=2))
        return
    print(json.dumps(diff(current, previous), indent=2))


if __name__ == '__main__':
    main()
