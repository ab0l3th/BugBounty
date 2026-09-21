import json
import unittest
from pathlib import Path
from unittest.mock import patch

import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'automation') not in sys.path:
    sys.path.insert(0, str(ROOT / 'automation'))

import github_monitor


class GitHubMonitorTest(unittest.TestCase):
    def test_parse_commits_creates_activity_summary(self):
        payload = [
            {
                'sha': 'abc123',
                'commit': {'message': 'Fix dashboard grouping', 'author': {'date': '2026-09-20T12:00:00Z'}},
                'author': {'login': 'ab0l3th'},
                'html_url': 'https://github.com/ab0l3th/BugBounty/commit/abc123',
            },
            {
                'sha': 'def456',
                'commit': {'message': 'Add GitHub monitor', 'author': {'date': '2026-09-20T13:00:00Z'}},
                'author': {'login': 'ab0l3th'},
                'html_url': 'https://github.com/ab0l3th/BugBounty/commit/def456',
            },
        ]

        with patch('github_monitor.fetch_url', return_value=json.dumps(payload)):
            result = github_monitor.github_activity('ab0l3th/BugBounty')

        self.assertEqual(result['job'], 'github-monitor')
        self.assertEqual(result['program'], 'github')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(len(result['discovered']), 2)
        self.assertEqual(result['discovered'][0], 'abc123')


if __name__ == '__main__':
    unittest.main()
