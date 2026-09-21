import sys
import unittest
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'automation') not in sys.path:
    sys.path.insert(0, str(ROOT / 'automation'))

import passive_dns_enrichment


class RateLimitRetryTest(unittest.TestCase):
    def test_fetch_url_retries_after_http_429(self):
        class MockResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, *_args, **_kwargs):
                return b'hello'

        response = MockResponse()
        err = HTTPError('https://example.com', 429, 'Too Many Requests', hdrs=None, fp=None)

        with patch('passive_dns_enrichment.request.urlopen', side_effect=[err, response]) as mock_urlopen:
            result = passive_dns_enrichment.fetch_url('https://example.com', timeout=5)

        self.assertEqual(result, 'hello')
        self.assertEqual(mock_urlopen.call_count, 2)


if __name__ == '__main__':
    unittest.main()
