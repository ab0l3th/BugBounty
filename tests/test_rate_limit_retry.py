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

    def test_candidate_sources_skips_failing_sources(self):
        with patch('passive_dns_enrichment.crt_sh_candidates', side_effect=TimeoutError('slow upstream')):
            with patch('passive_dns_enrichment.dns_google_candidates', return_value={'api.example.com'}):
                with patch('passive_dns_enrichment.certspotter_candidates', return_value={'www.example.com'}):
                    with patch('passive_dns_enrichment.hackertarget_candidates', return_value={'mail.example.com'}):
                        sources = passive_dns_enrichment.candidate_sources('example.com')

        self.assertEqual(sources['dns.google'], {'api.example.com'})
        self.assertEqual(sources['certspotter'], {'www.example.com'})
        self.assertEqual(sources['hackertarget'], {'mail.example.com'})
        self.assertNotIn('crt.sh', sources)


if __name__ == '__main__':
    unittest.main()
