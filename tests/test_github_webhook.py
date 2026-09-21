import hashlib
import hmac
import unittest

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'automation') not in sys.path:
    sys.path.insert(0, str(ROOT / 'automation'))

import dashboard_app


class GithubWebhookSignatureTest(unittest.TestCase):
    def test_verify_signature_accepts_valid_sha256(self):
        secret = 'test-secret'
        body = b'{"ref":"refs/heads/main","zen":"keep it logically awesome"}'
        sig = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        self.assertTrue(dashboard_app.verify_github_signature(body, sig, secret))

    def test_verify_signature_rejects_invalid_sha256(self):
        secret = 'test-secret'
        body = b'{"ref":"refs/heads/main"}'
        self.assertFalse(dashboard_app.verify_github_signature(body, 'sha256=deadbeef', secret))


if __name__ == '__main__':
    unittest.main()
