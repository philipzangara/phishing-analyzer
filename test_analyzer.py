import unittest
from phishing_analyzer import verdict, url_verdict

class TestVerdict(unittest.TestCase):
    def test_true_returns_flagged(self):
        self.assertEqual(verdict(True), "FLAGGED")