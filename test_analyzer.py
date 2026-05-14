import unittest
from display import verdict, url_verdict
from body import extract_urls
from config import DEBUG

class TestVerdict(unittest.TestCase):
    def test_true_returns_flagged(self):
        self.assertEqual(verdict(True), "FLAGGED")
    def test_false_returns_clean(self):
        self.assertEqual(verdict(False), "CLEAN")
    def test_none_returns_na(self):
        self.assertEqual(verdict(None), "N/A")

class TestUrlVerdict(unittest.TestCase):
    def test_malicious_count_returns_malicious(self):
        self.assertEqual(url_verdict(1,0), "MALICIOUS")
    def test_suspicious_count_returns_suspicious(self):
        self.assertEqual(url_verdict(0,1), "SUSPICIOUS")
    def test_clean_returns_clean(self):
        self.assertEqual(url_verdict(0,0), "CLEAN")

class TestExtractUrls(unittest.TestCase):
    def test_extracts_plain_text_url(self):
        body = {"plain": "click here http://malicious.com", "html": ""}
        result = extract_urls(body)
        self.assertIn("http://malicious.com", result)

    def test_extracts_html_text_url(self):
        body = {"plain": "", 
                "html": '<a href="http://malicious.com">click here</a>'}
        result = extract_urls(body)
        self.assertIn("http://malicious.com", result)
        
    def test_duplicate_url(self):
        body = {"plain": "click here http://malicious.com", 
                "html": '<a href="http://malicious.com">click here</a>'}
        result = extract_urls(body)
        print(result)

        self.assertEqual(len(result), 1)
