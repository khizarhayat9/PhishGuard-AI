import unittest
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml.feature_extraction import extract_url_features
from ml.predict import PhishGuardPredictor

class TestPhishGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.predictor = PhishGuardPredictor()

    def test_feature_extraction_ip(self):
        feats = extract_url_features("http://192.168.1.1/login")
        self.assertEqual(feats["has_ip_address"], 1)
        self.assertEqual(feats["has_https"], 0)
        self.assertGreaterEqual(feats["suspicious_keyword_count"], 1)

    def test_legitimate_prediction(self):
        res = self.predictor.analyze_url("https://github.com/scikit-learn/scikit-learn")
        self.assertEqual(res["risk_level"], "low")

    def test_phishing_prediction(self):
        res = self.predictor.analyze_url("http://192.168.1.45/paypal/login/verify-account.php")
        self.assertEqual(res["risk_level"], "high")

if __name__ == "__main__":
    unittest.main()
