import os
import json
import joblib
import numpy as np
from ml.feature_extraction import extract_url_features, features_to_vector

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'phishguard_model.joblib')
REPORT_PATH = os.path.join(os.path.dirname(__file__), 'models', 'evaluation_report.json')

class PhishGuardPredictor:
    def __init__(self):
        if not os.path.exists(MODEL_PATH):
            from ml.train import train_and_evaluate
            train_and_evaluate()
        artifact = joblib.load(MODEL_PATH)
        self.model = artifact["model"]
        self.model_name = artifact["model_name"]

    def get_evaluation_report(self):
        if os.path.exists(REPORT_PATH):
            with open(REPORT_PATH, 'r') as f:
                return json.load(f)
        return {}

    def generate_explanations(self, features: dict) -> list:
        reasons = []
        if features['has_ip_address'] == 1:
            reasons.append({"severity": "high", "text": "Raw IPv4 address used instead of a registered domain name."})
        if features['has_at_symbol'] == 1:
            reasons.append({"severity": "high", "text": "Contains '@' symbol, commonly used to obscure the actual destination host."})
        if features['is_shortened'] == 1:
            reasons.append({"severity": "medium", "text": "Uses a URL shortening service that masks the final landing page."})
        if features['has_unusual_port'] == 1:
            reasons.append({"severity": "high", "text": "Specifies a non-standard network port outside standard HTTP/HTTPS (80/443)."})
        if features['suspicious_keyword_count'] >= 1:
            reasons.append({"severity": "medium", "text": f"Detected {features['suspicious_keyword_count']} high-risk credential/security keyword(s) in URL."})
        if features['url_length'] > 75:
            reasons.append({"severity": "medium", "text": f"Unusually long URL ({features['url_length']} characters), often used to hide malicious parameters."})
        if features['num_hyphens'] >= 3:
            reasons.append({"severity": "medium", "text": f"Excessive hyphens ({features['num_hyphens']}) detected, typical of domain spoofing."})
        if features['num_subdomains'] >= 3:
            reasons.append({"severity": "medium", "text": f"Deep subdomain nesting ({features['num_subdomains']} levels) imitating legitimate brands."})
        if features['has_https'] == 0:
            reasons.append({"severity": "low", "text": "Connection lacks HTTPS encryption."})

        if not reasons:
            reasons.append({"severity": "safe", "text": "Clean domain structure with standard length, valid HTTPS, and no lexical anomalies."})
        return reasons

    def analyze_url(self, url: str) -> dict:
        features = extract_url_features(url)
        vector = np.array([features_to_vector(features)])
        phishing_prob = float(self.model.predict_proba(vector)[0][1])

        if phishing_prob >= 0.70:
            classification = "Malicious / Phishing"
            risk_level = "high"
        elif phishing_prob >= 0.35:
            classification = "Suspicious"
            risk_level = "medium"
        else:
            classification = "Safe / Legitimate"
            risk_level = "low"

        explanations = self.generate_explanations(features)

        return {
            "url": url,
            "classification": classification,
            "risk_level": risk_level,
            "model_score": round(phishing_prob * 100, 1),
            "model_used": self.model_name,
            "features": features,
            "explanations": explanations,
            "disclaimer": "Prediction reflects lexical ML probability—not live domain reputation or external threat intelligence."
        }
