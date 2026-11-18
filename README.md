# PhishGuard AI — Intelligent Phishing URL Detection & Cyber Threat Analysis Platform

PhishGuard AI is an AI-powered cybersecurity web application that statically inspects website URLs to detect phishing and malicious links, provides human-readable Explainable AI findings, visualizes threat analytics, and maintains an audit-ready SQLite scan history.

## Key Features
- **Zero-Execution Static Analysis (SSRF-Safe):** Evaluates 13 lexical and structural URL features without ever making outbound requests to untrusted links.
- **Multi-Model ML Pipeline:** Trains and benchmarks Logistic Regression, Decision Tree, and Random Forest classifiers using Scikit-learn, prioritizing high Recall to minimize dangerous false negatives.
- **Explainable AI Findings:** Breaks down every prediction into clear security indicators (e.g., raw IPv4 usage, `@` symbol obfuscation, URL shorteners, excessive subdomains, suspicious keywords).
- **Interactive Cybersecurity Dashboard:** Real-time threat statistics, Chart.js distribution visualizations, searchable SQLite scan logs, and model performance benchmarks.
- **Privacy-First Sanitization:** Strips sensitive query strings and credentials from URLs before persisting records to SQLite.

## Project Architecture
```text
PhishGuard-AI/
├── app/
│   ├── main.py                 # Flask REST API & input validation
│   ├── templates/
│   │   └── index.html          # Dark-navy cybersecurity dashboard UI
│   └── static/
├── ml/
│   ├── dataset/                # Place external Kaggle URL CSVs here
│   ├── models/                 # Serialized Joblib model & evaluation report
│   ├── feature_extraction.py   # Shared 13-feature lexical extractor
│   ├── train.py                # Model comparison & serialization script
│   └── predict.py              # Inference & Explainable AI engine
├── database/
│   └── db.py                   # SQLite persistence & analytics queries
├── tests/
│   └── test_phishguard.py      # Automated unit tests
├── requirements.txt
├── .env.example
└── .gitignore
```

## Quick Start

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Train & Verify the ML Model**
   ```bash
   python -m ml.train
   ```

3. **Run Unit Tests**
   ```bash
   python -m unittest discover tests
   ```

4. **Launch the Web Application**
   ```bash
   python app/main.py
   ```
   Open `http://127.0.0.1:5000` in your browser.
