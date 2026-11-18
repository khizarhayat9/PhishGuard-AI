import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)
from ml.feature_extraction import extract_url_features, features_to_vector, FEATURE_NAMES

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

def build_training_dataframe(csv_path=None):
    """Loads a Kaggle CSV (columns: 'url', 'label') or generates a representative seed dataset."""
    if csv_path and os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        return df[['url', 'label']]

    legit_urls = [
        "https://www.google.com/search?q=machine+learning",
        "https://github.com/scikit-learn/scikit-learn",
        "https://www.wikipedia.org/wiki/Cybersecurity",
        "https://stackoverflow.com/questions/415511/how-do-i-get-the-current-time",
        "https://www.microsoft.com/en-us/security",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://www.kaggle.com/datasets",
        "https://www.linkedin.com/in/khizar-hayat-ai-engineer/",
        "https://www.amazon.com/gp/bestsellers",
        "https://www.nytimes.com/section/technology",
        "https://openai.com/research",
        "https://www.cloudflare.com/learning/security/what-is-phishing/",
        "https://www.coursera.org/browse/data-science",
        "https://www.apple.com/macbook-pro/",
        "https://www.bbc.com/news/technology"
    ] * 40

    phishing_urls = [
        "http://192.168.1.45/paypal/login/verify-account.php",
        "http://secure-login-appleid-update.com/auth/signin?session=89234792384",
        "https://www.paypal.com.account-security-update-99.info/webscr",
        "http://bit.ly/3x89BankVerifyUrgent",
        "http://login-microsoftonline-support-auth.net:8080/credential/confirm",
        "http://www.ebayisapi-secure-billing-update.com/user@verify/login.html",
        "http://104.21.44.12/wallet-connect-airdrop-claim-now/",
        "https://netflix-billing-suspended-update-payment.com/signin",
        "http://account.verify.amazon.security.alert.support-center.org/login",
        "http://tinyurl.com/urgent-tax-refund-claim-2026",
        "http://secure.banking.chase.com.verify-user-identity.xyz/login",
        "http://webscr-paypal-limit-lifted-confirm.com/index.php?cmd=_login",
        "http://91.198.174.192:8443/admin/login.php",
        "https://instagram-verified-badge-support-form.tk/password-reset",
        "http://update-your-bank-details-immediately.com/secure/account"
    ] * 40

    urls = legit_urls + phishing_urls
    labels = [0] * len(legit_urls) + [1] * len(phishing_urls)
    return pd.DataFrame({'url': urls, 'label': labels})

def train_and_evaluate():
    df = build_training_dataframe()
    X = np.array([features_to_vector(extract_url_features(u)) for u in df['url']])
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Decision Tree": DecisionTreeClassifier(max_depth=8, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=150, max_depth=12, random_state=42)
    }

    results = {}
    best_model = None
    best_recall = -1
    best_name = ""

    for name, clf in models.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1]

        cm = confusion_matrix(y_test, y_pred).tolist()
        metrics = {
            "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
            "precision": round(float(precision_score(y_test, y_pred)), 4),
            "recall": round(float(recall_score(y_test, y_pred)), 4),
            "f1_score": round(float(f1_score(y_test, y_pred)), 4),
            "roc_auc": round(float(roc_auc_score(y_test, y_prob)), 4),
            "confusion_matrix": cm
        }
        results[name] = metrics

        if metrics["recall"] >= best_recall:
            best_recall = metrics["recall"]
            best_model = clf
            best_name = name

    importances = {}
    if hasattr(best_model, 'feature_importances_'):
        for feat, imp in zip(FEATURE_NAMES, best_model.feature_importances_):
            importances[feat] = round(float(imp), 4)

    artifact = {
        "model": best_model,
        "model_name": best_name,
        "feature_names": FEATURE_NAMES
    }
    joblib.dump(artifact, os.path.join(MODEL_DIR, 'phishguard_model.joblib'))

    report = {
        "selected_model": best_name,
        "models": results,
        "feature_importances": dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))
    }
    with open(os.path.join(MODEL_DIR, 'evaluation_report.json'), 'w') as f:
        json.dump(report, f, indent=2)

    print(f"[+] Training complete. Best model: {best_name} (Recall: {best_recall})")

if __name__ == '__main__':
    train_and_evaluate()
