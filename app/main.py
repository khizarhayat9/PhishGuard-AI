import os
import sys
import re
from urllib.parse import urlparse, urlunparse
from flask import Flask, render_template, request, jsonify

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml.predict import PhishGuardPredictor
from database.db import (
    init_db, insert_scan, get_scans,
    get_dashboard_stats, delete_scan, clear_all_scans
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024

init_db()
predictor = PhishGuardPredictor()

URL_REGEX = re.compile(
    r'^(https?://)?'
    r'(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3})'
    r'(:\d{1,5})?(/.*)?$'
)

def sanitize_url_for_storage(raw_url: str) -> str:
    """Strips credentials and sensitive query strings before saving to SQLite."""
    parsed = urlparse(raw_url if raw_url.startswith(('http://', 'https://')) else 'http://' + raw_url)
    clean_netloc = parsed.hostname or ''
    if parsed.port:
        clean_netloc += f":{parsed.port}"
    return urlunparse((parsed.scheme, clean_netloc, parsed.path, '', '', ''))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.get_json(silent=True) or {}
    raw_url = str(data.get('url', '')).strip()

    if not raw_url or len(raw_url) > 2048:
        return jsonify({"error": "Please provide a valid URL under 2048 characters."}), 400

    if not URL_REGEX.match(raw_url):
        return jsonify({"error": "Invalid URL format. Enter a valid domain or IP address."}), 400

    try:
        result = predictor.analyze_url(raw_url)
        safe_storage_url = sanitize_url_for_storage(raw_url)
        insert_scan(
            sanitized_url=safe_storage_url,
            classification=result['classification'],
            risk_level=result['risk_level'],
            model_score=result['model_score']
        )
        return jsonify(result), 200
    except Exception:
        return jsonify({"error": "Internal analysis error occurred."}), 500

@app.route('/api/stats', methods=['GET'])
def stats():
    return jsonify(get_dashboard_stats()), 200

@app.route('/api/history', methods=['GET'])
def history():
    q = request.args.get('q', '').strip()
    filter_type = request.args.get('filter', 'ALL').strip()
    return jsonify(get_scans(q, filter_type)), 200

@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def remove_scan(scan_id):
    delete_scan(scan_id)
    return jsonify({"status": "deleted"}), 200

@app.route('/api/history/clear', methods=['DELETE'])
def clear_history():
    clear_all_scans()
    return jsonify({"status": "cleared"}), 200

@app.route('/api/model-metrics', methods=['GET'])
def model_metrics():
    return jsonify(predictor.get_evaluation_report()), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
