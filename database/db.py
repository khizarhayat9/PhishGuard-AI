import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'phishguard.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sanitized_url TEXT NOT NULL,
            classification TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            model_score REAL NOT NULL,
            scanned_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def insert_scan(sanitized_url: str, classification: str, risk_level: str, model_score: float):
    conn = get_connection()
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        '''INSERT INTO scan_history (sanitized_url, classification, risk_level, model_score, scanned_at)
           VALUES (?, ?, ?, ?, ?)''',
        (sanitized_url, classification, risk_level, model_score, scanned_at)
    )
    conn.commit()
    conn.close()

def get_scans(search_query: str = "", filter_type: str = "ALL"):
    conn = get_connection()
    query = "SELECT * FROM scan_history WHERE 1=1"
    params = []

    if search_query:
        query += " AND sanitized_url LIKE ?"
        params.append(f"%{search_query}%")
    if filter_type and filter_type != "ALL":
        query += " AND classification = ?"
        params.append(filter_type)

    query += " ORDER BY id DESC LIMIT 100"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_dashboard_stats():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
    safe = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'low'").fetchone()[0]
    suspicious = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'medium'").fetchone()[0]
    phishing = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'high'").fetchone()[0]
    recent = conn.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT 5").fetchall()
    conn.close()
    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "phishing": phishing,
        "recent": [dict(r) for r in recent]
    }

def delete_scan(scan_id: int):
    conn = get_connection()
    conn.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()

def clear_all_scans():
    conn = get_connection()
    conn.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()
