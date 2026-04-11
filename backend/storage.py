import sqlite3
import uuid
import json
import os

DB_FILE = "scanner.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            url TEXT,
            forms_found INTEGER,
            vulnerabilities TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Auto-initialize on import
init_db()

def save_report(data: dict) -> str:
    report_id = str(uuid.uuid4())
    # vulnerabilities is a list of dicts, we serialize it to json string for DB
    vulnerabilities = json.dumps(data.get("vulnerabilities", []))
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO reports (id, url, forms_found, vulnerabilities)
        VALUES (?, ?, ?, ?)
    ''', (report_id, data.get("url"), data.get("forms_found", 0), vulnerabilities))
    conn.commit()
    conn.close()
    return report_id

def load_report(report_id: str) -> dict:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT url, forms_found, vulnerabilities, timestamp FROM reports WHERE id = ?", (report_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "report_id": report_id,
            "url": row[0],
            "forms_found": row[1],
            "vulnerabilities": json.loads(row[2]),
            "timestamp": row[3]
        }
    return None

def get_all_reports() -> list:
    """Returns a high-level summary of all reports for the history dashboard."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Ordered by newest first
    cursor.execute("SELECT id, url, forms_found, timestamp FROM reports ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "report_id": row[0],
            "url": row[1],
            "forms_found": row[2],
            "timestamp": row[3]
        }
        for row in rows
    ]
