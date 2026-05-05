import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "reverser.db"


class DatabaseManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()

        # Main sample table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256 TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER,
            entropy REAL,
            is_packed INTEGER,
            score INTEGER,
            verdict TEXT,
            analyzed_at TEXT
        )
        """)

        # Detailed analysis table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sample_id INTEGER,
            imports TEXT,
            dangerous_apis TEXT,
            sections TEXT,
            suspicious_sections TEXT,
            FOREIGN KEY (sample_id) REFERENCES samples(id)
        )
        """)

        self.conn.commit()

    def save_analysis(self, results):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()

        # Check if sample already exists
        cursor.execute("SELECT id FROM samples WHERE sha256 = ?", (results['sha256'],))
        existing = cursor.fetchone()

        if existing:
            sample_id = existing[0]
            # Update existing sample
            cursor.execute("""
                UPDATE samples 
                SET filename = ?, file_size = ?, entropy = ?, is_packed = ?, score = ?, verdict = ?, analyzed_at = ?
                WHERE id = ?
            """, (
                results.get('filename', ''),
                results.get('file_size', 0),
                results.get('entropy', 0.0),
                1 if results.get('is_packed') else 0,
                results.get('score', 0),
                results.get('verdict', 'UNKNOWN'),
                now,
                sample_id
            ))
        else:
            # Insert new sample
            cursor.execute("""
                INSERT INTO samples (sha256, filename, file_size, entropy, is_packed, score, verdict, analyzed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                results['sha256'],
                results.get('filename', ''),
                results.get('file_size', 0),
                results.get('entropy', 0.0),
                1 if results.get('is_packed') else 0,
                results.get('score', 0),
                results.get('verdict', 'UNKNOWN'),
                now
            ))
            sample_id = cursor.lastrowid

        # Delete old analysis data for this sample
        cursor.execute("DELETE FROM analysis WHERE sample_id = ?", (sample_id,))

        # Insert new analysis data
        cursor.execute("""
            INSERT INTO analysis (sample_id, imports, dangerous_apis, sections, suspicious_sections)
            VALUES (?, ?, ?, ?, ?)
        """, (
            sample_id,
            json.dumps(results.get('imports', [])),
            json.dumps(results.get('dangerous_apis', [])),
            json.dumps(results.get('sections', [])),
            json.dumps(results.get('suspicious_sections', []))
        ))

        self.conn.commit()
        print(f"Saved: {results.get('filename', 'unknown')} (Score: {results.get('score', 0)})")
        return sample_id

    def get_sample_by_sha256(self, sha256):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM samples WHERE sha256 = ?", (sha256,))
        return cursor.fetchone()

    def list_recent(self, limit=10):
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT filename, sha256, score, verdict, analyzed_at
            FROM samples
            ORDER BY analyzed_at DESC
            LIMIT ?
        """, (limit,))
        return cursor.fetchall()

    def close(self):
        self.conn.close()


if __name__ == "__main__":
    db = DatabaseManager()
    print("Database ready!")
    print("\nRecent analyses:")
    for row in db.list_recent():
        print(f"  {row[3]:10} | Score: {row[2]:3} | {row[0]}")
    db.close()