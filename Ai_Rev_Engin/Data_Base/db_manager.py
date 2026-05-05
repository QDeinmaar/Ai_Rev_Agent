import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "reverser.db"


class DatabaseManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row  # cleaner access

        # Improve reliability
        self.conn.execute("PRAGMA journal_mode=WAL;")

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
            is_packed BOOLEAN,
            score INTEGER,
            verdict TEXT,
            analyzed_at TEXT
        )
        """)

        # Detailed analysis table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sample_id INTEGER UNIQUE,
            imports TEXT,
            dangerous_apis TEXT,
            sections TEXT,
            suspicious_sections TEXT,
            FOREIGN KEY (sample_id) REFERENCES samples(id)
        )
        """)

        self.conn.commit()

    def save_analysis(self, results):
        """
        Save full analysis result into database
        """

        cursor = self.conn.cursor()

        now = datetime.now().isoformat()

        # 1. Insert or update sample safely
        cursor.execute("""
        INSERT INTO samples (
            sha256, filename, file_size, entropy,
            is_packed, score, verdict, analyzed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(sha256) DO UPDATE SET
            file_size=excluded.file_size,
            entropy=excluded.entropy,
            is_packed=excluded.is_packed,
            score=excluded.score,
            verdict=excluded.verdict,
            analyzed_at=excluded.analyzed_at
        """, (
            results['sha256'],
            results['filename'],
            results.get('file_size', 0),
            results.get('entropy', 0.0),
            int(results.get('is_packed', 0)),
            results.get('score', 0),
            results.get('verdict', 'UNKNOWN'),
            now
        ))

        # Get sample ID safely
        cursor.execute("SELECT id FROM samples WHERE sha256 = ?", (results['sha256'],))
        sample_id = cursor.fetchone()["id"]

        # 2. Insert detailed analysis
        cursor.execute("""
        INSERT INTO analysis (
            sample_id, imports, dangerous_apis,
            sections, suspicious_sections
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(sample_id) DO UPDATE SET
            imports=excluded.imports,
            dangerous_apis=excluded.dangerous_apis,
            sections=excluded.sections,
            suspicious_sections=excluded.suspicious_sections
        """, (
            sample_id,
            json.dumps(results.get('imports', [])),
            json.dumps(results.get('dangerous_apis', [])),
            json.dumps(results.get('sections', [])),
            json.dumps(results.get('suspicious_sections', []))
        ))

        self.conn.commit()

        print(f"✅ Saved: {results['filename']} (score: {results.get('score', 0)})")

        return sample_id

    def get_sample_by_sha256(self, sha256):
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM samples WHERE sha256 = ?
        """, (sha256,))
        return cursor.fetchone()

    def get_full_analysis(self, sha256):
        cursor = self.conn.cursor()

        cursor.execute("""
        SELECT s.*, a.*
        FROM samples s
        LEFT JOIN analysis a ON s.id = a.sample_id
        WHERE s.sha256 = ?
        """, (sha256,))

        row = cursor.fetchone()
        if not row:
            return None

        return dict(row)

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

    for row in db.list_recent():
        print(dict(row))

    db.close()