import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "reverser.db" # The location of the database

class DataBaseManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self._create_tables()
    
    def _create_tables(self):
        cursor = self.conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256 TEXT UNIQUE NOT NULL,
                    filename TEXT NOT NULL,
                    file_size INTEGER,
                    entropy REAL,
                    is_packed BOOLEAN,
                    score INTEGER,
                    verdict TEXT,
                    analyzed_at TIMESTAMP
                )
        ''')

        cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sample_id INTEGER,
                    imports TEXT,
                    dangerous_apis TEXT,
                    sections TEXT,
                    suspicious_sections TEXT,
                    FOREIGN KEY (sample_id) REFERENCES samples(id)
                )
        ''') # Stores detailed infos
        
        self.conn.commit()

    def save_analysis(self, results):
        """
        Save analysis results to database
        
        Args:
            results: Dictionary from PeParser.get_full_analysis()
        """
        cursor = self.conn.cursor()

        # Insert into samples table
        cursor.execute('''
            INSERT OR REPLACE INTO samples 
            (sha256, filename, file_size, entropy, is_packed, score, verdict, analyzed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            results['sha256'],
            results['filename'],
            results['file_size'],
            results['entropy'],
            results['is_packed'],
            results['score'],
            results['verdict'],
            datetime.now().isoformat()
        ))

        # Get the sample ID
        sample_id = cursor.lastrowid
        
        # Insert into analysis table
        cursor.execute('''
            INSERT OR REPLACE INTO analysis
            (sample_id, imports, dangerous_apis, sections, suspicious_sections)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            sample_id,
            json.dumps(results.get('imports', [])),
            json.dumps(results.get('dangerous_apis', [])),
            json.dumps(results.get('sections', [])),
            json.dumps(results.get('suspicious_sections', []))
        ))
        
        self.conn.commit()
        print(f"✅ Saved to database: {results['filename']}")
        
        return sample_id
    
    def get_sample_by_sha256(self, sha256):
        """Retrieve a sample by its SHA256 hash"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM samples WHERE sha256 = ?", (sha256,))
        return cursor.fetchone()
    
    def list_recent(self, limit=10):
        """List most recent analyses"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT filename, sha256, score, verdict, analyzed_at 
            FROM samples 
            ORDER BY analyzed_at DESC 
            LIMIT ?
        ''', (limit,))
        return cursor.fetchall()
    
    def close(self):
        """Close database connection"""
        self.conn.close()


if __name__ == "__main__":
    db = DataBaseManager()
    db.list_recent()
    print("Database ready!")
    db.close()