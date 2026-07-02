import sqlite3
import json
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATABASE_FILE
from crypto.ratchet import DoubleRatchet

class SessionStore:
    def __init__(self,db_path=DATABASE_FILE):
        self.db_path=db_path
        self.connection=sqlite3.connect(self.db_path)
        self._create_tables()

    def _create_tables(self):
        cursor =self.connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                local_user TEXT NOT NULL,
                remote_user TEXT NOT NULL,
                ratchet_state BLOB NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(local_user, remote_user)
            )
        """)

        self.connection.commit()

    def save_session(self,local_user,remote_user,ratchet_state):

        cursor = self.connection.cursor()

        serialized_data = json.dumps(ratchet_state.to_dict()).encode('utf-8')

        cursor.execute("""
           INSERT OR REPLACE INTO sessions 
            (local_user, remote_user, ratchet_state, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """,(local_user, remote_user, serialized_data))

        self.connection.commit()

    def load_session(self,local_user,remote_user):
        
        cursor = self.connection.cursor()

        cursor.execute("""
            SELECT ratchet_state FROM sessions
            WHERE local_user=? AND remote_user=?
        """,(local_user, remote_user))

        row= cursor.fetchone()

        if row is None:
            return None

        return DoubleRatchet.from_dict(json.loads(row[0].decode('utf-8')))
    
    def delete_session(self,local_user,remote_user):
        cursor = self.connection.cursor()

        cursor.execute("""
            DELETE FROM sessions
            WHERE local_user=? AND remote_user=?
        """,(local_user, remote_user))

        self.connection.commit()

    def list_sessions(self,local_user):
        cursor = self.connection.cursor()

        cursor.execute("""
            SELECT remote_user FROM sessions
            WHERE local_user = ?
            ORDER BY updated_at DESC
        """,(local_user,))

        rows= cursor.fetchall()
        return [row[0] for row in rows]
    
    def close(self):
        self.connection.close()
        