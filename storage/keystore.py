import sqlite3
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATABASE_FILE



class Keystore:
    def __init__(self,db_path=DATABASE_FILE):

        self.db_path=db_path
        self.connection=sqlite3.connect(self.db_path)
        self._create_tables()

    def _create_tables(self):
        cursor =self.connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                key_type TEXT NOT NULL,
                key_data BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_user_keytype 
            ON keys(user_id, key_type)
        """)

        self.connection.commit()

    def save_key(self,user_id,key_type,key_data):

        cursor = self.connection.cursor()

        cursor.execute("""
            INSERT INTO keys (user_id, key_type, key_data)
            VALUES (?, ?, ?)
        """,(user_id,key_type,key_data))

        self.connection.commit()

    def load_key(self,user_id,key_type):
        
        cursor = self.connection.cursor()

        cursor.execute("""
            SELECT key_data FROM keys
            WHERE user_id=? AND key_type=?
            ORDER BY created_at DESC
            LIMIT 1
        """,(user_id,key_type))

        row=cursor.fetchone()
        if row is None:
            return None
        else:
            return row[0]
    def load_all_keys(self,user_id,key_type):
        cursor = self.connection.cursor()

        cursor.execute("""
            SELECT key_data FROM keys
            WHERE user_id=? AND key_type=?
            ORDER BY created_at DESC
        """,(user_id,key_type))

        rows=cursor.fetchall()
        return [row[0] for row in rows]
    
    def delete_keys(self,user_id,key_type):
        cursor = self.connection.cursor()

        cursor.execute("""
            DELETE FROM keys
            WHERE user_id=? AND key_type=?
        """,(user_id,key_type))

        self.connection.commit()
    def close(self):
        self.connection.close()

        