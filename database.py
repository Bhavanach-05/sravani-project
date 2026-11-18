import sqlite3
import os
from config import Config

def get_db_connection(db_path=None):
    if db_path is None:
        db_path = Config.DATABASE_PATH
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db(db_path=None):
    if db_path is None:
        db_path = Config.DATABASE_PATH
        
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    # 1. users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        failed_login_count INTEGER DEFAULT 0,
        is_locked INTEGER DEFAULT 0,
        lock_until DATETIME NULL
    );
    """)
    
    # 2. smart_cards
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS smart_cards (
        card_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        card_uid TEXT UNIQUE NOT NULL,
        fuzzy_verifier_data TEXT NOT NULL,
        helper_data TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
    );
    """)
    
    # 3. ringlwe_keys
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ringlwe_keys (
        key_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        public_params TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
    );
    """)
    
    # 4. sessions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        session_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_token TEXT UNIQUE NOT NULL,
        session_key_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        status TEXT DEFAULT 'active',
        FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
    );
    """)
    
    # 5. audit_logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NULL,
        event_type TEXT NOT NULL,
        description TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        outcome TEXT NOT NULL,
        severity TEXT NOT NULL,
        metadata_json TEXT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE SET NULL
    );
    """)
    
    # 6. honey_tokens
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS honey_tokens (
        token_id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_type TEXT NOT NULL,
        decoy_value TEXT UNIQUE NOT NULL,
        decoy_metadata TEXT NULL,
        triggered_count INTEGER DEFAULT 0,
        last_triggered_at DATETIME NULL
    );
    """)
    
    # 7. scad_events
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scad_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NULL,
        card_id INTEGER NULL,
        event_description TEXT NOT NULL,
        severity TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE SET NULL,
        FOREIGN KEY(card_id) REFERENCES smart_cards(card_id) ON DELETE SET NULL
    );
    """)
    
    conn.commit()
    seed_honey_tokens(conn)
    conn.close()
    return True

def seed_honey_tokens(conn):
    cursor = conn.cursor()
    # Default decoy honey tokens
    decoys = [
        ('USERNAME', 'admin_root', 'Decoy administrator account seeded to catch credential-stuffing bots'),
        ('USERNAME', 'backup_service', 'Decoy service account seeded for automated lateral movement detection'),
        ('CARD_UID', 'CARD-HONEY-7777', 'Decoy smart card ID seeded in public client mocks'),
        ('CARD_UID', 'CARD-DECOY-0000', 'Decoy smart card ID seeded in developer test fixtures')
    ]
    for token_type, decoy_value, metadata in decoys:
        cursor.execute("""
        INSERT OR IGNORE INTO honey_tokens (token_type, decoy_value, decoy_metadata, triggered_count)
        VALUES (?, ?, ?, 0)
        """, (token_type, decoy_value, metadata))
    conn.commit()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
