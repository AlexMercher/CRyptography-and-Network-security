import sqlite3
import os
from pathlib import Path
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = Path(__file__).resolve().parent / "update_system.db"

def get_db_connection(db_file=None):
    target = db_file or DB_PATH
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_file=None):
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    
    # 1. Administrators
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS administrators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL
    )
    """)
    
    # 2. Software Releases
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS releases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        software_id TEXT NOT NULL,
        version TEXT NOT NULL,
        release_sequence INTEGER NOT NULL,
        description TEXT,
        package_filename TEXT NOT NULL,
        package_size INTEGER NOT NULL,
        package_hash TEXT NOT NULL,
        signed_metadata_json TEXT NOT NULL,
        signature TEXT NOT NULL,
        published_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        status TEXT DEFAULT 'published',
        UNIQUE(software_id, version)
    )
    """)
    
    # 3. Clients
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT UNIQUE NOT NULL,
        installed_version TEXT NOT NULL,
        last_check TEXT NOT NULL,
        status TEXT DEFAULT 'active'
    )
    """)
    
    # 4. Update Activity
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS update_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        release_id INTEGER,
        action TEXT NOT NULL,
        verification_result TEXT,
        installation_result TEXT,
        details TEXT,
        timestamp TEXT NOT NULL
    )
    """)
    
    # 5. Security Events
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        related_client_or_admin TEXT,
        description TEXT NOT NULL,
        result TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
    """)
    
    # Seed default admin if none exists
    cursor.execute("SELECT id FROM administrators WHERE username = ?", ("admin",))
    if cursor.fetchone() is None:
        p_hash = generate_password_hash("Admin@SecureUpdate2026!")
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "INSERT INTO administrators (username, password_hash, status, created_at) VALUES (?, ?, 'active', ?)",
            ("admin", p_hash, now_iso)
        )
    
    conn.commit()
    conn.close()

def log_security_event(event_type: str, description: str, result: str = "BLOCKED", related_user: str = "system", db_file=None):
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO security_events (event_type, related_client_or_admin, description, result, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (event_type, related_user, description, result, now_iso)
    )
    conn.commit()
    conn.close()

def log_update_activity(client_id: str, action: str, verification_result: str, installation_result: str = "N/A", details: str = "", release_id: int = None, db_file=None):
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO update_activity (client_id, release_id, action, verification_result, installation_result, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (client_id, release_id, action, verification_result, installation_result, details, now_iso)
    )
    conn.commit()
    conn.close()

