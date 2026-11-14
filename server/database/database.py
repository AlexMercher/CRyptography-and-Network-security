import sqlite3
import os
import json
import secrets
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from werkzeug.security import generate_password_hash, check_password_hash

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = Path(__file__).resolve().parent / "update_system.db"

CANONICAL_RELEASES = [
    {
        "software_id": "demoapp",
        "version": "1.0.0",
        "release_sequence": 1,
        "package_filename": "demoapp-1.0.0.zip",
        "description": "Baseline diagnostic engine, basic local logging",
        "initial_status": "published"
    },
    {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "description": "Network performance optimizer, cryptographic telemetry module",
        "initial_status": "prepared"
    },
    {
        "software_id": "demoapp",
        "version": "1.2.0",
        "release_sequence": 3,
        "package_filename": "demoapp-1.2.0.zip",
        "description": "Distributed health probe, structured JSON telemetry logging",
        "initial_status": "prepared"
    },
    {
        "software_id": "demoapp",
        "version": "1.3.0",
        "release_sequence": 4,
        "package_filename": "demoapp-1.3.0.zip",
        "description": "Advanced analytics: Fibonacci benchmark, Miller-Rabin primality check",
        "initial_status": "prepared"
    },
    {
        "software_id": "demoapp",
        "version": "1.4.0",
        "release_sequence": 5,
        "package_filename": "demoapp-1.4.0.zip",
        "description": "Security toolkit: password entropy calculator, NIST compliance module",
        "initial_status": "prepared"
    }
]

def get_db_connection(db_file=None):
    if db_file:
        target = db_file
    else:
        try:
            from flask import current_app, has_app_context
            if has_app_context() and current_app and current_app.config.get("DATABASE"):
                target = current_app.config.get("DATABASE")
            else:
                target = DB_PATH
        except Exception:
            target = DB_PATH
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
        revocation_reason TEXT,
        revoked_at TEXT,
        UNIQUE(software_id, version)
    )
    """)
    
    # Auto-migrate table columns if upgrading existing database
    cursor.execute("PRAGMA table_info(releases)")
    existing_cols = [row["name"] for row in cursor.fetchall()]
    if "revocation_reason" not in existing_cols:
        cursor.execute("ALTER TABLE releases ADD COLUMN revocation_reason TEXT")
    if "revoked_at" not in existing_cols:
        cursor.execute("ALTER TABLE releases ADD COLUMN revoked_at TEXT")
    
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
    
    # 6. Presentation Sessions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS presentation_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        reset_by TEXT DEFAULT 'system',
        notes TEXT
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

def get_active_presentation_session(db_file=None) -> Optional[Dict[str, Any]]:
    """Retrieves the currently active presentation session, if any."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM presentation_sessions WHERE status = 'active' ORDER BY id DESC LIMIT 1"
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def seed_canonical_releases(db_file=None, only_versions: Optional[List[str]] = None, force_reset_status: bool = False):
    """
    Ensures all 5 canonical releases (1.0.0 through 1.4.0) are packaged,
    cryptographically signed with the publisher private key, and upserted
    into the releases table with valid metadata and appropriate initial status.
    """
    from common.crypto_engine import compute_sha256, verify_metadata
    from server.services.signing_service import create_and_sign_release_metadata
    from scripts.setup_demoapp import build_zip

    priv_key_path = PROJECT_ROOT / "keys" / "publisher_private.pem"
    pub_key_path = PROJECT_ROOT / "keys" / "publisher_public.pem"
    if not priv_key_path.exists() or not pub_key_path.exists():
        raise FileNotFoundError("Publisher keypair missing. Cannot seed canonical releases.")

    # Verify keypair match before signing
    test_meta = {"test": "keypair_validation"}
    from common.crypto_engine import sign_metadata
    test_sig = sign_metadata(priv_key_path, test_meta)
    if not verify_metadata(pub_key_path, test_meta, test_sig):
        raise ValueError("Publisher private key does not match public key!")

    packages_dir = PROJECT_ROOT / "storage" / "packages"
    packages_dir.mkdir(parents=True, exist_ok=True)
    releases_storage = PROJECT_ROOT / "storage" / "releases"
    releases_storage.mkdir(parents=True, exist_ok=True)

    conn = get_db_connection(db_file)
    cursor = conn.cursor()

    target_defs = CANONICAL_RELEASES
    if only_versions:
        target_defs = [r for r in CANONICAL_RELEASES if r["version"] in only_versions]

    for rel in target_defs:
        ver = rel["version"]
        seq = rel["release_sequence"]
        filename = rel["package_filename"]
        desc = rel["description"]
        initial_status = rel.get("initial_status", "prepared")
        pkg_path = packages_dir / filename

        # Ensure ZIP package exists
        if not pkg_path.exists():
            src_dir = PROJECT_ROOT / "demoapp" / "versions" / ver
            if src_dir.exists():
                build_zip(src_dir, pkg_path)
            else:
                raise FileNotFoundError(f"Source directory for DemoApp {ver} not found at {src_dir}")

        pkg_size = pkg_path.stat().st_size
        pkg_hash = compute_sha256(pkg_path)

        # Create deterministic metadata and signature
        meta, sig = create_and_sign_release_metadata(
            software_id=rel["software_id"],
            version=ver,
            release_sequence=seq,
            package_filename=filename,
            package_hash=pkg_hash,
            package_size=pkg_size,
            description=desc,
            expiration_days=365,
            private_key_path=priv_key_path
        )
        meta_json = json.dumps(meta, sort_keys=True)
        now_iso = meta["release_timestamp"]
        exp_iso = meta["expiration_timestamp"]

        # Save to storage/releases/{software_id}_{version}.json
        meta_file = releases_storage / f"{rel['software_id']}_{ver}.json"
        meta_file.write_text(json.dumps({"metadata": meta, "signature": sig}, indent=2), encoding="utf-8")

        # Upsert into releases table
        if force_reset_status:
            cursor.execute(
                """
                INSERT INTO releases (
                    software_id, version, release_sequence, description,
                    package_filename, package_size, package_hash,
                    signed_metadata_json, signature, published_at, expires_at, status,
                    revocation_reason, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                ON CONFLICT(software_id, version) DO UPDATE SET
                    release_sequence = excluded.release_sequence,
                    description = excluded.description,
                    package_filename = excluded.package_filename,
                    package_size = excluded.package_size,
                    package_hash = excluded.package_hash,
                    signed_metadata_json = excluded.signed_metadata_json,
                    signature = excluded.signature,
                    published_at = excluded.published_at,
                    expires_at = excluded.expires_at,
                    status = excluded.status,
                    revocation_reason = NULL,
                    revoked_at = NULL
                """,
                (
                    rel["software_id"], ver, seq, desc,
                    filename, pkg_size, pkg_hash,
                    meta_json, sig, now_iso, exp_iso,
                    initial_status
                )
            )
        else:
            cursor.execute(
                """
                INSERT INTO releases (
                    software_id, version, release_sequence, description,
                    package_filename, package_size, package_hash,
                    signed_metadata_json, signature, published_at, expires_at, status,
                    revocation_reason, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                ON CONFLICT(software_id, version) DO UPDATE SET
                    release_sequence = excluded.release_sequence,
                    description = excluded.description,
                    package_filename = excluded.package_filename,
                    package_size = excluded.package_size,
                    package_hash = excluded.package_hash,
                    signed_metadata_json = excluded.signed_metadata_json,
                    signature = excluded.signature,
                    published_at = excluded.published_at,
                    expires_at = excluded.expires_at
                """,
                (
                    rel["software_id"], ver, seq, desc,
                    filename, pkg_size, pkg_hash,
                    meta_json, sig, now_iso, exp_iso,
                    initial_status
                )
            )

    conn.commit()
    conn.close()

def start_new_presentation_session(actor="system", notes="New Presentation Session", db_file=None) -> Dict[str, Any]:
    """
    Explicitly starts a fresh presentation session:
    1. Generates a new unique session identifier.
    2. Closes prior active sessions.
    3. Restores canonical releases (1.0.0 published, 1.1.0 through 1.4.0 prepared).
    4. Removes any non-canonical ad-hoc releases created during demonstrations.
    5. Clears presentation-specific activity and logs.
    6. Restores demonstration client to version 1.0.0, sequence 1 baseline.
    7. Preserves administrator credentials, publisher keys, and TLS configuration.
    """
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    session_id = f"sess-{now_dt.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4)}"

    conn = get_db_connection(db_file)
    cursor = conn.cursor()

    # 1. Close any existing active sessions
    cursor.execute(
        "UPDATE presentation_sessions SET status = 'closed' WHERE status = 'active'"
    )

    # 2. Insert new active presentation session
    cursor.execute(
        """
        INSERT INTO presentation_sessions (session_id, created_at, status, reset_by, notes)
        VALUES (?, ?, 'active', ?, ?)
        """,
        (session_id, now_iso, actor, notes)
    )

    # 3. Clean non-canonical demoapp releases
    canonical_versions = tuple(r["version"] for r in CANONICAL_RELEASES)
    placeholders = ",".join("?" for _ in canonical_versions)
    cursor.execute(
        f"DELETE FROM releases WHERE software_id = 'demoapp' AND version NOT IN ({placeholders})",
        canonical_versions
    )

    # 4. Reset canonical releases: 1.0.0 is published, 1.1.0-1.4.0 are prepared
    cursor.execute(
        """
        UPDATE releases
        SET status = 'published', revocation_reason = NULL, revoked_at = NULL
        WHERE software_id = 'demoapp' AND version = '1.0.0'
        """
    )
    cursor.execute(
        """
        UPDATE releases
        SET status = 'prepared', revocation_reason = NULL, revoked_at = NULL
        WHERE software_id = 'demoapp' AND version != '1.0.0'
        """
    )

    # 5. Clear mutable activity and security logs for fresh session demonstration
    cursor.execute("DELETE FROM update_activity")
    cursor.execute("DELETE FROM security_events")

    # 6. Reset clients table
    cursor.execute("DELETE FROM clients")
    cursor.execute(
        """
        INSERT INTO clients (client_id, installed_version, last_check, status)
        VALUES ('client-alpha', '1.0.0', ?, 'active')
        """,
        (now_iso,)
    )

    conn.commit()
    conn.close()

    # 7. Ensure canonical packages are fully seeded and signed with clean status
    seed_canonical_releases(db_file=db_file, force_reset_status=True)

    # 8. Reset client filesystem baseline (state.json, current/ 1.0.0, clean staging/backup)
    try:
        from server.routes.client_ui import reset_client_baseline_internal
        reset_client_baseline_internal(actor=actor)
    except Exception as e:
        print(f"[!] Warning: client baseline reset encountered: {e}")

    # 9. Log session initialization
    log_security_event(
        event_type="PRESENTATION_SESSION_STARTED",
        description=f"New presentation session {session_id} initialized with canonical baseline by {actor}",
        result="SUCCESS",
        related_user=actor,
        db_file=db_file
    )

    return {
        "session_id": session_id,
        "created_at": now_iso,
        "status": "active",
        "reset_by": actor,
        "notes": notes,
        "releases_count": len(CANONICAL_RELEASES)
    }

def ensure_canonical_baseline(db_file=None, force_new_session=False, actor="system") -> Dict[str, Any]:
    """
    Ensures that the demonstration environment has an active presentation session
    and that all five canonical DemoApp releases exist.

    If force_new_session is True or no active session exists:
      -> Initializes a new session and restores canonical baseline.
    If an active session already exists and force_new_session is False:
      -> Reconnects to existing session, PRESERVING all active mutations, revocations, and client state.
    """
    init_db(db_file)
    active = get_active_presentation_session(db_file)

    if not active or force_new_session:
        return start_new_presentation_session(actor=actor, notes="Automatic baseline initialization" if not active else "Explicit new session", db_file=db_file)

    # Reconnect to active session without altering mutable state (revocations, installations)
    # Check if any canonical releases are missing from the database
    conn = get_db_connection(db_file)
    c = conn.cursor()
    c.execute("SELECT version FROM releases WHERE software_id = 'demoapp'")
    existing_versions = {row["version"] for row in c.fetchall()}
    conn.close()

    missing = [r for r in CANONICAL_RELEASES if r["version"] not in existing_versions]
    if missing:
        # Seed missing versions only, preserving existing status of other releases
        seed_canonical_releases(db_file=db_file, only_versions=[m["version"] for m in missing])

    return active
