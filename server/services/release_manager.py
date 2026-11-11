import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from server.database.database import get_db_connection, log_security_event, log_update_activity
from server.services.signing_service import create_and_sign_release_metadata
from common.crypto_engine import compare_versions

RELEASES_STORAGE = Path(__file__).resolve().parent.parent.parent / "storage" / "releases"

class ReleaseManager:
    @staticmethod
    def publish_release(
        software_id: str,
        version: str,
        release_sequence: int,
        package_filename: str,
        package_hash: str,
        package_size: int,
        description: str,
        expiration_days: int = 365,
        publisher_user: str = "admin",
        custom_private_key: Path = None,
        db_file = None
    ) -> Dict[str, Any]:
        conn = get_db_connection(db_file)
        cursor = conn.cursor()
        
        # Check if version already published
        cursor.execute(
            "SELECT id, version, release_sequence FROM releases WHERE software_id = ? AND version = ?",
            (software_id, version)
        )
        existing = cursor.fetchone()
        if existing:
            conn.close()
            raise ValueError(f"Version {version} for software '{software_id}' is already published.")
            
        # Check sequence number is greater than highest existing
        cursor.execute(
            "SELECT MAX(release_sequence) as max_seq FROM releases WHERE software_id = ?",
            (software_id,)
        )
        row = cursor.fetchone()
        max_seq = row["max_seq"] if row and row["max_seq"] is not None else 0
        if release_sequence <= max_seq:
            conn.close()
            raise ValueError(
                f"Release sequence ({release_sequence}) must be strictly greater than current maximum ({max_seq})."
            )
            
        # Sign the metadata
        metadata, signature = create_and_sign_release_metadata(
            software_id=software_id,
            version=version,
            release_sequence=release_sequence,
            package_filename=package_filename,
            package_hash=package_hash,
            package_size=package_size,
            description=description,
            expiration_days=expiration_days,
            private_key_path=custom_private_key
        )
        
        metadata_json = json.dumps(metadata, sort_keys=True)
        now_iso = metadata["release_timestamp"]
        exp_iso = metadata["expiration_timestamp"]
        
        cursor.execute(
            """
            INSERT INTO releases (
                software_id, version, release_sequence, description,
                package_filename, package_size, package_hash,
                signed_metadata_json, signature, published_at, expires_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published')
            """,
            (
                software_id, version, release_sequence, description,
                package_filename, package_size, package_hash,
                metadata_json, signature, now_iso, exp_iso
            )
        )
        rel_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Save copy in storage/releases/
        RELEASES_STORAGE.mkdir(parents=True, exist_ok=True)
        meta_file = RELEASES_STORAGE / f"{software_id}_{version}.json"
        meta_file.write_text(json.dumps({
            "metadata": metadata,
            "signature": signature
        }, indent=2), encoding="utf-8")
        
        return {
            "id": rel_id,
            "metadata": metadata,
            "signature": signature
        }

    @staticmethod
    def get_latest_release(software_id: str, db_file = None) -> Optional[Dict[str, Any]]:
        conn = get_db_connection(db_file)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM releases
            WHERE software_id = ? AND status = 'published'
            ORDER BY release_sequence DESC LIMIT 1
            """,
            (software_id,)
        )
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "id": row["id"],
            "software_id": row["software_id"],
            "version": row["version"],
            "release_sequence": row["release_sequence"],
            "description": row["description"],
            "package_filename": row["package_filename"],
            "package_size": row["package_size"],
            "package_hash": row["package_hash"],
            "metadata": json.loads(row["signed_metadata_json"]),
            "signature": row["signature"],
            "published_at": row["published_at"],
            "expires_at": row["expires_at"],
            "status": row["status"],
            "revocation_reason": row["revocation_reason"] if "revocation_reason" in row.keys() else None,
            "revoked_at": row["revoked_at"] if "revoked_at" in row.keys() else None
        }

    @staticmethod
    def get_release_by_id(release_id: int, db_file = None) -> Optional[Dict[str, Any]]:
        conn = get_db_connection(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM releases WHERE id = ?", (release_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "id": row["id"],
            "software_id": row["software_id"],
            "version": row["version"],
            "release_sequence": row["release_sequence"],
            "description": row["description"],
            "package_filename": row["package_filename"],
            "package_size": row["package_size"],
            "package_hash": row["package_hash"],
            "metadata": json.loads(row["signed_metadata_json"]),
            "signed_metadata_raw": row["signed_metadata_json"],
            "signature": row["signature"],
            "published_at": row["published_at"],
            "expires_at": row["expires_at"],
            "status": row["status"],
            "revocation_reason": row["revocation_reason"] if "revocation_reason" in row.keys() else None,
            "revoked_at": row["revoked_at"] if "revoked_at" in row.keys() else None
        }

    @staticmethod
    def list_releases(software_id: Optional[str] = None, db_file = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_file)
        cursor = conn.cursor()
        if software_id:
            cursor.execute(
                "SELECT * FROM releases WHERE software_id = ? ORDER BY release_sequence DESC",
                (software_id,)
            )
        else:
            cursor.execute("SELECT * FROM releases ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()
        results = []
        for r in rows:
            results.append({
                "id": r["id"],
                "software_id": r["software_id"],
                "version": r["version"],
                "release_sequence": r["release_sequence"],
                "description": r["description"],
                "package_filename": r["package_filename"],
                "package_size": r["package_size"],
                "package_hash": r["package_hash"],
                "metadata": json.loads(r["signed_metadata_json"]),
                "signature": r["signature"],
                "published_at": r["published_at"],
                "expires_at": r["expires_at"],
                "status": r["status"],
                "revocation_reason": r["revocation_reason"] if "revocation_reason" in r.keys() else None,
                "revoked_at": r["revoked_at"] if "revoked_at" in r.keys() else None
            })
        return results

    @staticmethod
    def revoke_release(release_id: int, reason: str = "Administrative revocation", db_file = None) -> bool:
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_file)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE releases SET status = 'revoked', revocation_reason = ?, revoked_at = ? WHERE id = ?",
            (reason, now_iso, release_id)
        )
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        if success:
            log_security_event("RELEASE_REVOKED", f"Release ID {release_id} was revoked: {reason}", "ALERT", db_file=db_file)
        return success

