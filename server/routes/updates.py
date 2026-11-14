import os
from pathlib import Path
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, send_file, abort
from server.database.database import get_db_connection, log_security_event, log_update_activity
from server.services.release_manager import ReleaseManager

updates_bp = Blueprint("updates", __name__)
PACKAGES_DIR = Path(__file__).resolve().parent.parent.parent / "storage" / "packages"

@updates_bp.route("/check", methods=["GET"])
def check_updates():
    software_id = request.args.get("software_id", "demoapp").strip()
    client_id = request.args.get("client_id", "client-default").strip()
    current_version = request.args.get("current_version", "1.0.0").strip()
    
    # Update client registration in DB
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM clients WHERE client_id = ?", (client_id,))
    existing = cursor.fetchone()
    if existing:
        cursor.execute(
            "UPDATE clients SET installed_version = ?, last_check = ? WHERE client_id = ?",
            (current_version, now_iso, client_id)
        )
    else:
        cursor.execute(
            "INSERT INTO clients (client_id, installed_version, last_check, status) VALUES (?, ?, ?, 'active')",
            (client_id, current_version, now_iso)
        )
    # Determine client's installed sequence number from releases if known
    cursor.execute(
        "SELECT release_sequence FROM releases WHERE software_id = ? AND version = ?",
        (software_id, current_version)
    )
    cur_rel = cursor.fetchone()
    current_seq = cur_rel["release_sequence"] if cur_rel else 0
    conn.commit()
    conn.close()

    # Query only eligible (published, non-revoked) releases strictly newer than current sequence
    latest = ReleaseManager.get_latest_release(software_id, min_sequence=current_seq)
    if not latest:
        log_update_activity(
            client_id, "CHECK", "NO_RELEASES_AVAILABLE",
            details=f"No eligible higher release available for v{current_version} (Seq {current_seq})"
        )
        return jsonify({
            "update_available": False,
            "message": f"System is up-to-date. No eligible updates available for v{current_version}."
        }), 200
        
    log_update_activity(
        client_id=client_id,
        action="CHECK",
        verification_result="CHECKED",
        details=f"Current: {current_version} (Seq: {current_seq}), Latest eligible on server: {latest['version']} (Seq: {latest['release_sequence']})",
        release_id=latest["id"]
    )
    
    return jsonify({
        "update_available": True,
        "release_id": latest["id"],
        "metadata": latest["metadata"],
        "signature": latest["signature"]
    }), 200

@updates_bp.route("/catalog", methods=["GET"])
def get_release_catalog():
    software_id = request.args.get("software_id", "demoapp").strip()
    releases = ReleaseManager.list_releases(software_id)
    return jsonify({"catalog": releases}), 200

@updates_bp.route("/download/<filename>", methods=["GET"])
def download_package(filename: str):
    clean_filename = os.path.basename(filename)
    file_path = PACKAGES_DIR / clean_filename
    
    if not file_path.exists() or not file_path.is_file():
        log_security_event(
            "PACKAGE_DOWNLOAD_NOT_FOUND",
            f"Requested non-existent package: {clean_filename}",
            result="BLOCKED"
        )
        return jsonify({"error": "Package not found"}), 404
        
    client_id = request.args.get("client_id", "unknown-client")
    log_update_activity(
        client_id=client_id,
        action="DOWNLOAD",
        verification_result="DISPATCHED",
        details=f"File: {clean_filename}, Size: {file_path.stat().st_size} bytes"
    )
    
    return send_file(
        str(file_path),
        mimetype="application/zip",
        as_attachment=True,
        download_name=clean_filename
    )

@updates_bp.route("/report", methods=["POST"])
def report_update_status():
    data = request.get_json() or {}
    client_id = data.get("client_id", "unknown-client")
    action = data.get("action", "UNKNOWN")
    verification_result = data.get("verification_result", "UNKNOWN")
    installation_result = data.get("installation_result", "N/A")
    details = data.get("details", "")
    release_id = data.get("release_id")
    security_event = data.get("security_event")
    
    log_update_activity(
        client_id=client_id,
        action=action,
        verification_result=verification_result,
        installation_result=installation_result,
        details=details,
        release_id=release_id
    )
    
    if security_event:
        log_security_event(
            event_type=security_event.get("type", "CLIENT_ALERT"),
            description=security_event.get("description", details),
            result="BLOCKED",
            related_user=client_id
        )
        
    return jsonify({"status": "received"}), 200

