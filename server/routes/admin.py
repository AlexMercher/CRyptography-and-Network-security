from flask import Blueprint, request, jsonify, session
from server.routes.auth import login_required
from server.services.package_manager import validate_and_save_package
from server.services.release_manager import ReleaseManager
from server.database.database import get_db_connection, log_security_event

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/upload", methods=["POST"])
@login_required
def upload_package():
    if "package" not in request.files:
        return jsonify({"error": "No package file provided"}), 400
    file = request.files["package"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400
        
    try:
        saved_name, pkg_hash, pkg_size = validate_and_save_package(file)
        return jsonify({
            "message": "Package uploaded and verified successfully",
            "filename": saved_name,
            "sha256": pkg_hash,
            "size": pkg_size
        }), 200
    except ValueError as e:
        log_security_event(
            "MALICIOUS_PACKAGE_UPLOAD",
            f"Blocked upload: {str(e)}",
            result="BLOCKED",
            related_user=session.get("user", "admin")
        )
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

@admin_bp.route("/publish", methods=["POST"])
@login_required
def publish_release():
    data = request.get_json() or {}
    software_id = data.get("software_id", "demoapp").strip()
    version = data.get("version", "").strip()
    release_sequence = data.get("release_sequence")
    package_filename = data.get("package_filename", "").strip()
    package_hash = data.get("package_hash", "").strip()
    package_size = data.get("package_size")
    description = data.get("description", "").strip()
    expiration_days = int(data.get("expiration_days", 365))
    
    if not all([software_id, version, release_sequence, package_filename, package_hash, package_size]):
        return jsonify({"error": "Missing required release metadata fields"}), 400
        
    try:
        release = ReleaseManager.publish_release(
            software_id=software_id,
            version=version,
            release_sequence=int(release_sequence),
            package_filename=package_filename,
            package_hash=package_hash,
            package_size=int(package_size),
            description=description,
            expiration_days=expiration_days,
            publisher_user=session.get("user", "admin")
        )
        log_security_event(
            "RELEASE_PUBLISHED",
            f"Published signed release {software_id} v{version} (seq: {release_sequence})",
            result="ALLOWED",
            related_user=session.get("user", "admin")
        )
        return jsonify({
            "message": f"Release {version} published and signed successfully",
            "release": release
        }), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to publish release: {str(e)}"}), 500

@admin_bp.route("/releases", methods=["GET"])
@login_required
def get_releases():
    software_id = request.args.get("software_id")
    releases = ReleaseManager.list_releases(software_id)
    return jsonify({"releases": releases}), 200

@admin_bp.route("/revoke/<int:release_id>", methods=["POST"])
@login_required
def revoke_release(release_id: int):
    data = request.get_json() or {}
    reason = data.get("reason", "Revoked by administrator")
    success = ReleaseManager.revoke_release(release_id, reason)
    if success:
        return jsonify({"message": f"Release {release_id} revoked successfully"}), 200
    return jsonify({"error": "Release not found"}), 404

@admin_bp.route("/logs", methods=["GET"])
@login_required
def get_logs():
    limit = int(request.args.get("limit", 100))
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))
    sec_rows = cursor.fetchall()
    
    cursor.execute("SELECT * FROM update_activity ORDER BY id DESC LIMIT ?", (limit,))
    act_rows = cursor.fetchall()
    conn.close()
    
    sec_logs = [dict(r) for r in sec_rows]
    act_logs = [dict(r) for r in act_rows]
    return jsonify({
        "security_events": sec_logs,
        "update_activity": act_logs
    }), 200

@admin_bp.route("/stats", methods=["GET"])
@login_required
def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as c FROM releases WHERE status = 'published'")
    pub_count = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM clients")
    client_count = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM security_events")
    sec_count = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM update_activity WHERE action = 'INSTALL' AND installation_result = 'SUCCESS'")
    success_installs = cursor.fetchone()["c"]
    conn.close()
    
    return jsonify({
        "published_releases": pub_count,
        "active_clients": client_count,
        "security_events": sec_count,
        "successful_installs": success_installs
    }), 200

