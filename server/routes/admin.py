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
    grouped = ReleaseManager.get_releases_grouped(software_id)
    return jsonify({
        "releases": grouped["all_releases"],
        "published_releases": grouped["published_releases"],
        "prepared_releases": grouped["prepared_releases"]
    }), 200

@admin_bp.route("/releases/<int:release_id>/publish", methods=["POST"])
@login_required
def publish_prepared_release(release_id: int):
    try:
        actor = session.get("user", "admin")
        updated_release = ReleaseManager.publish_prepared_release(
            release_id=release_id,
            publisher_user=actor
        )
        return jsonify({
            "message": f"Release v{updated_release['version']} (sequence {updated_release['release_sequence']}) published successfully",
            "release": updated_release
        }), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to publish release: {str(e)}"}), 500

@admin_bp.route("/releases/<int:release_id>", methods=["GET"])
@login_required
def get_release_details(release_id: int):
    release = ReleaseManager.get_release_by_id(release_id)
    if not release:
        return jsonify({"error": f"Release ID {release_id} not found"}), 404
    return jsonify({"release": release}), 200

@admin_bp.route("/revoke/<int:release_id>", methods=["POST"])
@login_required
def revoke_release(release_id: int):
    data = request.get_json() or {}
    reason = data.get("reason", "Revoked by administrator").strip()
    if not reason:
        reason = "Revoked by administrator"
    success = ReleaseManager.revoke_release(release_id, reason)
    if success:
        return jsonify({
            "message": f"Release {release_id} revoked successfully",
            "release_id": release_id,
            "revocation_reason": reason
        }), 200
    return jsonify({"error": "Release not found"}), 404

@admin_bp.route("/logs", methods=["GET"])
@login_required
def get_logs():
    limit = int(request.args.get("limit", 100))
    event_type = request.args.get("event_type", "").strip()
    result = request.args.get("result", "").strip()
    search = request.args.get("search", "").strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Dynamic filtering for security events
    sec_query = "SELECT * FROM security_events WHERE 1=1"
    params = []
    if event_type and event_type != "ALL":
        sec_query += " AND event_type = ?"
        params.append(event_type)
    if result and result != "ALL":
        sec_query += " AND result = ?"
        params.append(result)
    if search:
        sec_query += " AND (description LIKE ? OR related_client_or_admin LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    sec_query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(sec_query, params)
    sec_rows = cursor.fetchall()
    
    # Client update activity
    cursor.execute("SELECT * FROM update_activity ORDER BY id DESC LIMIT ?", (limit,))
    act_rows = cursor.fetchall()
    conn.close()
    
    sec_logs = [dict(r) for r in sec_rows]
    act_logs = [dict(r) for r in act_rows]
    return jsonify({
        "security_events": sec_logs,
        "update_activity": act_logs,
        "filters": {
            "event_type": event_type or "ALL",
            "result": result or "ALL",
            "search": search
        }
    }), 200

@admin_bp.route("/stats", methods=["GET"])
@login_required
def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as c FROM releases WHERE status = 'published'")
    pub_count = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM releases WHERE status = 'prepared'")
    prep_count = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM releases WHERE status = 'revoked'")
    rev_count = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM releases")
    total_releases = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM clients")
    client_count = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM security_events")
    sec_count = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM security_events WHERE result = 'BLOCKED'")
    blocked_count = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM update_activity WHERE action = 'INSTALL' AND installation_result = 'SUCCESS'")
    success_installs = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM update_activity")
    total_activity = cursor.fetchone()["c"]
    conn.close()
    
    from server.database.database import get_active_presentation_session
    active_sess = get_active_presentation_session()

    return jsonify({
        "published_releases": pub_count,
        "prepared_releases": prep_count,
        "revoked_releases": rev_count,
        "total_releases": total_releases,
        "active_clients": client_count,
        "security_events": sec_count,
        "blocked_attacks": blocked_count,
        "successful_installs": success_installs,
        "total_activities": total_activity,
        "active_session": active_sess,
        "data_source": "live_sqlite_database"
    }), 200

@admin_bp.route("/presentation-session", methods=["GET"])
@login_required
def get_presentation_session():
    from server.database.database import get_active_presentation_session
    sess = get_active_presentation_session()
    return jsonify({"session": sess}), 200

@admin_bp.route("/new-session", methods=["POST"])
@login_required
def start_new_session_route():
    from flask import current_app
    if not current_app.config.get("DEMO_MODE", False):
        return jsonify({"error": "Starting a new presentation session requires demonstration mode (DEMO_MODE)."}), 403

    csrf_header = request.headers.get("X-CSRF-Token", "").strip()
    expected_csrf = session.get("csrf_token", "")
    if not csrf_header or csrf_header != expected_csrf:
        return jsonify({"error": "Invalid or missing CSRF token"}), 403

    from server.database.database import start_new_presentation_session
    actor = session.get("user", "admin")
    sess = start_new_presentation_session(actor=actor, notes="Triggered from Admin Dashboard UI")
    return jsonify({
        "message": f"New presentation session {sess['session_id']} started successfully. Canonical baseline restored.",
        "session": sess
    }), 200

