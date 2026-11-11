import json
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify

from client.updater import ClientUpdater
from client.version_manager import VersionManager
from common.crypto_engine import compute_sha256, sign_metadata

client_ui_bp = Blueprint("client_ui", __name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

@client_ui_bp.route("/status", methods=["GET"])
def get_client_status():
    vm = VersionManager()
    state = vm.get_state()
    return jsonify(state), 200

def reset_client_baseline_internal(actor: str = "internal-system") -> dict:
    """
    Authoritative internal implementation of baseline reset.
    Restores state.json (1.0.0, seq 1), restores demoapp/current from 1.0.0,
    purges temporary/staged/backup/download files, and logs audit entries.
    """
    from server.database.database import log_update_activity, log_security_event

    # 1. Reset state.json
    state_file = PROJECT_ROOT / "client" / "storage" / "state.json"
    initial_state = {
        "software_id": "demoapp",
        "installed_version": "1.0.0",
        "release_sequence": 1,
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "status": "HEALTHY",
        "last_rollback_attempt": None
    }
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(initial_state, indent=2), encoding="utf-8")
    
    # 2. Reset current app directory from authoritative 1.0.0 version
    app_current = PROJECT_ROOT / "demoapp" / "current"
    v1_source = PROJECT_ROOT / "demoapp" / "versions" / "1.0.0"
    if app_current.exists():
        shutil.rmtree(app_current)
    shutil.copytree(v1_source, app_current)

    # 3. Clean client staging, backup, and temporary download directories
    client_storage = PROJECT_ROOT / "client" / "storage"
    backup_dir = client_storage / "backup"
    staged_dir = client_storage / "staged"
    downloads_dir = client_storage / "downloads"

    if backup_dir.exists():
        shutil.rmtree(backup_dir, ignore_errors=True)
        backup_dir.mkdir(parents=True, exist_ok=True)

    if staged_dir.exists():
        shutil.rmtree(staged_dir, ignore_errors=True)
        staged_dir.mkdir(parents=True, exist_ok=True)

    if downloads_dir.exists():
        for tmp_file in downloads_dir.glob("*.part"):
            tmp_file.unlink(missing_ok=True)
        for tmp_file in downloads_dir.glob("*.tmp"):
            tmp_file.unlink(missing_ok=True)

    # Clean demoapp temp staging if left from partial installs
    demo_staging = PROJECT_ROOT / "demoapp" / ".staging"
    demo_backup = PROJECT_ROOT / "demoapp" / ".backup"
    if demo_staging.exists():
        shutil.rmtree(demo_staging, ignore_errors=True)
    if demo_backup.exists():
        shutil.rmtree(demo_backup, ignore_errors=True)

    # 4. Log audit and security activity
    try:
        log_update_activity(
            client_id="client-alpha",
            action="RESET",
            verification_result="SUCCESS",
            installation_result="SUCCESS",
            details=f"Demonstration client state reset to v1.0.0 baseline (Sequence: 1) by {actor}"
        )
        log_security_event(
            event_type="DEMO_CLIENT_RESET",
            description=f"Client reset to DemoApp v1.0.0 baseline for demonstration testing (authorized by {actor})",
            result="SUCCESS",
            related_user=actor
        )
    except Exception:
        pass

    return {
        "message": "Client reset to DemoApp v1.0.0 baseline successfully.",
        "state": initial_state,
        "cleaned_directories": ["backup", "staged", "temp_downloads"]
    }

@client_ui_bp.route("/reset", methods=["POST"])
def reset_client_to_baseline():
    """
    Resets client demoapp to 1.0.0 baseline for clean repeatable demonstrations.
    Requires:
      1. DEMO_MODE must be enabled in application config.
      2. Caller must originate from local loopback (127.0.0.1, ::1).
      3. Caller must be an authorized administrator (via active admin session + valid CSRF,
         or via X-Admin-Reset-Token / Authorization Bearer token).
    Cleans temporary downloads, backups, staging areas, restores state.json,
    and logs an audit trail record in the database.
    """
    import hmac
    from flask import current_app, session
    from server.database.database import log_security_event

    remote_addr = request.remote_addr or ""
    configured_reset_token = current_app.config.get("ADMIN_RESET_TOKEN")
    is_demo_mode = current_app.config.get("DEMO_MODE", False)

    # 1. Check DEMO_MODE (Defaults to False - Fail Closed)
    if not is_demo_mode:
        log_security_event(
            event_type="DEMO_RESET_BLOCKED_PRODUCTION",
            description="Rejected reset attempt because demonstration mode is disabled (fail-closed default).",
            result="BLOCKED",
            related_user=session.get("user", "anonymous")
        )
        return jsonify({
            "error": "Client reset is disabled when demonstration mode is not active.",
            "status": 403
        }), 403

    # 2. Check Loopback (do not trust X-Forwarded-For)
    allowed_loopbacks = ("127.0.0.1", "::1", "localhost", "testclient")
    if remote_addr not in allowed_loopbacks:
        log_security_event(
            event_type="DEMO_RESET_BLOCKED_NETWORK",
            description=f"Rejected reset attempt from non-loopback address: {remote_addr}",
            result="BLOCKED",
            related_user=session.get("user", "anonymous")
        )
        return jsonify({
            "error": "Reset endpoint is restricted to local loopback interface.",
            "status": 403
        }), 403

    # 3. Check Authentication & Authorization
    auth_header = request.headers.get("Authorization", "")
    bearer_token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
    token_header = request.headers.get("X-Admin-Reset-Token", "").strip()
    provided_token = token_header or bearer_token

    user = session.get("user")
    role = session.get("role", "admin" if user == "admin" else "user")

    authorized = False
    auth_user = "anonymous"

    # Option A: Command-line / test token authorization (constant-time verification)
    if provided_token:
        if not configured_reset_token:
            log_security_event(
                event_type="DEMO_RESET_BLOCKED_NO_TOKEN_CONFIGURED",
                description="Rejected token-based reset attempt: no administrative token configured on server.",
                result="BLOCKED",
                related_user=user or "token-bearer"
            )
            return jsonify({
                "error": "Token-based reset is disabled: no valid reset token configured on server.",
                "status": 403
            }), 403

        if hmac.compare_digest(provided_token, str(configured_reset_token)):
            authorized = True
            auth_user = user or "token-admin"
        else:
            log_security_event(
                event_type="DEMO_RESET_BLOCKED_INVALID_TOKEN",
                description="Rejected reset attempt with invalid administrative token.",
                result="BLOCKED",
                related_user=user or "token-bearer"
            )
            return jsonify({
                "error": "Invalid administrative reset token.",
                "status": 403
            }), 403

    # Option B: Browser-based administrator session with CSRF protection
    elif user:
        if role != "admin" and user != "admin":
            log_security_event(
                event_type="DEMO_RESET_BLOCKED_UNAUTHORIZED_ROLE",
                description=f"Rejected reset attempt for non-admin user: {user} (role: {role})",
                result="BLOCKED",
                related_user=user
            )
            return jsonify({
                "error": "Unauthorized: administrative privileges required.",
                "status": 403
            }), 403

        # Validate CSRF for session-based request
        csrf_header = request.headers.get("X-CSRF-Token", "").strip()
        expected_csrf = session.get("csrf_token", "")
        if not csrf_header or csrf_header != expected_csrf:
            log_security_event(
                event_type="DEMO_RESET_BLOCKED_CSRF",
                description=f"Rejected reset attempt due to missing or invalid CSRF token for user: {user}",
                result="BLOCKED",
                related_user=user
            )
            return jsonify({
                "error": "Invalid or missing CSRF token.",
                "status": 403
            }), 403

        authorized = True
        auth_user = user

    if not authorized:
        log_security_event(
            event_type="DEMO_RESET_BLOCKED_UNAUTHENTICATED",
            description="Rejected unauthenticated reset attempt (no admin session or token).",
            result="BLOCKED",
            related_user="anonymous"
        )
        return jsonify({
            "error": "Authentication required to invoke client reset.",
            "status": 401
        }), 401

    res_data = reset_client_baseline_internal(actor=auth_user)
    return jsonify(res_data), 200

@client_ui_bp.route("/run-update", methods=["POST"])
def run_client_update():
    updater = ClientUpdater(
        server_url="https://127.0.0.1:5000",
        client_id="demo-client-ui"
    )
    result = updater.run_update_pipeline()
    return jsonify(result), 200

@client_ui_bp.route("/run-scenario/<int:scenario_num>", methods=["POST"])
def run_scenario(scenario_num: int):
    updater = ClientUpdater(
        server_url="https://127.0.0.1:5000",
        client_id="demo-scenario-runner"
    )
    pkg_110 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.1.0.zip"
    pub_priv = PROJECT_ROOT / "keys" / "publisher_private.pem"
    atk_priv = PROJECT_ROOT / "keys" / "attacker_private.pem"
    
    if scenario_num == 1:
        # Scenario 1: Genuine Successful Update (1.0.0 -> 1.1.0)
        # Ensure clean 1.0.0 baseline before executing Scenario 1 to prevent isolation bleed
        vm = VersionManager()
        vm.commit_installed_version("1.0.0", 1)
        app_current = PROJECT_ROOT / "demoapp" / "current"
        v1_source = PROJECT_ROOT / "demoapp" / "versions" / "1.0.0"
        if app_current.exists():
            shutil.rmtree(app_current)
        shutil.copytree(v1_source, app_current)

        meta = {
            "software_id": "demoapp",
            "version": "1.1.0",
            "release_id": "rel-demoapp-1.1.0-official",
            "release_sequence": 2,
            "package_filename": "demoapp-1.1.0.zip",
            "package_size": pkg_110.stat().st_size,
            "package_hash": compute_sha256(pkg_110),
            "release_timestamp": datetime.now(timezone.utc).isoformat(),
            "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "description": "Genuine DemoApp 1.1.0 update"
        }
        sig = sign_metadata(pub_priv, meta)
        res = updater.run_update_pipeline(override_payload={
            "metadata": meta,
            "signature": sig,
            "release_id": 1
        })
        return jsonify({
            "scenario": 1,
            "title": "Scenario 1 — Successful Update",
            "expected": "Update authentic, verified and installed successfully.",
            "result": res
        })
        
    elif scenario_num == 2:
        # Scenario 2: Package Tampering (SHA-256 mismatch)
        vm = VersionManager()
        vm.commit_installed_version("1.0.0", 1)
        meta = {
            "software_id": "demoapp",
            "version": "1.1.0",
            "release_id": "rel-demoapp-1.1.0-tamper",
            "release_sequence": 2,
            "package_filename": "demoapp-1.1.0.zip",
            "package_size": pkg_110.stat().st_size,
            "package_hash": compute_sha256(pkg_110),
            "release_timestamp": datetime.now(timezone.utc).isoformat(),
            "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "description": "DemoApp 1.1.0 update before transit tampering"
        }
        sig = sign_metadata(pub_priv, meta)
        res = updater.run_update_pipeline(
            override_payload={"metadata": meta, "signature": sig, "release_id": 1},
            simulate_tampered_package=True
        )
        return jsonify({
            "scenario": 2,
            "title": "Scenario 2 — Package Tampering Attack",
            "expected": "SHA-256 mismatch detected. Update rejected before installation.",
            "result": res
        })
        
    elif scenario_num == 3:
        # Scenario 3: Unauthorized Publisher (Attacker Ed25519 key)
        vm = VersionManager()
        vm.commit_installed_version("1.0.0", 1)
        meta = {
            "software_id": "demoapp",
            "version": "1.1.0",
            "release_id": "rel-rogue-1.1.0",
            "release_sequence": 2,
            "package_filename": "demoapp-1.1.0.zip",
            "package_size": pkg_110.stat().st_size,
            "package_hash": compute_sha256(pkg_110),
            "release_timestamp": datetime.now(timezone.utc).isoformat(),
            "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "description": "Malicious release signed by unauthorized attacker key"
        }
        rogue_sig = sign_metadata(atk_priv, meta)
        res = updater.run_update_pipeline(override_payload={
            "metadata": meta,
            "signature": rogue_sig,
            "release_id": 999
        })
        return jsonify({
            "scenario": 3,
            "title": "Scenario 3 — Unauthorized Publisher Attack",
            "expected": "Ed25519 signature verification fails against trusted public key.",
            "result": res
        })
        
    elif scenario_num == 4:
        # Scenario 4: Rollback Attack
        # Ensure client state is at 1.1.0 or higher first, then attempt to supply 1.0.0 release
        vm = VersionManager()
        vm.commit_installed_version("1.1.0", 2)
        
        pkg_100 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.0.0.zip"
        meta = {
            "software_id": "demoapp",
            "version": "1.0.0",
            "release_id": "rel-demoapp-1.0.0",
            "release_sequence": 1,
            "package_filename": "demoapp-1.0.0.zip",
            "package_size": pkg_100.stat().st_size,
            "package_hash": compute_sha256(pkg_100),
            "release_timestamp": "2026-11-01T00:00:00Z",
            "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "description": "Legitimate old release replayed"
        }
        valid_sig = sign_metadata(pub_priv, meta)
        res = updater.run_update_pipeline(override_payload={
            "metadata": meta,
            "signature": valid_sig,
            "release_id": 100
        })
        return jsonify({
            "scenario": 4,
            "title": "Scenario 4 — Rollback Attack",
            "expected": "Signature passes, but client version policy rejects older release.",
            "result": res
        })
        
    elif scenario_num == 5:
        # Scenario 5: Metadata Tampering
        vm = VersionManager()
        vm.commit_installed_version("1.0.0", 1)
        meta = {
            "software_id": "demoapp",
            "version": "1.1.0",
            "release_id": "rel-demoapp-1.1.0",
            "release_sequence": 2,
            "package_filename": "demoapp-1.1.0.zip",
            "package_size": pkg_110.stat().st_size,
            "package_hash": compute_sha256(pkg_110),
            "release_timestamp": datetime.now(timezone.utc).isoformat(),
            "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "description": "Valid update metadata before tampering"
        }
        original_sig = sign_metadata(pub_priv, meta)
        # Attacker tampers with package_hash
        meta["package_hash"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        res = updater.run_update_pipeline(override_payload={
            "metadata": meta,
            "signature": original_sig,
            "release_id": 995
        })
        return jsonify({
            "scenario": 5,
            "title": "Scenario 5 — Metadata Tampering Attack",
            "expected": "Ed25519 verification fails because metadata hash was modified.",
            "result": res
        })
        
    elif scenario_num == 6:
        # Scenario 6: Expired Release
        vm = VersionManager()
        vm.commit_installed_version("1.0.0", 1)
        past_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        meta = {
            "software_id": "demoapp",
            "version": "1.1.0",
            "release_id": "rel-expired-1.1.0",
            "release_sequence": 2,
            "package_filename": "demoapp-1.1.0.zip",
            "package_size": pkg_110.stat().st_size,
            "package_hash": compute_sha256(pkg_110),
            "release_timestamp": (datetime.now(timezone.utc) - timedelta(days=60)).isoformat(),
            "expiration_timestamp": past_time,
            "description": "Expired release metadata"
        }
        valid_sig = sign_metadata(pub_priv, meta)
        res = updater.run_update_pipeline(override_payload={
            "metadata": meta,
            "signature": valid_sig,
            "release_id": 994
        })
        return jsonify({
            "scenario": 6,
            "title": "Scenario 6 — Expired Release Attack",
            "expected": "Signature passes, but client expiration validation rejects it.",
            "result": res
        })
        
    return jsonify({"error": f"Unknown scenario {scenario_num}"}), 400

@client_ui_bp.route("/history", methods=["GET"])
def get_client_history():
    from server.database.database import get_db_connection
    client_id = request.args.get("client_id", "").strip()
    limit = int(request.args.get("limit", 50))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    if client_id:
        cursor.execute(
            "SELECT * FROM update_activity WHERE client_id = ? ORDER BY id DESC LIMIT ?",
            (client_id, limit)
        )
    else:
        cursor.execute("SELECT * FROM update_activity ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    history = [dict(r) for r in rows]
    return jsonify({"history": history}), 200

@client_ui_bp.route("/diagnostic-report", methods=["GET"])
def get_diagnostic_report():
    vm = VersionManager()
    state = vm.get_state()
    now_utc = datetime.now(timezone.utc).isoformat()
    
    app_current = PROJECT_ROOT / "demoapp" / "current"
    vinfo_file = app_current / "version.json"
    app_meta = {}
    if vinfo_file.exists():
        try:
            with open(vinfo_file, "r", encoding="utf-8") as f:
                app_meta = json.load(f)
        except Exception:
            pass
            
    trusted_key_file = PROJECT_ROOT / "client" / "trusted_keys" / "publisher_public.pem"
    trusted_ca_file = PROJECT_ROOT / "client" / "trusted_certs" / "ca.crt"
    
    from server.services.release_manager import ReleaseManager
    latest_server_rel = ReleaseManager.get_latest_release("demoapp")
    
    from server.database.database import get_db_connection
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM update_activity ORDER BY id DESC LIMIT 10")
    recent_acts = [dict(r) for r in c.fetchall()]
    c.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 10")
    recent_secs = [dict(r) for r in c.fetchall()]
    conn.close()

    report = {
        "report_generated_utc": now_utc,
        "system": "Secure Software Update System (CNS)",
        "client_id": "client-alpha",
        "client_state": state,
        "runtime_application": {
            "path": str(app_current),
            "healthy": vinfo_file.exists(),
            "manifest": app_meta
        },
        "cryptographic_anchors": {
            "publisher_public_key_present": trusted_key_file.exists(),
            "publisher_public_key_size_bytes": trusted_key_file.stat().st_size if trusted_key_file.exists() else 0,
            "root_ca_certificate_present": trusted_ca_file.exists(),
            "root_ca_certificate_size_bytes": trusted_ca_file.stat().st_size if trusted_ca_file.exists() else 0,
            "transport_security": "HTTPS / TLS 1.3 enforced",
            "signature_algorithm": "Ed25519 (RFC 8032)",
            "digest_algorithm": "SHA-256 (FIPS 180-4)"
        },
        "server_status": {
            "latest_available_version": latest_server_rel["version"] if latest_server_rel else "None",
            "latest_available_sequence": latest_server_rel["release_sequence"] if latest_server_rel else 0,
            "latest_package_hash": latest_server_rel["package_hash"] if latest_server_rel else "None"
        },
        "recent_activity_audit": recent_acts,
        "recent_security_incidents": recent_secs
    }
    return jsonify(report), 200

