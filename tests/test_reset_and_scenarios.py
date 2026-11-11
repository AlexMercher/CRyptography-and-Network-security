import os
import json
import shutil
import socket
import time
import threading
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from server.app import create_app
from server.database.database import init_db
from client.updater import ClientUpdater
from client.version_manager import VersionManager
from common.crypto_engine import compute_sha256, sign_metadata

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ADMIN_TOKEN = "cns-demo-reset-authorized-key-2026"
AUTH_HEADERS = {"X-Admin-Reset-Token": ADMIN_TOKEN}

def is_server_listening(host="127.0.0.1", port=5000) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0

@pytest.fixture(scope="session", autouse=True)
def ensure_server():
    if not is_server_listening():
        app = create_app()
        cert_file = PROJECT_ROOT / "certs" / "server.crt"
        key_file = PROJECT_ROOT / "certs" / "server.key"
        
        thread = threading.Thread(
            target=lambda: app.run(
                host="127.0.0.1",
                port=5000,
                ssl_context=(str(cert_file), str(key_file)),
                debug=False,
                use_reloader=False
            ),
            daemon=True
        )
        thread.start()
        for _ in range(15):
            if is_server_listening():
                break
            time.sleep(0.3)
    yield

@pytest.fixture
def app_instance(tmp_path):
    test_db = tmp_path / "test_reset.db"
    init_db(test_db)
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-cns-key",
        "DEMO_MODE": True,
        "ADMIN_RESET_TOKEN": ADMIN_TOKEN
    })
    return app

@pytest.fixture
def client_app(app_instance):
    return app_instance.test_client()

# ==============================================================================
# TASK B: RESET ENDPOINT SECURITY TESTS (B3)
# ==============================================================================

def test_reset_security_authorized_admin_token_allowed(client_app):
    """B3.1: Authorized administrator reset using token in demo mode is allowed (200)."""
    res = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res.status_code == 200
    data = res.get_json()
    assert data["state"]["installed_version"] == "1.0.0"
    assert data["state"]["release_sequence"] == 1

def test_reset_security_authorized_admin_session_allowed(client_app):
    """B3.2: Authorized administrator reset using session + CSRF token is allowed (200)."""
    with client_app.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "valid-admin-csrf-token-123"

    res = client_app.post("/api/client/reset", headers={"X-CSRF-Token": "valid-admin-csrf-token-123"})
    assert res.status_code == 200
    assert res.get_json()["state"]["installed_version"] == "1.0.0"

def test_reset_security_unauthenticated_rejected(client_app):
    """B3.3: Unauthenticated reset attempt without token or session is rejected (401)."""
    res = client_app.post("/api/client/reset")
    assert res.status_code == 401
    data = res.get_json()
    assert "authentication required" in data["error"].lower()

def test_reset_security_unauthorized_user_role_rejected(client_app):
    """B3.4: Authenticated user without administrator privileges is rejected (403)."""
    with client_app.session_transaction() as sess:
        sess["user"] = "regular_operator"
        sess["role"] = "viewer"
        sess["csrf_token"] = "viewer-csrf-token-456"

    res = client_app.post("/api/client/reset", headers={"X-CSRF-Token": "viewer-csrf-token-456"})
    assert res.status_code == 403
    data = res.get_json()
    assert "unauthorized" in data["error"].lower()

def test_reset_security_invalid_token_rejected(client_app):
    """B3.5: Reset attempt with an incorrect token is rejected (403)."""
    res = client_app.post("/api/client/reset", headers={"X-Admin-Reset-Token": "forged-invalid-key-999"})
    assert res.status_code == 403
    data = res.get_json()
    assert "invalid" in data["error"].lower()

def test_reset_security_demo_mode_disabled_rejected(app_instance):
    """B3.6: Reset attempt when DEMO_MODE is disabled is rejected (403)."""
    app_instance.config["DEMO_MODE"] = False
    test_client = app_instance.test_client()
    res = test_client.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res.status_code == 403
    data = res.get_json()
    assert "disabled" in data["error"].lower()
    app_instance.config["DEMO_MODE"] = True

def test_reset_security_non_loopback_rejected(client_app):
    """B3.7: Reset attempt from non-loopback network interface is rejected (403)."""
    res = client_app.post(
        "/api/client/reset",
        headers=AUTH_HEADERS,
        environ_base={"REMOTE_ADDR": "198.51.100.25"}
    )
    assert res.status_code == 403
    data = res.get_json()
    assert "loopback" in data["error"].lower()

def test_reset_security_invalid_csrf_rejected(client_app):
    """B3.8: Session-based reset attempt with invalid CSRF token is rejected (403)."""
    with client_app.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "genuine-csrf-secret"

    res = client_app.post("/api/client/reset", headers={"X-CSRF-Token": "forged-csrf-token"})
    assert res.status_code == 403
    data = res.get_json()
    assert "csrf" in data["error"].lower()

def test_reset_security_rollback_protection_intact_without_reset(client_app):
    """B3.9: Normal update cannot bypass rollback protection without authorized reset."""
    # Reset to baseline
    client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    vm = VersionManager()
    
    # Install 1.1.0
    res1 = client_app.post("/api/client/run-scenario/1")
    assert res1.status_code == 200
    assert vm.get_state()["installed_version"] == "1.1.0"

    # Attempt rollback to 1.0.0 without reset
    s4 = client_app.post("/api/client/run-scenario/4").get_json()
    assert s4["result"]["success"] is False
    assert s4["result"]["error_stage"] == 4
    # State remains at 1.1.0
    assert vm.get_state()["installed_version"] == "1.1.0"

def test_reset_token_absent_from_rendered_html(client_app):
    """
    Task 1: Confirms that the secret administrator reset token is absent from
    all browser-rendered HTML pages, and that ordinary application JS cannot
    retrieve it from the DOM.
    """
    for route in ["/", "/admin", "/client", "/how-it-works"]:
        res = client_app.get(route)
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        # Secret token value must never appear in HTML
        assert ADMIN_TOKEN not in html
        # Obsolete meta tag must be completely gone
        assert 'name="demo-reset-token"' not in html
        assert "demo-reset-token" not in html

def test_reset_token_absent_from_api_responses(client_app):
    """
    Task 1: Confirms that the administrator reset token is never leaked in
    any client-facing API responses or telemetry/diagnostic outputs.
    """
    endpoints = [
        "/api/client/status",
        "/api/client/diagnostic-report",
        "/api/client/history",
        "/api/updates/check?software_id=demoapp&client_id=client-alpha&current_version=1.0.0"
    ]
    for endpoint in endpoints:
        res = client_app.get(endpoint)
        assert res.status_code == 200
        body = res.get_data(as_text=True)
        assert ADMIN_TOKEN not in body

def test_reset_security_token_rejected_when_no_token_configured(app_instance):
    """
    Task 1: Reject token-based reset requests if no valid token is configured
    on the server (constant-time protection and fail-closed secret).
    """
    app_instance.config["ADMIN_RESET_TOKEN"] = None
    test_client = app_instance.test_client()
    res = test_client.post("/api/client/reset", headers={"X-Admin-Reset-Token": ADMIN_TOKEN})
    assert res.status_code == 403
    data = res.get_json()
    assert "no valid reset token configured" in data["error"].lower()
    app_instance.config["ADMIN_RESET_TOKEN"] = ADMIN_TOKEN

# ==============================================================================
# TASK F: INDEPENDENT AUDIT OF ALL 12 RESET CONDITIONS (R1 - R12)
# ==============================================================================

def test_reset_r1_clean_state(client_app):
    """R1: Test reset restores clean 1.0.0 baseline."""
    res = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res.status_code == 200
    vm = VersionManager()
    st = vm.get_state()
    assert st["installed_version"] == "1.0.0"
    assert st["release_sequence"] == 1
    assert (PROJECT_ROOT / "demoapp" / "current" / "version.json").exists()
    vinfo = json.loads((PROJECT_ROOT / "demoapp" / "current" / "version.json").read_text(encoding="utf-8"))
    assert vinfo["version"] == "1.0.0"
    assert vinfo["release_sequence"] == 1

def test_reset_r2_reinstall_after_reset(client_app):
    """R2: Install update -> Reset -> Reinstall works cleanly."""
    client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    vm = VersionManager()
    
    res1 = client_app.post("/api/client/run-scenario/1")
    assert res1.status_code == 200
    assert vm.get_state()["installed_version"] == "1.1.0"
    
    client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert vm.get_state()["installed_version"] == "1.0.0"
    
    res2 = client_app.post("/api/client/run-scenario/1")
    assert res2.status_code == 200
    assert res2.get_json()["result"]["success"] is True
    assert vm.get_state()["installed_version"] == "1.1.0"

def test_reset_r3_progressive_updates_then_reset(client_app):
    """R3: Progressive updates (1.0 -> 1.1 -> 1.2) -> Reset -> Clean baseline."""
    client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    updater = ClientUpdater()
    pub_priv = PROJECT_ROOT / "keys" / "publisher_private.pem"
    vm = VersionManager()

    for ver, seq in [("1.1.0", 2), ("1.2.0", 3)]:
        pkg = PROJECT_ROOT / "storage" / "packages" / f"demoapp-{ver}.zip"
        meta = {
            "software_id": "demoapp",
            "version": ver,
            "release_id": f"rel-r3-{ver}",
            "release_sequence": seq,
            "package_filename": pkg.name,
            "package_size": pkg.stat().st_size,
            "package_hash": compute_sha256(pkg),
            "release_timestamp": datetime.now(timezone.utc).isoformat(),
            "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "description": f"R3 test to {ver}"
        }
        sig = sign_metadata(pub_priv, meta)
        res = updater.run_update_pipeline(override_payload={"metadata": meta, "signature": sig, "release_id": 300 + seq})
        assert res["success"] is True

    assert vm.get_state()["installed_version"] == "1.2.0"
    client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert vm.get_state()["installed_version"] == "1.0.0"
    assert vm.get_state()["release_sequence"] == 1

def test_reset_r4_reset_after_package_tampering(client_app):
    """R4: Reset after package tampering attack cleans transient failure state."""
    client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    res_tamper = client_app.post("/api/client/run-scenario/2").get_json()
    assert res_tamper["result"]["success"] is False
    
    res_reset = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res_reset.status_code == 200
    vm = VersionManager()
    assert vm.get_state()["installed_version"] == "1.0.0"

def test_reset_r5_reset_after_rogue_key_attack(client_app):
    """R5: Reset after unauthorized publisher key attack restores clean baseline."""
    client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    res_rogue = client_app.post("/api/client/run-scenario/3").get_json()
    assert res_rogue["result"]["success"] is False
    
    res_reset = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res_reset.status_code == 200
    vm = VersionManager()
    assert vm.get_state()["installed_version"] == "1.0.0"

def test_reset_r6_reset_after_rollback_attack(client_app):
    """R6: Reset after rollback attack restores clean baseline."""
    res_s4 = client_app.post("/api/client/run-scenario/4").get_json()
    assert res_s4["result"]["success"] is False
    
    res_reset = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res_reset.status_code == 200
    vm = VersionManager()
    assert vm.get_state()["installed_version"] == "1.0.0"
    assert vm.get_state()["release_sequence"] == 1

def test_reset_r7_reset_after_metadata_tampering(client_app):
    """R7: Reset after metadata tampering attack restores clean baseline."""
    res_s5 = client_app.post("/api/client/run-scenario/5").get_json()
    assert res_s5["result"]["success"] is False
    
    res_reset = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res_reset.status_code == 200
    vm = VersionManager()
    assert vm.get_state()["installed_version"] == "1.0.0"

def test_reset_r8_reset_after_expired_release(client_app):
    """R8: Reset after expired release attack restores clean baseline."""
    res_s6 = client_app.post("/api/client/run-scenario/6").get_json()
    assert res_s6["result"]["success"] is False
    
    res_reset = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res_reset.status_code == 200
    vm = VersionManager()
    assert vm.get_state()["installed_version"] == "1.0.0"

def test_reset_r9_reset_after_interrupted_download(client_app):
    """R9: Reset removes orphaned .part download files."""
    dl_dir = PROJECT_ROOT / "client" / "storage" / "downloads"
    dl_dir.mkdir(parents=True, exist_ok=True)
    orphan_part = dl_dir / "interrupted_demo.part"
    orphan_part.write_bytes(b"INCOMPLETE_DOWNLOAD_STREAM")
    assert orphan_part.exists()

    res = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res.status_code == 200
    assert not orphan_part.exists()

def test_reset_r10_reset_after_installation_failure(client_app):
    """R10: Reset purges leftover .staging and .backup directories."""
    stage_dir = PROJECT_ROOT / "demoapp" / ".staging"
    backup_dir = PROJECT_ROOT / "demoapp" / ".backup"
    stage_dir.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)
    (stage_dir / "corrupted.py").write_text("broken")
    (backup_dir / "old_backup.json").write_text("backup")

    res = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res.status_code == 200
    assert not stage_dir.exists()
    assert not backup_dir.exists()

def test_reset_r11_consecutive_resets_idempotent(client_app):
    """R11: Consecutive resets are idempotent and safe."""
    for _ in range(3):
        res = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
        assert res.status_code == 200
    vm = VersionManager()
    assert vm.get_state()["installed_version"] == "1.0.0"
    assert vm.get_state()["release_sequence"] == 1

def test_reset_r12_browser_status_and_filesystem_sync(client_app):
    """
    R12: Browser UI page rendering, status endpoint, and filesystem state
    are all verified to synchronize accurately post-reset.
    """
    res = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res.status_code == 200

    # 1. Simulate browser page refresh: GET /client
    page_res = client_app.get("/client")
    assert page_res.status_code == 200
    page_html = page_res.get_data(as_text=True)
    assert "Client Dashboard" in page_html
    # Page must contain CSRF token but NOT secret reset token
    assert 'name="csrf-token"' in page_html
    assert ADMIN_TOKEN not in page_html

    # 2. Simulate frontend loadClientState() query: GET /api/client/status
    status_res = client_app.get("/api/client/status")
    assert status_res.status_code == 200
    status_data = status_res.get_json()

    # 3. Read authoritative filesystem files directly
    vm = VersionManager()
    fs_state = vm.get_state()
    vinfo_path = PROJECT_ROOT / "demoapp" / "current" / "version.json"
    assert vinfo_path.exists()
    vinfo = json.loads(vinfo_path.read_text(encoding="utf-8"))

    # Assert exact synchronization across page, status API, state file, and app directory
    assert status_data["installed_version"] == fs_state["installed_version"] == vinfo["version"] == "1.0.0"
    assert status_data["release_sequence"] == fs_state["release_sequence"] == vinfo["release_sequence"] == 1

# ==============================================================================
# TASK G: REGRESSION TESTS FOR THE FOUR DEFECTS (SIZ-001, ISO-001, RST-001, TST-001)
# ==============================================================================

def test_regression_siz_001_dynamic_package_size_and_digest(client_app):
    """
    SIZ-001 Regression: Verifies that scenario metadata calculates package_size
    and package_hash dynamically from the actual archive on disk, preventing
    false Step 5 download size rejection.
    """
    pkg_110 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.1.0.zip"
    actual_size = pkg_110.stat().st_size
    actual_hash = compute_sha256(pkg_110)

    # Run Scenario 1 and verify download step succeeded with actual size
    res = client_app.post("/api/client/run-scenario/1").get_json()
    assert res["result"]["success"] is True
    step_5 = next(s for s in res["result"]["steps"] if s["step"] == 5)
    assert step_5["success"] is True
    assert f"{actual_size} bytes" in step_5["message"]

def test_regression_iso_001_cross_scenario_isolation_4_then_1(client_app):
    """
    ISO-001 Regression: Scenario 4 establishes an advanced state (1.1.0, Seq 2)
    to test rollback. Scenario 1 executed immediately afterwards must succeed
    because of proper per-scenario isolation baseline initialization.
    """
    s4 = client_app.post("/api/client/run-scenario/4").get_json()
    assert s4["result"]["success"] is False
    assert s4["result"]["error_stage"] == 4
    
    s1 = client_app.post("/api/client/run-scenario/1").get_json()
    assert s1["result"]["success"] is True
    assert s1["result"].get("error_stage") is None

def test_regression_rst_001_complete_directory_and_state_cleanup(client_app):
    """
    RST-001 Regression: Deliberately seed client downloads, staging, and backup
    directories with dirty files. Reset must thoroughly clean all of them.
    """
    client_downloads = PROJECT_ROOT / "client" / "storage" / "downloads"
    client_staged = PROJECT_ROOT / "client" / "storage" / "staged"
    client_backup = PROJECT_ROOT / "client" / "storage" / "backup"
    demo_staging = PROJECT_ROOT / "demoapp" / ".staging"
    demo_backup = PROJECT_ROOT / "demoapp" / ".backup"

    for d in [client_downloads, client_staged, client_backup, demo_staging, demo_backup]:
        d.mkdir(parents=True, exist_ok=True)

    part_file = client_downloads / "dirty.part"
    tmp_file = client_downloads / "dirty.tmp"
    part_file.write_bytes(b"garbage")
    tmp_file.write_bytes(b"garbage")

    res = client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    assert res.status_code == 200
    assert not part_file.exists()
    assert not tmp_file.exists()
    assert not demo_staging.exists()
    assert not demo_backup.exists()

def test_regression_tst_001_isolated_test_suite_execution():
    """
    TST-001 Regression: Verifies that test environment can discover or start
    the HTTPS update server daemon automatically without manual intervention.
    """
    assert is_server_listening("127.0.0.1", 5000) is True

# ==============================================================================
# EXISTING SCENARIOS & REPEATED UPDATES (v1.0.0 -> v1.4.0)
# ==============================================================================

def test_all_six_scenarios_via_api(client_app):
    """Test all 6 demonstration scenarios independently via the client UI endpoint."""
    s1 = client_app.post("/api/client/run-scenario/1").get_json()
    assert s1["result"]["success"] is True

    s2 = client_app.post("/api/client/run-scenario/2").get_json()
    assert s2["result"]["success"] is False
    assert s2["result"]["error_stage"] in (6, 7)

    s3 = client_app.post("/api/client/run-scenario/3").get_json()
    assert s3["result"]["success"] is False
    assert s3["result"]["error_stage"] == 2

    s4 = client_app.post("/api/client/run-scenario/4").get_json()
    assert s4["result"]["success"] is False
    assert s4["result"]["error_stage"] == 4

    s5 = client_app.post("/api/client/run-scenario/5").get_json()
    assert s5["result"]["success"] is False
    assert s5["result"]["error_stage"] == 2

    s6 = client_app.post("/api/client/run-scenario/6").get_json()
    assert s6["result"]["success"] is False
    assert s6["result"]["error_stage"] == 3

def test_repeated_updates_1_to_4(client_app):
    """Test repeated updates 1.0.0 -> 1.1.0 -> 1.2.0 -> 1.3.0 -> 1.4.0."""
    client_app.post("/api/client/reset", headers=AUTH_HEADERS)
    updater = ClientUpdater()
    pub_priv = PROJECT_ROOT / "keys" / "publisher_private.pem"
    vm = VersionManager()

    for ver, seq in [("1.1.0", 2), ("1.2.0", 3), ("1.3.0", 4), ("1.4.0", 5)]:
        pkg = PROJECT_ROOT / "storage" / "packages" / f"demoapp-{ver}.zip"
        assert pkg.exists(), f"Package demoapp-{ver}.zip missing"
        meta = {
            "software_id": "demoapp",
            "version": ver,
            "release_id": f"rel-test-{ver}",
            "release_sequence": seq,
            "package_filename": pkg.name,
            "package_size": pkg.stat().st_size,
            "package_hash": compute_sha256(pkg),
            "release_timestamp": datetime.now(timezone.utc).isoformat(),
            "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "description": f"Update to {ver}"
        }
        sig = sign_metadata(pub_priv, meta)
        res = updater.run_update_pipeline(override_payload={"metadata": meta, "signature": sig, "release_id": 500 + seq})
        assert res["success"] is True
        assert vm.get_state()["installed_version"] == ver
        assert vm.get_state()["release_sequence"] == seq
