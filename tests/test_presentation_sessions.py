import pytest
import json
import shutil
from pathlib import Path

from server.app import create_app
from server.database.database import (
    init_db,
    ensure_canonical_baseline,
    start_new_presentation_session,
    get_active_presentation_session,
    get_db_connection,
    CANONICAL_RELEASES
)
from server.services.release_manager import ReleaseManager
from client.version_manager import VersionManager
from client.updater import ClientUpdater

PROJECT_ROOT = Path(__file__).resolve().parent.parent

@pytest.fixture
def session_app(tmp_path):
    """Creates an isolated application instance using a temporary database."""
    test_db = tmp_path / "test_sessions.db"
    init_db(test_db)
    # Initialize baseline session on this isolated database
    ensure_canonical_baseline(db_file=test_db, force_new_session=True, actor="pytest_fixture")
    
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-session-key",
        "DEMO_MODE": True,
        "ADMIN_RESET_TOKEN": "cns-demo-reset-authorized-key-2026"
    })
    app.config["DATABASE"] = str(test_db)
    return app, test_db

@pytest.fixture
def test_client(session_app):
    app, test_db = session_app
    client = app.test_client()
    # Log in as admin
    client.post("/api/auth/login", json={
        "username": "admin",
        "password": "Admin@SecureUpdate2026!"
    })
    return client, test_db

# ==============================================================================
# TEST GROUP A: PRESENTATION SESSION PERSISTENCE
# ==============================================================================

def test_a1_initial_session_creation(session_app):
    """A1. Verify that a new presentation session creates the correct initial database state."""
    app, test_db = session_app
    sess = get_active_presentation_session(test_db)
    assert sess is not None
    assert sess["session_id"].startswith("sess-")
    assert sess["status"] == "active"

    # All 5 canonical releases must exist in database
    releases = ReleaseManager.list_releases("demoapp", db_file=test_db)
    assert len(releases) == 5
    rel_map = {r["version"]: r for r in releases}
    assert rel_map["1.0.0"]["status"] == "published"
    for v in ["1.1.0", "1.2.0", "1.3.0", "1.4.0"]:
        assert rel_map[v]["status"] == "prepared"
        assert rel_map[v]["revocation_reason"] is None

    # Client must be at 1.0.0, sequence 1
    vm = VersionManager()
    state = vm.get_state()
    assert state["installed_version"] == "1.0.0"
    assert state["release_sequence"] == 1

def test_a2_revocation_persistence(session_app):
    """A2. Publish 1.1.0 and 1.2.0, then revoke DemoApp 1.2.0. Verify the database records it as revoked."""
    app, test_db = session_app
    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}
    ReleaseManager.publish_prepared_release(releases["1.1.0"], db_file=test_db)
    ReleaseManager.publish_prepared_release(releases["1.2.0"], db_file=test_db)

    success = ReleaseManager.revoke_release(releases["1.2.0"], "Security flaw in distributed probe", db_file=test_db)
    assert success is True

    # Verify directly from database
    rel_updated = ReleaseManager.get_release_by_id(releases["1.2.0"], db_file=test_db)
    assert rel_updated["status"] == "revoked"
    assert "Security flaw" in rel_updated["revocation_reason"]
    assert rel_updated["revoked_at"] is not None

def test_a3_browser_refresh_persistence(test_client):
    """A3. Refresh the Admin Dashboard. Verify version 1.2.0 remains revoked."""
    client, test_db = test_client

    # Publish 1.1.0 and 1.2.0, then revoke 1.2.0
    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}
    ReleaseManager.publish_prepared_release(releases["1.1.0"], db_file=test_db)
    ReleaseManager.publish_prepared_release(releases["1.2.0"], db_file=test_db)
    ReleaseManager.revoke_release(releases["1.2.0"], "Administrative revocation", db_file=test_db)

    # Simulate browser refreshing dashboard
    page_res = client.get("/admin")
    assert page_res.status_code == 200

    # API call triggered by loadReleases()
    api_res = client.get("/api/admin/releases?software_id=demoapp")
    assert api_res.status_code == 200
    data = api_res.get_json()
    rel_120_api = next(r for r in data["releases"] if r["version"] == "1.2.0")
    assert rel_120_api["status"] == "revoked"

def test_a4_navigation_persistence(test_client):
    """A4. Navigate to Client Dashboard and back. Verify version 1.2.0 remains revoked in active session."""
    client, test_db = test_client

    # Publish 1.1.0 and 1.2.0, then revoke 1.2.0
    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}
    ReleaseManager.publish_prepared_release(releases["1.1.0"], db_file=test_db)
    ReleaseManager.publish_prepared_release(releases["1.2.0"], db_file=test_db)
    ReleaseManager.revoke_release(releases["1.2.0"], "Persistent test", db_file=test_db)

    # Navigate to client page
    client.get("/client")
    client.get("/api/client/status")

    # Navigate to how-it-works page
    client.get("/how-it-works")

    # Navigate back to admin dashboard
    client.get("/admin")
    releases_back = ReleaseManager.list_releases("demoapp", db_file=test_db)
    rel_120_back = next(r for r in releases_back if r["version"] == "1.2.0")
    assert rel_120_back["status"] == "revoked"

def test_a5_server_restart_persistence(session_app):
    """A5. Restart the Flask application without starting a new presentation session. Verify 1.2.0 remains revoked."""
    app, test_db = session_app

    # Publish 1.1.0 and 1.2.0, then revoke 1.2.0
    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}
    ReleaseManager.publish_prepared_release(releases["1.1.0"], db_file=test_db)
    ReleaseManager.publish_prepared_release(releases["1.2.0"], db_file=test_db)
    ReleaseManager.revoke_release(releases["1.2.0"], "Pre-restart revocation", db_file=test_db)

    # Simulate server shutdown and normal startup (force_new_session=False)
    # Reconnecting to same DB:
    reconnected_sess = ensure_canonical_baseline(db_file=test_db, force_new_session=False)
    assert reconnected_sess is not None

    # Verify 1.2.0 is STILL revoked
    reloaded_rel = ReleaseManager.get_release_by_id(releases["1.2.0"], db_file=test_db)
    assert reloaded_rel["status"] == "revoked"

def test_a6_client_update_filtering(session_app):
    """A6. Verify that a revoked release is not offered to the client."""
    app, test_db = session_app

    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}
    for v in ["1.1.0", "1.2.0", "1.3.0", "1.4.0"]:
        ReleaseManager.publish_prepared_release(releases[v], db_file=test_db)

    # When 1.4.0, 1.3.0, and 1.2.0 are revoked:
    ReleaseManager.revoke_release(releases["1.4.0"], "Revoked 1.4.0", db_file=test_db)
    ReleaseManager.revoke_release(releases["1.3.0"], "Revoked 1.3.0", db_file=test_db)
    ReleaseManager.revoke_release(releases["1.2.0"], "Revoked 1.2.0", db_file=test_db)

    # Client at 1.0.0 (seq 1) asks for updates:
    # 1.4.0, 1.3.0, 1.2.0 are revoked -> 1.1.0 should be the latest eligible release!
    latest_eligible = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=1)
    assert latest_eligible is not None
    assert latest_eligible["version"] == "1.1.0"
    assert latest_eligible["release_sequence"] == 2

# ==============================================================================
# TEST GROUP B: NEW PRESENTATION SESSION LIFECYCLE
# ==============================================================================

def test_b1_create_new_session_after_revocation(session_app):
    """B1. Starting a new presentation session must restore versions to their initial baseline."""
    app, test_db = session_app

    # Publish 1.1.0, 1.2.0 and revoke 1.2.0
    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}
    ReleaseManager.publish_prepared_release(releases["1.1.0"], db_file=test_db)
    ReleaseManager.publish_prepared_release(releases["1.2.0"], db_file=test_db)
    ReleaseManager.revoke_release(releases["1.2.0"], "Session 1 revocation", db_file=test_db)
    assert ReleaseManager.get_release_by_id(releases["1.2.0"], db_file=test_db)["status"] == "revoked"

    # Start new presentation session
    new_sess = start_new_presentation_session(actor="prof_demo", notes="Demo 2", db_file=test_db)
    assert new_sess["status"] == "active"

    # 1.0.0 is published, 1.1.0 through 1.4.0 are prepared and unrevoked
    rel_100_restored = ReleaseManager.get_release_by_id(releases["1.0.0"], db_file=test_db)
    assert rel_100_restored["status"] == "published"
    rel_120_restored = ReleaseManager.get_release_by_id(releases["1.2.0"], db_file=test_db)
    assert rel_120_restored["status"] == "prepared"
    assert rel_120_restored["revocation_reason"] is None

def test_b2_version_catalogue_restoration(session_app):
    """B2. Verify that versions 1.0.0 through 1.4.0 all exist after starting new session."""
    app, test_db = session_app
    start_new_presentation_session(actor="tester", db_file=test_db)

    releases = ReleaseManager.list_releases("demoapp", db_file=test_db)
    versions = {r["version"] for r in releases}
    assert versions == {"1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"}

def test_b3_client_baseline_restoration(session_app):
    """B3. Verify the client starts at version 1.0.0, sequence 1."""
    app, test_db = session_app

    # Simulate client at 1.3.0
    vm = VersionManager()
    vm.commit_installed_version("1.3.0", 4)
    assert vm.get_state()["installed_version"] == "1.3.0"

    # Start new presentation session
    start_new_presentation_session(actor="tester", db_file=test_db)

    # Client must be restored to 1.0.0, seq 1
    assert vm.get_state()["installed_version"] == "1.0.0"
    assert vm.get_state()["release_sequence"] == 1

def test_b4_session_identifier_unique(session_app):
    """B4. Verify the new presentation session receives a different identifier."""
    app, test_db = session_app
    sess1 = get_active_presentation_session(test_db)
    assert sess1 is not None

    sess2 = start_new_presentation_session(actor="tester", db_file=test_db)
    assert sess2["session_id"] != sess1["session_id"]

    # Verify old session marked closed
    conn = get_db_connection(test_db)
    c = conn.cursor()
    c.execute("SELECT status FROM presentation_sessions WHERE session_id = ?", (sess1["session_id"],))
    row = c.fetchone()
    conn.close()
    assert row["status"] == "closed"

def test_b5_session_isolation(session_app):
    """B5. Verify revocations from previous session are not present in new session."""
    app, test_db = session_app
    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}

    # Publish and revoke in session 1
    ReleaseManager.publish_prepared_release(releases["1.1.0"], db_file=test_db)
    ReleaseManager.revoke_release(releases["1.1.0"], "Revoked in sess 1", db_file=test_db)

    # Start new session
    start_new_presentation_session(actor="new_prof", db_file=test_db)

    # 1.0.0 is published, 1.1.0-1.4.0 are prepared, none revoked
    r100 = ReleaseManager.get_release_by_id(releases["1.0.0"], db_file=test_db)
    assert r100["status"] == "published"
    for v in ["1.1.0", "1.2.0", "1.3.0", "1.4.0"]:
        r = ReleaseManager.get_release_by_id(releases[v], db_file=test_db)
        assert r["status"] == "prepared"
        assert r["revocation_reason"] is None

def test_b6_key_preservation(session_app):
    """B6. Verify publisher keys and TLS trust material are unchanged across new sessions."""
    app, test_db = session_app
    pub_key_path = PROJECT_ROOT / "keys" / "publisher_public.pem"
    priv_key_path = PROJECT_ROOT / "keys" / "publisher_private.pem"
    ca_crt_path = PROJECT_ROOT / "certs" / "ca.crt"

    pub_bytes = pub_key_path.read_bytes()
    priv_bytes = priv_key_path.read_bytes()
    ca_bytes = ca_crt_path.read_bytes()

    # Trigger new presentation session
    start_new_presentation_session(actor="tester", db_file=test_db)

    assert pub_key_path.read_bytes() == pub_bytes
    assert priv_key_path.read_bytes() == priv_bytes
    assert ca_crt_path.read_bytes() == ca_bytes

def test_b7_administrator_preservation(test_client):
    """B7. Verify administrator login continues to work after a new presentation session."""
    client, test_db = test_client

    # Start new presentation session
    start_new_presentation_session(actor="tester", db_file=test_db)

    # Login should succeed with default credentials
    login_res = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "Admin@SecureUpdate2026!"
    })
    assert login_res.status_code == 200
    assert login_res.get_json()["user"] == "admin"

# ==============================================================================
# TEST GROUP C: RELEASE VISIBILITY & CANDIDATE SELECTION
# ==============================================================================

def test_c1_all_five_versions_in_database(session_app):
    """C1. Verify that database contains exactly one valid release record for each intended DemoApp version."""
    app, test_db = session_app
    releases = ReleaseManager.list_releases("demoapp", db_file=test_db)
    assert len(releases) == 5

    expected_sequences = {
        "1.0.0": 1,
        "1.1.0": 2,
        "1.2.0": 3,
        "1.3.0": 4,
        "1.4.0": 5
    }
    for r in releases:
        assert r["version"] in expected_sequences
        assert r["release_sequence"] == expected_sequences[r["version"]]
        assert r["package_size"] > 0
        assert len(r["package_hash"]) == 64
        assert len(r["signature"]) > 20

def test_c2_all_five_versions_in_api(test_client):
    """C2. Verify release listing APIs return all five records."""
    client, test_db = test_client

    # Admin releases API returns all releases and grouped views
    admin_res = client.get("/api/admin/releases?software_id=demoapp")
    assert admin_res.status_code == 200
    data = admin_res.get_json()
    assert len(data["releases"]) == 5
    admin_versions = [r["version"] for r in data["releases"]]
    assert admin_versions == ["1.4.0", "1.3.0", "1.2.0", "1.1.0", "1.0.0"]

    assert len(data["published_releases"]) == 1
    assert data["published_releases"][0]["version"] == "1.0.0"

    assert len(data["prepared_releases"]) == 4
    prepared_versions = [r["version"] for r in data["prepared_releases"]]
    assert prepared_versions == ["1.1.0", "1.2.0", "1.3.0", "1.4.0"]

    # Public client catalog API
    catalog_res = client.get("/api/updates/catalog?software_id=demoapp")
    assert catalog_res.status_code == 200
    cat_data = catalog_res.get_json()["catalog"]
    assert len(cat_data) == 5

def test_c3_all_five_versions_in_admin_dashboard(test_client):
    """C3. Verify stats reflect 1 baseline published and 4 prepared releases initially."""
    client, test_db = test_client
    res = client.get("/admin")
    assert res.status_code == 200

    # Ensure stats reflect all 5 releases: 1 published, 4 prepared
    stats_res = client.get("/api/admin/stats")
    assert stats_res.status_code == 200
    stats = stats_res.get_json()
    assert stats["total_releases"] == 5
    assert stats["published_releases"] == 1
    assert stats["prepared_releases"] == 4

def test_c4_latest_version_detection(session_app):
    """C4. Verify client discovers 1.1.0 only after admin publishes it, and 1.4.0 after all are published."""
    app, test_db = session_app
    # Initially at 1.0.0 baseline: 1.1.0-1.4.0 are prepared (not published) -> no update available
    latest_initial = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=1)
    assert latest_initial is None

    # Admin publishes 1.1.0:
    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}
    ReleaseManager.publish_prepared_release(releases["1.1.0"], db_file=test_db)
    latest_after_110 = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=1)
    assert latest_after_110 is not None
    assert latest_after_110["version"] == "1.1.0"
    assert latest_after_110["release_sequence"] == 2

    # Now publish remaining 1.2.0, 1.3.0, 1.4.0:
    for v in ["1.2.0", "1.3.0", "1.4.0"]:
        ReleaseManager.publish_prepared_release(releases[v], db_file=test_db)

    latest_final = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=1)
    assert latest_final is not None
    assert latest_final["version"] == "1.4.0"
    assert latest_final["release_sequence"] == 5

def test_c5_revoked_intermediate_version(session_app):
    """C5. Revoke 1.2.0. Verify 1.2.0 is excluded from candidates while 1.4.0 remains available."""
    app, test_db = session_app
    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}
    for v in ["1.1.0", "1.2.0", "1.3.0", "1.4.0"]:
        ReleaseManager.publish_prepared_release(releases[v], db_file=test_db)

    # Revoke intermediate 1.2.0
    ReleaseManager.revoke_release(releases["1.2.0"], "Revoked intermediate", db_file=test_db)

    # Latest eligible for client at 1.0.0 is still 1.4.0
    latest = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=1)
    assert latest is not None
    assert latest["version"] == "1.4.0"

    # Client at 1.1.0 (seq 2) checking for updates:
    latest_for_110 = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=2)
    assert latest_for_110 is not None
    assert latest_for_110["version"] == "1.4.0"
    assert latest_for_110["version"] != "1.2.0"

def test_c6_revoked_latest_version(session_app):
    """C6. Revoke 1.4.0. Verify client chooses highest remaining eligible release (1.3.0)."""
    app, test_db = session_app
    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}
    for v in ["1.1.0", "1.2.0", "1.3.0", "1.4.0"]:
        ReleaseManager.publish_prepared_release(releases[v], db_file=test_db)

    # Revoke 1.4.0
    ReleaseManager.revoke_release(releases["1.4.0"], "Revoked latest", db_file=test_db)

    # Latest remaining eligible release must be 1.3.0
    latest = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=1)
    assert latest is not None
    assert latest["version"] == "1.3.0"
    assert latest["release_sequence"] == 4

    # Now revoke 1.3.0 as well -> next should be 1.2.0
    ReleaseManager.revoke_release(releases["1.3.0"], "Revoked 1.3.0", db_file=test_db)
    latest_next = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=1)
    assert latest_next is not None
    assert latest_next["version"] == "1.2.0"
    assert latest_next["release_sequence"] == 3

# ==============================================================================
# TEST GROUP D: PUBLICATION LIFECYCLE, SEQUENCING & PIPELINE STATES
# ==============================================================================

def test_d1_out_of_order_publication_blocked(session_app):
    """D1. Attempting to publish 1.3.0 (sequence 4) while 1.1.0 (sequence 2) is prepared must be rejected."""
    app, test_db = session_app
    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}
    
    with pytest.raises(ValueError) as excinfo:
        ReleaseManager.publish_prepared_release(releases["1.3.0"], db_file=test_db)
    assert "Earlier version" in str(excinfo.value)
    assert "1.1.0" in str(excinfo.value)

def test_d2_e2e_sequential_publication_and_update_lifecycle(session_app):
    """
    D2. End-to-end multi-version update demonstration lifecycle:
    Admin publishes 1.1.0 -> Client updates to 1.1.0.
    Admin publishes 1.2.0 -> Client updates to 1.2.0.
    Admin publishes 1.3.0 -> Client updates to 1.3.0.
    Admin publishes 1.4.0 -> Client updates to 1.4.0.
    """
    app, test_db = session_app
    releases = {r["version"]: r["id"] for r in ReleaseManager.list_releases("demoapp", db_file=test_db)}
    vm = VersionManager()
    
    # 1. Baseline: client is at 1.0.0, sequence 1
    vm.commit_installed_version("1.0.0", 1)
    assert ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=1) is None

    # 2. Publish 1.1.0
    ReleaseManager.publish_prepared_release(releases["1.1.0"], db_file=test_db)
    latest = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=1)
    assert latest["version"] == "1.1.0"
    assert latest["release_sequence"] == 2
    
    # Client executes update to 1.1.0
    vm.commit_installed_version("1.1.0", 2)
    assert vm.get_state()["installed_version"] == "1.1.0"
    assert ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=2) is None

    # 3. Publish 1.2.0 -> Client updates
    ReleaseManager.publish_prepared_release(releases["1.2.0"], db_file=test_db)
    latest = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=2)
    assert latest["version"] == "1.2.0"
    vm.commit_installed_version("1.2.0", 3)

    # 4. Publish 1.3.0 -> Client updates
    ReleaseManager.publish_prepared_release(releases["1.3.0"], db_file=test_db)
    latest = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=3)
    assert latest["version"] == "1.3.0"
    vm.commit_installed_version("1.3.0", 4)

    # 5. Publish 1.4.0 -> Client updates
    ReleaseManager.publish_prepared_release(releases["1.4.0"], db_file=test_db)
    latest = ReleaseManager.get_latest_release("demoapp", db_file=test_db, min_sequence=4)
    assert latest["version"] == "1.4.0"
    vm.commit_installed_version("1.4.0", 5)

    assert vm.get_state()["installed_version"] == "1.4.0"
    assert vm.get_state()["release_sequence"] == 5

def test_d3_pipeline_explicit_step_statuses(session_app):
    """D3. Verify that pipeline verification returns explicit PASSED, FAILED, and SKIPPED statuses."""
    from common.crypto_engine import sign_metadata
    from datetime import datetime, timezone, timedelta

    atk_priv = PROJECT_ROOT / "keys" / "attacker_private.pem"
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_id": "rel-rogue-test",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_size": 1268,
        "package_hash": "a" * 64,
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Rogue update from unauthorized key"
    }
    rogue_sig = sign_metadata(atk_priv, metadata)

    updater = ClientUpdater(
        trusted_public_key_path=PROJECT_ROOT / "keys" / "publisher_public.pem"
    )
    res = updater.run_update_pipeline(override_payload={
        "metadata": metadata,
        "signature": rogue_sig,
        "release_id": 999
    })

    assert res["success"] is False
    assert res["error_stage"] == 2
    assert len(res["steps"]) == 11

    # Step 1: PASSED
    assert res["steps"][0]["step"] == 1
    assert res["steps"][0]["status"] == "PASSED"

    # Step 2: FAILED
    assert res["steps"][1]["step"] == 2
    assert res["steps"][1]["status"] == "FAILED"

    # Steps 3 through 11: SKIPPED
    for i in range(2, 11):
        assert res["steps"][i]["step"] == i + 1
        assert res["steps"][i]["status"] == "SKIPPED"
        assert res["steps"][i]["success"] is False

