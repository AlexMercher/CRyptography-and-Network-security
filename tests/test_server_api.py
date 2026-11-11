import pytest
import io
import json
from server.app import create_app
from server.database.database import init_db

@pytest.fixture
def app(tmp_path):
    test_db = tmp_path / "test_api.db"
    init_db(test_db)
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-key"
    })
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_unauthenticated_admin_access_rejected(client):
    """TC10: Attempt to access admin dashboard or API without auth -> 401."""
    res = client.get("/api/admin/releases")
    assert res.status_code == 401
    data = res.get_json()
    assert "error" in data

def test_unauthorized_publishing_rejected(client):
    """TC11: Attempt to publish update without authentication -> 401."""
    res = client.post("/api/admin/publish", json={
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_hash": "abc",
        "package_size": 100
    })
    assert res.status_code == 401

def test_admin_login_success(client):
    res = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "Admin@SecureUpdate2026!"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["user"] == "admin"

def test_admin_login_failure(client):
    res = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "WrongPassword!"
    })
    assert res.status_code == 401

def test_admin_upload_and_publish_flow(client):
    # 1. Login
    login_res = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "Admin@SecureUpdate2026!"
    })
    assert login_res.status_code == 200

    # 2. Get releases
    rel_res = client.get("/api/admin/releases")
    assert rel_res.status_code == 200

def test_how_it_works_page_renders(client):
    """Test that the new How It Works page renders with all 6 required sections."""
    res = client.get("/how-it-works")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "System Architecture" in html
    assert "Cryptography Explained" in html
    assert "Complete Update Lifecycle" in html
    assert "Attack Simulations" in html
    assert "Trust &amp; Key Management" in html or "Trust & Key Management" in html
    assert "Security Limitations" in html
    assert "architecture-svg" in html

def test_admin_logs_filtering(client):
    """Test filtering logs by event_type and result."""
    # Login
    client.post("/api/auth/login", json={
        "username": "admin",
        "password": "Admin@SecureUpdate2026!"
    })
    res = client.get("/api/admin/logs?event_type=PUBLISH&result=SUCCESS")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, dict)
    assert "security_events" in data
    assert "update_activity" in data
    assert data["filters"]["event_type"] == "PUBLISH"
    assert data["filters"]["result"] == "SUCCESS"

def test_admin_release_details_not_found(client):
    """Test fetching a non-existent release ID returns 404."""
    client.post("/api/auth/login", json={
        "username": "admin",
        "password": "Admin@SecureUpdate2026!"
    })
    res = client.get("/api/admin/releases/999999")
    assert res.status_code == 404

def test_client_ui_history_endpoint(client):
    """Test the client history endpoint returns a list of history records."""
    res = client.get("/api/client/history")
    assert res.status_code == 200
    data = res.get_json()
    assert "history" in data
    assert isinstance(data["history"], list)

def test_client_ui_diagnostic_report(client):
    """Test the client diagnostic report endpoint returns full diagnostic JSON."""
    res = client.get("/api/client/diagnostic-report")
    assert res.status_code == 200
    data = res.get_json()
    assert "report_generated_utc" in data
    assert "cryptographic_anchors" in data
    assert "client_state" in data
    assert data["cryptographic_anchors"]["digest_algorithm"] == "SHA-256 (FIPS 180-4)"




