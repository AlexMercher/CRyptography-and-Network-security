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

