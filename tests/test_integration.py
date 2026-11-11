import pytest
import shutil
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from client.updater import ClientUpdater
from common.crypto_engine import sign_metadata, compute_sha256

@pytest.fixture
def test_updater(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir(parents=True, exist_ok=True)
    
    # Init app with 1.0.0
    shutil.copytree(Path("demoapp/versions/1.0.0"), app_dir, dirs_exist_ok=True)
    
    # State file
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({
        "software_id": "demoapp",
        "installed_version": "1.0.0",
        "release_sequence": 1,
        "installed_at": "2026-11-01T00:00:00Z",
        "status": "HEALTHY"
    }), encoding="utf-8")
    
    updater = ClientUpdater(
        server_url="https://127.0.0.1:5000",
        client_id="test-client-1",
        software_id="demoapp",
        trusted_public_key_path=Path("keys/publisher_public.pem"),
        ca_cert_path=Path("certs/ca.crt"),
        state_file_path=state_file,
        target_app_dir=app_dir
    )
    return updater

def test_scenario_3_unauthorized_publisher_rejected(test_updater):
    """
    Scenario 3 / TC07: Attacker creates metadata and signs with attacker private key.
    Client checks signature using trusted publisher public key -> Signature verification fails!
    """
    atk_priv = Path("keys/attacker_private.pem")
    assert atk_priv.exists()
    
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_id": "rel-malicious-1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_size": 1268,
        "package_hash": compute_sha256(Path("storage/packages/demoapp-1.1.0.zip")),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Rogue update from malicious party"
    }
    
    rogue_sig = sign_metadata(atk_priv, metadata)
    
    res = test_updater.run_update_pipeline(override_payload={
        "metadata": metadata,
        "signature": rogue_sig,
        "release_id": 999
    })
    
    assert res["success"] is False
    assert res["error_stage"] == 2
    assert "signature verification failed" in res["message"].lower()

def test_scenario_6_expired_release_rejected(test_updater):
    """
    Scenario 6 / TC14: Update metadata has expiration timestamp in the past.
    Signature is valid, but client rejects expired metadata.
    """
    pub_priv = Path("keys/publisher_private.pem")
    
    past_expiration = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_id": "rel-expired-1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_size": 1268,
        "package_hash": compute_sha256(Path("storage/packages/demoapp-1.1.0.zip")),
        "release_timestamp": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),
        "expiration_timestamp": past_expiration,
        "description": "Legitimate but expired update"
    }
    
    valid_sig = sign_metadata(pub_priv, metadata)
    
    res = test_updater.run_update_pipeline(override_payload={
        "metadata": metadata,
        "signature": valid_sig,
        "release_id": 998
    })
    
    assert res["success"] is False
    assert res["error_stage"] == 3
    assert "expired" in res["message"].lower()

def test_tc13_mismatched_software_id_rejected(test_updater):
    """
    TC13: Software ID in metadata does not match expected software ('demoapp').
    """
    pub_priv = Path("keys/publisher_private.pem")
    metadata = {
        "software_id": "other_application",
        "version": "1.1.0",
        "release_id": "rel-other-1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_size": 1268,
        "package_hash": compute_sha256(Path("storage/packages/demoapp-1.1.0.zip")),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Wrong software target"
    }
    sig = sign_metadata(pub_priv, metadata)
    
    res = test_updater.run_update_pipeline(override_payload={
        "metadata": metadata,
        "signature": sig,
        "release_id": 997
    })
    
    assert res["success"] is False
    assert res["error_stage"] == 3
    assert "mismatched software identifier" in res["message"].lower()

def test_tc18_invalid_https_cert_rejected(test_updater):
    """
    TC18: Client attempts connection to a server presenting a rogue / untrusted certificate.
    TLS certificate verification must reject the connection and fail secure.
    """
    rogue_ca_cert = Path("certs/rogue_ca.crt")
    assert rogue_ca_cert.exists()
    
    # Downloader uses genuine ca.crt. Testing with an untrusted cert or pointing verify to rogue CA
    # ensures client fails if the cert does not match.
    avail, payload, msg = test_updater.check_for_updates(custom_verify=str(rogue_ca_cert))
    assert avail is False
    assert "tls" in msg.lower() or "certificate" in msg.lower() or "failed" in msg.lower()

