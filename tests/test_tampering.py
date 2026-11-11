import pytest
import shutil
from pathlib import Path
from client.verifier import Verifier
from client.installer import SecureInstaller
from common.crypto_engine import compute_sha256, sign_metadata

@pytest.fixture
def test_env(tmp_path):
    pkg_source = Path("storage/packages/demoapp-1.1.0.zip")
    assert pkg_source.exists()
    
    # Copy genuine package to test temp path
    test_pkg = tmp_path / "demoapp-1.1.0.zip"
    shutil.copy(pkg_source, test_pkg)
    
    trusted_key = Path("keys/publisher_public.pem")
    priv_key = Path("keys/publisher_private.pem")
    
    return {
        "pkg_path": test_pkg,
        "trusted_key": trusted_key,
        "priv_key": priv_key,
        "app_dir": tmp_path / "app_current"
    }

def test_tc04_package_tampering_rejected(test_env):
    """
    Scenario 2 / TC04: Tamper with a file or append payload to the package.
    SHA-256 verification must detect this and reject installation.
    """
    pkg_path = test_env["pkg_path"]
    original_hash = compute_sha256(pkg_path)
    
    # Tamper with the package by injecting malicious bytes
    with open(pkg_path, "ab") as f:
        f.write(b"\x90\x90\x90_MALICIOUS_PAYLOAD_TAMPERING_TEST")
        
    tampered_hash = compute_sha256(pkg_path)
    assert original_hash != tampered_hash
    
    verifier = Verifier(test_env["trusted_key"])
    valid, msg = verifier.verify_package_hash(pkg_path, original_hash)
    
    assert valid is False
    assert "integrity check failed" in msg.lower()

def test_tc05_metadata_tampering_rejected(test_env):
    """
    Scenario 5 / TC05: Change version or package hash in signed metadata while
    retaining original signature. Ed25519 verification must fail.
    """
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_id": "rel-demoapp-1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_size": 1268,
        "package_hash": compute_sha256(test_env["pkg_path"]),
        "release_timestamp": "2026-11-11T00:00:00Z",
        "expiration_timestamp": "2030-01-01T00:00:00Z"
    }
    
    # Generate genuine publisher signature
    sig = sign_metadata(test_env["priv_key"], metadata)
    
    verifier = Verifier(test_env["trusted_key"])
    
    # Genuine metadata passes
    ok, _ = verifier.verify_publisher_signature(metadata, sig)
    assert ok is True
    
    # Tamper with package_hash
    tampered_meta1 = dict(metadata)
    tampered_meta1["package_hash"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ok1, msg1 = verifier.verify_publisher_signature(tampered_meta1, sig)
    assert ok1 is False
    assert "verification failed" in msg1.lower()
    
    # Tamper with version
    tampered_meta2 = dict(metadata)
    tampered_meta2["version"] = "2.0.0"
    ok2, msg2 = verifier.verify_publisher_signature(tampered_meta2, sig)
    assert ok2 is False
    assert "verification failed" in msg2.lower()

