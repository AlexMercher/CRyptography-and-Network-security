import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from common.crypto_engine import (
    generate_ed25519_keypair,
    canonicalize_json,
    sign_metadata,
    verify_metadata,
    sign_data,
    verify_signature,
    compare_versions,
    is_release_expired
)

@pytest.fixture
def keys():
    pub_priv = Path("keys/publisher_private.pem")
    pub_pub = Path("keys/publisher_public.pem")
    atk_priv = Path("keys/attacker_private.pem")
    atk_pub = Path("keys/attacker_public.pem")
    assert pub_priv.exists() and pub_pub.exists()
    return {
        "pub_priv": pub_priv.read_bytes(),
        "pub_pub": pub_pub.read_bytes(),
        "atk_priv": atk_priv.read_bytes(),
        "atk_pub": atk_pub.read_bytes(),
    }

def test_canonicalize_json_order_independent():
    d1 = {"b": 2, "a": 1, "nested": {"y": 20, "x": 10}}
    d2 = {"nested": {"x": 10, "y": 20}, "a": 1, "b": 2}
    assert canonicalize_json(d1) == canonicalize_json(d2)

def test_valid_signature_verification(keys):
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "expiration_timestamp": "2030-01-01T00:00:00Z"
    }
    sig = sign_metadata(keys["pub_priv"], metadata)
    assert isinstance(sig, str) and len(sig) > 0
    
    # Client verifies using publisher public key
    valid = verify_metadata(keys["pub_pub"], metadata, sig)
    assert valid is True

def test_metadata_tampering_fails_verification(keys):
    """TC05: Modify signed metadata fields, signature must fail."""
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_sequence": 2,
        "package_hash": "original_hash_value"
    }
    sig = sign_metadata(keys["pub_priv"], metadata)
    
    # Tamper with the package_hash or version in metadata
    tampered_metadata = dict(metadata)
    tampered_metadata["package_hash"] = "modified_malicious_hash"
    
    assert verify_metadata(keys["pub_pub"], tampered_metadata, sig) is False
    
    # Tamper with version
    tampered_version = dict(metadata)
    tampered_version["version"] = "1.2.0"
    assert verify_metadata(keys["pub_pub"], tampered_version, sig) is False

def test_unauthorized_key_fails_verification(keys):
    """TC07: Attacker signs release using attacker private key; client rejects it."""
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_sequence": 2,
        "package_hash": "attacker_payload_hash"
    }
    # Attacker signs with rogue private key
    rogue_sig = sign_metadata(keys["atk_priv"], metadata)
    
    # Client verifies with trusted publisher public key -> MUST FAIL
    assert verify_metadata(keys["pub_pub"], metadata, rogue_sig) is False

def test_invalid_signature_string(keys):
    """TC06: Random / corrupted signature string fails."""
    metadata = {"test": "data"}
    assert verify_metadata(keys["pub_pub"], metadata, "invalid_base64_sig") is False
    assert verify_metadata(keys["pub_pub"], metadata, "") is False

def test_expiration_check():
    """TC14: Release expiration checking."""
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    
    assert is_release_expired(future) is False
    assert is_release_expired(past) is True
    # Corrupted date string should fail secure
    assert is_release_expired("invalid-date") is True

def test_semver_comparison():
    assert compare_versions("1.1.0", "1.0.0") == 1
    assert compare_versions("1.0.0", "1.1.0") == -1
    assert compare_versions("1.1.0", "1.1.0") == 0
    assert compare_versions("2.0.0", "1.9.9") == 1
    assert compare_versions("1.0.1", "1.0.0") == 1

