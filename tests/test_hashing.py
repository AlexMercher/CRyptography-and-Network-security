import pytest
import tempfile
from pathlib import Path
from common.crypto_engine import compute_sha256

def test_sha256_deterministic_bytes():
    data = b"Hello, Secure Software Update System!"
    hash1 = compute_sha256(data)
    hash2 = compute_sha256(data)
    assert hash1 == hash2
    assert len(hash1) == 64
    assert hash1 == "bf6e6a6ec079f64ee49eca1346f9b7dde20fc0ff9be8024947c624093bda0480"

def test_sha256_file_vs_bytes():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"Cryptographic Verification Engine Test Content")
        temp_path = tf.name
    try:
        file_hash = compute_sha256(temp_path)
        bytes_hash = compute_sha256(b"Cryptographic Verification Engine Test Content")
        assert file_hash == bytes_hash
    finally:
        Path(temp_path).unlink(missing_ok=True)

def test_sha256_tamper_detection():
    orig_content = b"ORIGINAL_UPDATE_PACKAGE_PAYLOAD_v1.1.0"
    tampered_content = b"TAMPERED_UPDATE_PACKAGE_PAYLOAD_v1.1.0"
    
    hash_orig = compute_sha256(orig_content)
    hash_tampered = compute_sha256(tampered_content)
    
    assert hash_orig != hash_tampered

def test_sha256_demoapp_packages():
    pkg_dir = Path("storage/packages")
    for v in ["1.0.0", "1.1.0", "1.2.0"]:
        pkg_file = pkg_dir / f"demoapp-{v}.zip"
        assert pkg_file.exists()
        h = compute_sha256(pkg_file)
        assert len(h) == 64
        assert h != "0" * 64
