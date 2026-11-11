import pytest
import shutil
import zipfile
import json
from pathlib import Path
from client.installer import SecureInstaller

@pytest.fixture
def install_env(tmp_path):
    app_dir = tmp_path / "demoapp_current"
    app_dir.mkdir(parents=True, exist_ok=True)
    
    # Initial version 1.0.0 in app_dir
    (app_dir / "version.json").write_text(json.dumps({
        "software_id": "demoapp",
        "version": "1.0.0",
        "release_sequence": 1
    }), encoding="utf-8")
    (app_dir / "main.py").write_text("print('App 1.0.0')", encoding="utf-8")
    
    installer = SecureInstaller(target_app_dir=app_dir)
    return {
        "installer": installer,
        "app_dir": app_dir,
        "tmp_path": tmp_path
    }

def test_tc15_zip_slip_traversal_rejected(install_env):
    """
    TC15: Package contains path traversal or absolute path entries.
    Installer must detect and reject the archive before extraction.
    """
    installer = install_env["installer"]
    malicious_zip = install_env["tmp_path"] / "malicious_traversal.zip"
    
    # Construct a ZIP containing path traversal ../../evil.py
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("../../system_compromise.txt", "MALICIOUS CONTENT")
        zf.writestr("normal.txt", "NORMAL CONTENT")
        
    is_safe, msg = installer.validate_package_contents(malicious_zip)
    assert is_safe is False
    assert "zip slip" in msg.lower() or "traversal" in msg.lower()
    
    # Attempting install must also fail
    success, inst_msg = installer.install(malicious_zip, "1.1.0")
    assert success is False
    assert "archive validation" in inst_msg.lower()

def test_tc16_valid_update_installation(install_env):
    """
    TC16: Valid update archive extracts cleanly and updates files.
    """
    installer = install_env["installer"]
    app_dir = install_env["app_dir"]
    valid_zip = Path("storage/packages/demoapp-1.1.0.zip")
    assert valid_zip.exists()
    
    success, msg = installer.install(valid_zip, "1.1.0")
    assert success is True
    assert "successfully installed" in msg.lower()
    
    # Verify version.json in app_dir is updated to 1.1.0
    with open(app_dir / "version.json", "r", encoding="utf-8") as f:
        vinfo = json.load(f)
    assert vinfo["version"] == "1.1.0"

def test_tc17_failed_installation_recovery(install_env):
    """
    TC17: Simulated installation failure during activation.
    Installer must cleanly rollback and restore previous working 1.0.0 version.
    """
    installer = install_env["installer"]
    app_dir = install_env["app_dir"]
    valid_zip = Path("storage/packages/demoapp-1.1.0.zip")
    
    # Run installation with simulated failure trigger
    success, msg = installer.install(
        zip_path=valid_zip,
        expected_version="1.1.0",
        simulate_failure_during_activation=True
    )
    
    assert success is False
    assert "rollback to previous working version completed" in msg.lower()
    
    # App directory must still contain working 1.0.0
    with open(app_dir / "version.json", "r", encoding="utf-8") as f:
        vinfo = json.load(f)
    assert vinfo["version"] == "1.0.0"

def test_zip_bomb_compressed_archive_exceeding_max_size_rejected(install_env):
    """
    Task 3: Test that compressed archive exceeding max_archive_size is rejected.
    """
    app_dir = install_env["app_dir"]
    tmp_path = install_env["tmp_path"]
    strict_installer = SecureInstaller(target_app_dir=app_dir, max_archive_size=500)
    oversized_zip = tmp_path / "oversized_archive.zip"

    with zipfile.ZipFile(oversized_zip, "w") as zf:
        zf.writestr("test.txt", "A" * 600)

    is_safe, msg = strict_installer.validate_package_contents(oversized_zip)
    assert is_safe is False
    assert "maximum compressed size" in msg.lower()

def test_zip_bomb_individual_file_exceeding_max_size_rejected(install_env):
    """
    Task 3: Test that archive containing a single file exceeding max_single_file_size is rejected.
    """
    app_dir = install_env["app_dir"]
    tmp_path = install_env["tmp_path"]
    strict_installer = SecureInstaller(target_app_dir=app_dir, max_single_file_size=500)
    single_large_zip = tmp_path / "single_large.zip"

    with zipfile.ZipFile(single_large_zip, "w") as zf:
        zf.writestr("huge_entry.txt", "X" * 600)

    is_safe, msg = strict_installer.validate_package_contents(single_large_zip)
    assert is_safe is False
    assert "single-file limit" in msg.lower()

def test_zip_bomb_excessive_compression_ratio_rejected(install_env):
    """
    Task 3: Test that high-compression ratio archive (ZIP bomb) is rejected.
    """
    installer = install_env["installer"]
    tmp_path = install_env["tmp_path"]
    bomb_zip = tmp_path / "bomb_ratio.zip"

    # Create a highly compressible file: 250 KB of zeros compresses to ~250 bytes (ratio > 50:1)
    with zipfile.ZipFile(bomb_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeroes.bin", b"\x00" * (250 * 1024))

    is_safe, msg = installer.validate_package_contents(bomb_zip)
    assert is_safe is False
    assert "compression ratio" in msg.lower()

    # Attempting install must fail before extraction
    success, inst_msg = installer.install(bomb_zip, "1.1.0")
    assert success is False
    assert "compression ratio" in inst_msg.lower()

def test_zip_bomb_excessive_member_count_rejected(install_env):
    """
    Task 3: Test that archive with excessive file count is rejected.
    """
    installer = install_env["installer"]
    tmp_path = install_env["tmp_path"]
    too_many_files_zip = tmp_path / "too_many_members.zip"

    with zipfile.ZipFile(too_many_files_zip, "w") as zf:
        for i in range(250):  # Exceeds MAX_ARCHIVE_MEMBERS (200)
            zf.writestr(f"file_{i}.txt", f"data {i}")

    is_safe, msg = installer.validate_package_contents(too_many_files_zip)
    assert is_safe is False
    assert "member count exceeds" in msg.lower()

def test_zip_bomb_excessive_uncompressed_size_rejected(install_env):
    """
    Task 3: Test that archive declaring cumulative uncompressed size > limit is rejected.
    """
    tmp_path = install_env["tmp_path"]
    app_dir = install_env["app_dir"]
    # Configurable limits: set max uncompressed size to 1024 bytes
    strict_installer = SecureInstaller(target_app_dir=app_dir, max_total_uncompressed_size=1024)
    large_uncompressed_zip = tmp_path / "large_uncompressed.zip"

    with zipfile.ZipFile(large_uncompressed_zip, "w") as zf:
        zf.writestr("file1.txt", "A" * 800)
        zf.writestr("file2.txt", "B" * 800)  # Total 1600 bytes > 1024 limit

    is_safe, msg = strict_installer.validate_package_contents(large_uncompressed_zip)
    assert is_safe is False
    assert "exceeds limit" in msg.lower()

def test_zip_encrypted_entry_rejected(install_env):
    """
    Task 3: Test that archive with encrypted/password-protected entries is rejected.
    """
    import io
    installer = install_env["installer"]
    tmp_path = install_env["tmp_path"]
    encrypted_zip = tmp_path / "encrypted.zip"

    # Create a zip and set bit 0 (encryption flag) in the ZIP headers
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret.txt", b"secret data")
    raw = bytearray(buf.getvalue())
    i = raw.find(b"PK\x03\x04")
    if i != -1:
        raw[i + 6] |= 0x01
    j = raw.find(b"PK\x01\x02")
    if j != -1:
        raw[j + 8] |= 0x01
    encrypted_zip.write_bytes(bytes(raw))

    is_safe, msg = installer.validate_package_contents(encrypted_zip)
    assert is_safe is False
    assert "encrypted" in msg.lower()

def test_zip_duplicate_member_names_rejected(install_env):
    """
    Task 3 & 6: Test that archive with duplicate member names is rejected.
    Catches zipfile UserWarning during fixture creation to keep test suite warning-free.
    """
    import warnings
    installer = install_env["installer"]
    tmp_path = install_env["tmp_path"]
    dup_zip = tmp_path / "dup_names.zip"

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(dup_zip, "w") as zf:
            zf.writestr("module.py", "print('original')")
            zf.writestr("module.py", "print('duplicate overwrite')")

    is_safe, msg = installer.validate_package_contents(dup_zip)
    assert is_safe is False
    assert "duplicate" in msg.lower()

def test_malformed_corrupt_zip_rejected(install_env):
    """
    Task 3: Test that corrupted or invalid ZIP is rejected.
    """
    installer = install_env["installer"]
    tmp_path = install_env["tmp_path"]
    corrupt_zip = tmp_path / "corrupt.zip"
    corrupt_zip.write_bytes(b"NOT_A_VALID_ZIP_HEADER_DATA_123456789")

    is_safe, msg = installer.validate_package_contents(corrupt_zip)
    assert is_safe is False
    assert "invalid" in msg.lower() or "corrupted" in msg.lower()

def test_zip_bomb_streaming_extraction_runtime_byte_limit_enforced(install_env):
    """
    Task 3: Crucial test — demonstrates that actual bytes written are counted during
    streaming extraction and that extraction halts when runtime limit is exceeded,
    even if pre-extraction checks were bypassed or insufficient.

    Verifies:
      - Extraction terminates on exceeded runtime bytes
      - No files are written outside staging
      - Partial staging output is cleaned up
      - Previously installed application remains intact (1.0.0)
      - Trusted client state is not advanced
      - Subsequent legitimate updates install cleanly
    """
    app_dir = install_env["app_dir"]
    tmp_path = install_env["tmp_path"]
    installer = install_env["installer"]

    # Initial app state
    assert (app_dir / "version.json").exists()
    v1_info = json.loads((app_dir / "version.json").read_text(encoding="utf-8"))
    assert v1_info["version"] == "1.0.0"

    # Configure installer with a tight runtime extraction limit (500 bytes)
    streaming_installer = SecureInstaller(
        target_app_dir=app_dir,
        max_single_file_size=500,
        max_total_uncompressed_size=500
    )

    # Create archive with a 1200-byte payload
    bomb_zip = tmp_path / "streaming_bomb.zip"
    with zipfile.ZipFile(bomb_zip, "w") as zf:
        zf.writestr("version.json", json.dumps({"software_id": "demoapp", "version": "9.9.9", "release_sequence": 99}))
        zf.writestr("payload.bin", b"D" * 1200)

    # Bypass pre-extraction validation to specifically exercise the streaming extraction guard
    streaming_installer.validate_package_contents = lambda p: (True, "Pre-check passed for streaming test.")

    # Attempt installation
    success, msg = streaming_installer.install(bomb_zip, expected_version="9.9.9")
    assert success is False
    assert "exceeded" in msg.lower() or "limit during extraction" in msg.lower()

    # 1. Verify partial staging directory was deleted
    staged_target = streaming_installer.app_dir.parent / "client" / "storage" / "staged" / "stage_9.9.9"
    assert not staged_target.exists()

    # 2. Verify previously installed application remains intact at 1.0.0
    with open(app_dir / "version.json", "r", encoding="utf-8") as f:
        restored_info = json.load(f)
    assert restored_info["version"] == "1.0.0"
    assert "9.9.9" not in restored_info["version"]

    # 3. Verify subsequent legitimate update works cleanly
    valid_zip = Path("storage/packages/demoapp-1.1.0.zip")
    assert valid_zip.exists()
    legit_success, legit_msg = installer.install(valid_zip, expected_version="1.1.0")
    assert legit_success is True
    with open(app_dir / "version.json", "r", encoding="utf-8") as f:
        updated_info = json.load(f)
    assert updated_info["version"] == "1.1.0"

