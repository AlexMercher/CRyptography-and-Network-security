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

