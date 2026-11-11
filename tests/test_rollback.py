import pytest
import json
from pathlib import Path
from client.version_manager import VersionManager

@pytest.fixture
def version_mgr(tmp_path):
    state_file = tmp_path / "state.json"
    state_data = {
        "software_id": "demoapp",
        "installed_version": "1.1.0",
        "release_sequence": 2,
        "installed_at": "2026-11-10T12:00:00Z",
        "status": "HEALTHY"
    }
    state_file.write_text(json.dumps(state_data), encoding="utf-8")
    return VersionManager(state_file)

def test_tc08_rollback_older_version_rejected(version_mgr):
    """
    Scenario 4 / TC08: Client has DemoApp 1.1.0.
    Attempting to install DemoApp 1.0.0 (even if genuinely signed) MUST be rejected.
    """
    valid, msg = version_mgr.validate_version_sequence("1.0.0", 1)
    assert valid is False
    assert "rollback blocked" in msg.lower()
    assert "older than installed" in msg.lower()

def test_reinstallation_same_version_rejected(version_mgr):
    """Attempting to reinstall currently active 1.1.0 must be blocked."""
    valid, msg = version_mgr.validate_version_sequence("1.1.0", 2)
    assert valid is False
    assert "already installed" in msg.lower()

def test_tc09_sequence_replay_rejected(version_mgr):
    """
    TC09: Attempting to supply a higher semver but replayed/stale sequence number
    must be rejected.
    """
    # Candidate version says 1.2.0, but sequence is 2 (equal to current) or 1 (lower)
    valid, msg = version_mgr.validate_version_sequence("1.2.0", 2)
    assert valid is False
    assert "sequence rollback blocked" in msg.lower()

    valid2, msg2 = version_mgr.validate_version_sequence("1.2.0", 1)
    assert valid2 is False
    assert "sequence rollback blocked" in msg2.lower()

def test_newer_version_and_sequence_accepted(version_mgr):
    """Valid newer release (1.2.0, seq 3) is accepted."""
    valid, msg = version_mgr.validate_version_sequence("1.2.0", 3)
    assert valid is True
    assert "valid and strictly newer" in msg.lower()

