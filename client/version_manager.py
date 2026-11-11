import json
from pathlib import Path
from typing import Dict, Any, Tuple
from datetime import datetime, timezone
from common.crypto_engine import compare_versions

DEFAULT_STATE_FILE = Path(__file__).resolve().parent / "storage" / "state.json"

class VersionManager:
    """
    FR12 / SR05: Maintains trusted local installed version state.
    Provides strict version and sequence rollback protection.
    """
    def __init__(self, state_file_path: Path = None):
        self.state_file = state_file_path or DEFAULT_STATE_FILE
        self._ensure_state_file()

    def _ensure_state_file(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.state_file.exists():
            initial_state = {
                "software_id": "demoapp",
                "installed_version": "1.0.0",
                "release_sequence": 1,
                "installed_at": datetime.now(timezone.utc).isoformat(),
                "status": "HEALTHY",
                "last_rollback_attempt": None
            }
            self.state_file.write_text(json.dumps(initial_state, indent=2), encoding="utf-8")

    def get_state(self) -> Dict[str, Any]:
        with open(self.state_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def validate_version_sequence(self, candidate_version: str, candidate_sequence: int) -> Tuple[bool, str]:
        """
        Rollback & Replay Protection (FR12, SR05, TC08, TC09):
        An update is valid only if:
        1. candidate_version is strictly newer than installed_version.
        2. candidate_sequence is strictly greater than current release_sequence.
        """
        current_state = self.get_state()
        installed_v = current_state["installed_version"]
        installed_seq = current_state["release_sequence"]

        # SemVer comparison
        cmp_result = compare_versions(candidate_version, installed_v)
        if cmp_result < 0:
            return False, f"Rollback blocked: candidate version {candidate_version} is older than installed version {installed_v}."
        if cmp_result == 0:
            return False, f"Reinstallation blocked: version {candidate_version} is already installed."

        # Sequence check
        if candidate_sequence <= installed_seq:
            return False, (
                f"Sequence rollback blocked: candidate sequence {candidate_sequence} "
                f"is not greater than current sequence {installed_seq}."
            )

        return True, f"Version {candidate_version} (seq: {candidate_sequence}) is valid and strictly newer than {installed_v} (seq: {installed_seq})."

    def commit_installed_version(self, new_version: str, new_sequence: int):
        """
        Updates local trusted state ONLY after successful installation (FR14 Step 10).
        """
        state = self.get_state()
        state["installed_version"] = new_version
        state["release_sequence"] = new_sequence
        state["installed_at"] = datetime.now(timezone.utc).isoformat()
        state["status"] = "HEALTHY"
        self.state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

