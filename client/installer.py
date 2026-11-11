import os
import json
import shutil
import zipfile
from pathlib import Path
from typing import Tuple

DEFAULT_APP_DIR = Path(__file__).resolve().parent.parent / "demoapp" / "current"
STORAGE_DIR = Path(__file__).resolve().parent / "storage"
BACKUP_DIR = STORAGE_DIR / "backup"
STAGED_DIR = STORAGE_DIR / "staged"

class SecureInstaller:
    def __init__(self, target_app_dir: Path = None):
        self.app_dir = target_app_dir or DEFAULT_APP_DIR
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        STAGED_DIR.mkdir(parents=True, exist_ok=True)

    def validate_package_contents(self, zip_path: Path) -> Tuple[bool, str]:
        """
        SR09 / TC15: Validates archive paths against Zip Slip and directory traversal.
        """
        if not zip_path.exists():
            return False, f"Package file not found: {zip_path}"

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                for member in zf.infolist():
                    name = member.filename
                    # Check for absolute path or drive letter
                    if os.path.isabs(name) or (len(name) > 1 and name[1] == ":"):
                        return False, f"Zip Slip / Path Traversal detected: absolute path '{name}'"
                    # Check for parent directory references
                    parts = Path(name).parts
                    if ".." in parts:
                        return False, f"Zip Slip / Path Traversal detected: directory traversal in '{name}'"
                    # Check for dangerous characters
                    if "\x00" in name:
                        return False, f"Invalid archive member name (null byte): '{name}'"
            return True, "Archive contents validated: no unsafe paths detected."
        except zipfile.BadZipFile:
            return False, "Invalid or corrupted ZIP archive."

    def install(
        self,
        zip_path: Path,
        expected_version: str,
        simulate_failure_during_activation: bool = False
    ) -> Tuple[bool, str]:
        """
        FR14 / SR10 / TC16 / TC17: Stages, activates, and verifies update with safe rollback.
        """
        # Step 1: Validate archive contents
        is_safe, msg = self.validate_package_contents(zip_path)
        if not is_safe:
            return False, f"Installation aborted during archive validation: {msg}"

        # Step 2: Backup current version if it exists
        backup_app_dir = BACKUP_DIR / "current_backup"
        if self.app_dir.exists():
            if backup_app_dir.exists():
                shutil.rmtree(backup_app_dir)
            shutil.copytree(self.app_dir, backup_app_dir)

        # Step 3: Extract to staged location
        stage_target = STAGED_DIR / f"stage_{expected_version}"
        if stage_target.exists():
            shutil.rmtree(stage_target)
        stage_target.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(stage_target)

            # Step 4: Simulate failure during activation if requested (TC17)
            if simulate_failure_during_activation:
                raise RuntimeError("Simulated failure during update activation stage.")

            # Step 5: Activate update into target app directory
            if self.app_dir.exists():
                shutil.rmtree(self.app_dir)
            shutil.copytree(stage_target, self.app_dir)

            # Step 6: Post-installation verification (verify version.json matches)
            vinfo_path = self.app_dir / "version.json"
            if not vinfo_path.exists():
                raise RuntimeError("Post-installation verification failed: version.json is missing.")
            
            with open(vinfo_path, "r", encoding="utf-8") as f:
                vinfo = json.load(f)
            if vinfo.get("version") != expected_version:
                raise RuntimeError(
                    f"Post-installation verification failed: installed version '{vinfo.get('version')}' "
                    f"does not match expected '{expected_version}'."
                )

            # Cleanup staged files
            shutil.rmtree(stage_target, ignore_errors=True)
            return True, f"Successfully installed version {expected_version} into {self.app_dir}."

        except Exception as e:
            # Step 7: Automatic Rollback to preserved backup (SR10)
            if backup_app_dir.exists():
                if self.app_dir.exists():
                    shutil.rmtree(self.app_dir)
                shutil.copytree(backup_app_dir, self.app_dir)
            shutil.rmtree(stage_target, ignore_errors=True)
            return False, f"Installation failed ({e}). Rollback to previous working version completed."

