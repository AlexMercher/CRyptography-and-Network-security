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

# Resource & archive safety limits for ZIP bomb and exhaustion defense
MAX_ARCHIVE_SIZE = 16 * 1024 * 1024            # 16 MB maximum compressed archive size
MAX_TOTAL_UNCOMPRESSED_SIZE = 32 * 1024 * 1024  # 32 MB cumulative uncompressed size
MAX_SINGLE_FILE_SIZE = 16 * 1024 * 1024          # 16 MB maximum single uncompressed file size
MAX_ARCHIVE_MEMBERS = 200                       # Maximum number of files in an archive
MAX_COMPRESSION_RATIO = 50.0                    # Maximum uncompressed:compressed ratio (50:1)

class SecureInstaller:
    def __init__(
        self,
        target_app_dir: Path = None,
        max_archive_size: int = MAX_ARCHIVE_SIZE,
        max_total_uncompressed_size: int = MAX_TOTAL_UNCOMPRESSED_SIZE,
        max_single_file_size: int = MAX_SINGLE_FILE_SIZE,
        max_archive_members: int = MAX_ARCHIVE_MEMBERS,
        max_compression_ratio: float = MAX_COMPRESSION_RATIO
    ):
        self.app_dir = target_app_dir or DEFAULT_APP_DIR
        self.max_archive_size = max_archive_size
        self.max_total_uncompressed_size = max_total_uncompressed_size
        self.max_single_file_size = max_single_file_size
        self.max_archive_members = max_archive_members
        self.max_compression_ratio = max_compression_ratio
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        STAGED_DIR.mkdir(parents=True, exist_ok=True)

    def validate_package_contents(self, zip_path: Path) -> Tuple[bool, str]:
        """
        SR09 / TC15 / ZIP-BOMB DEFENSE: Validates package against Zip Slip,
        directory traversal, excessive compression ratios, oversized files,
        malformed archives, and archive-member exhaustion.
        """
        if not zip_path.exists():
            return False, f"Package file not found: {zip_path}"

        compressed_size = zip_path.stat().st_size
        if compressed_size > self.max_archive_size:
            return False, f"Archive exceeds maximum compressed size ({compressed_size} > {self.max_archive_size} bytes)."
        if compressed_size == 0:
            return False, "Archive file is empty (0 bytes)."

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                members = zf.infolist()
                if len(members) > self.max_archive_members:
                    return False, f"Archive member count exceeds maximum limit ({len(members)} > {self.max_archive_members})."

                total_uncompressed = 0
                seen_filenames = set()

                for member in members:
                    name = member.filename

                    # Check for absolute path or drive letter
                    if os.path.isabs(name) or (len(name) > 1 and name[1] == ":") or name.startswith("/") or name.startswith("\\"):
                        return False, f"Zip Slip / Path Traversal detected: absolute path '{name}'"

                    # Check for parent directory references
                    parts = Path(name).parts
                    if ".." in parts:
                        return False, f"Zip Slip / Path Traversal detected: directory traversal in '{name}'"

                    # Check for dangerous characters (null bytes)
                    if "\x00" in name:
                        return False, f"Invalid archive member name (null byte): '{name}'"

                    # Check for duplicate entries
                    norm_name = os.path.normpath(name).lower()
                    if norm_name in seen_filenames:
                        return False, f"Duplicate archive entry detected: '{name}'"
                    seen_filenames.add(norm_name)

                    # Check for encrypted entries
                    if member.flag_bits & 0x1:
                        return False, f"Encrypted archive entries are not permitted: '{name}'"

                    # Check single file uncompressed size limit
                    if member.file_size > self.max_single_file_size:
                        return False, f"Archive entry '{name}' exceeds single-file limit ({member.file_size} > {self.max_single_file_size} bytes)."

                    total_uncompressed += member.file_size

                # Check cumulative uncompressed size limit
                if total_uncompressed > self.max_total_uncompressed_size:
                    return False, f"Total uncompressed size exceeds limit ({total_uncompressed} > {self.max_total_uncompressed_size} bytes)."

                # Check compression ratio
                effective_compressed = max(compressed_size, 1)
                ratio = total_uncompressed / effective_compressed
                if ratio > self.max_compression_ratio:
                    return False, f"Suspicious compression ratio detected ({ratio:.1f}:1 exceeds max {self.max_compression_ratio}:1)."

            return True, "Archive contents validated: safe structure, no Zip Slip or ZIP bomb detected."
        except zipfile.BadZipFile:
            return False, "Invalid or corrupted ZIP archive."

    def _extract_safely(self, zf: zipfile.ZipFile, stage_target: Path) -> Tuple[bool, str]:
        """
        Safely extracts archive members with strict streaming byte counting to
        prevent ZIP bombs that forge or lie about header sizes.
        """
        cumulative_bytes = 0
        file_count = 0

        for member in zf.infolist():
            target_path = (stage_target / member.filename).resolve()
            # Boundary enforcement: must be strictly inside stage_target
            try:
                target_path.relative_to(stage_target.resolve())
            except ValueError:
                return False, f"Extraction aborted: target path '{target_path}' escapes staging sandbox."

            if member.is_dir() or member.filename.endswith("/"):
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            target_path.parent.mkdir(parents=True, exist_ok=True)
            file_count += 1
            if file_count > self.max_archive_members:
                return False, f"Extraction aborted: maximum file count exceeded ({file_count} > {self.max_archive_members})."

            file_bytes = 0
            with zf.open(member) as src, open(target_path, "wb") as dst:
                while True:
                    chunk = src.read(4096)
                    if not chunk:
                        break
                    chunk_len = len(chunk)

                    if file_bytes + chunk_len > self.max_single_file_size:
                        return False, f"Extraction aborted: entry '{member.filename}' exceeded single-file limit during extraction ({file_bytes + chunk_len} > {self.max_single_file_size} bytes)."
                    if cumulative_bytes + chunk_len > self.max_total_uncompressed_size:
                        return False, f"Extraction aborted: cumulative extracted size exceeded limit during extraction ({cumulative_bytes + chunk_len} > {self.max_total_uncompressed_size} bytes)."

                    dst.write(chunk)
                    file_bytes += chunk_len
                    cumulative_bytes += chunk_len

        return True, "Extraction completed safely."

    def install(
        self,
        zip_path: Path,
        expected_version: str,
        simulate_failure_during_activation: bool = False
    ) -> Tuple[bool, str]:
        """
        FR14 / SR10 / TC16 / TC17: Stages, activates, and verifies update with safe rollback.
        """
        # Step 1: Validate archive contents (pre-extraction check)
        is_safe, msg = self.validate_package_contents(zip_path)
        if not is_safe:
            return False, f"Installation aborted during archive validation: {msg}"

        # Step 2: Backup current version if it exists
        backup_app_dir = BACKUP_DIR / "current_backup"
        if self.app_dir.exists():
            if backup_app_dir.exists():
                shutil.rmtree(backup_app_dir)
            shutil.copytree(self.app_dir, backup_app_dir)

        # Step 3: Extract to staged location with streaming limits
        stage_target = STAGED_DIR / f"stage_{expected_version}"
        if stage_target.exists():
            shutil.rmtree(stage_target)
        stage_target.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                extract_ok, extract_msg = self._extract_safely(zf, stage_target)
                if not extract_ok:
                    raise RuntimeError(extract_msg)

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


