import os
import zipfile
from pathlib import Path
from werkzeug.utils import secure_filename
from common.crypto_engine import compute_sha256

PACKAGES_DIR = Path(__file__).resolve().parent.parent.parent / "storage" / "packages"

def validate_and_save_package(file_storage, filename: str = None) -> tuple[str, str, int]:
    """
    Validates uploaded file as a safe zip archive and saves it to storage/packages/.
    Returns (saved_filename, sha256_hash, file_size).
    """
    PACKAGES_DIR.mkdir(parents=True, exist_ok=True)
    clean_name = secure_filename(filename or file_storage.filename)
    if not clean_name.endswith(".zip"):
        raise ValueError("Only .zip packages are supported.")
    
    dest_path = PACKAGES_DIR / clean_name
    file_storage.save(str(dest_path))
    
    # Verify it is a valid zip
    if not zipfile.is_zipfile(dest_path):
        dest_path.unlink(missing_ok=True)
        raise ValueError("Uploaded file is not a valid ZIP archive.")
    
    # Inspect zip members to ensure no path traversal or zip-slip
    with zipfile.ZipFile(dest_path, "r") as zf:
        for member in zf.namelist():
            if member.startswith("/") or member.startswith("\\") or ".." in member:
                dest_path.unlink(missing_ok=True)
                raise ValueError(f"Unsafe path detected inside archive: {member}")
    
    file_size = dest_path.stat().st_size
    file_hash = compute_sha256(dest_path)
    return clean_name, file_hash, file_size

