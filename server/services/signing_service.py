import os
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple

from common.crypto_engine import sign_metadata, canonicalize_json

KEYS_DIR = Path(__file__).resolve().parent.parent.parent / "keys"
PUBLISHER_KEY_PATH = KEYS_DIR / "publisher_private.pem"

def create_and_sign_release_metadata(
    software_id: str,
    version: str,
    release_sequence: int,
    package_filename: str,
    package_hash: str,
    package_size: int,
    description: str = "",
    expiration_days: int = 365,
    private_key_path: Path = None
) -> Tuple[Dict[str, Any], str]:
    """
    Constructs deterministic release metadata and signs it using the Ed25519 private key.
    Returns (metadata_dict, signature_b64).
    """
    key_path = private_key_path or PUBLISHER_KEY_PATH
    if not key_path.exists():
        raise FileNotFoundError(f"Publisher private key not found at {key_path}")
    
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    exp_iso = (now + timedelta(days=expiration_days)).isoformat()
    release_id = f"rel-{software_id}-{version}-{int(now.timestamp())}"
    
    metadata = {
        "software_id": software_id,
        "version": version,
        "release_id": release_id,
        "release_sequence": release_sequence,
        "package_filename": package_filename,
        "package_size": package_size,
        "package_hash": package_hash.lower(),
        "release_timestamp": now_iso,
        "expiration_timestamp": exp_iso,
        "description": description
    }
    
    signature = sign_metadata(key_path, metadata)
    return metadata, signature

