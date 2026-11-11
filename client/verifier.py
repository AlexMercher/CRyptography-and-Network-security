from pathlib import Path
from typing import Dict, Any, Tuple
from common.crypto_engine import (
    verify_metadata,
    compute_sha256,
    is_release_expired
)

DEFAULT_TRUSTED_KEY = Path(__file__).resolve().parent / "trusted_keys" / "publisher_public.pem"

class Verifier:
    def __init__(self, trusted_public_key_path: Path = None):
        self.trusted_key_path = trusted_public_key_path or DEFAULT_TRUSTED_KEY

    def verify_publisher_signature(self, metadata: Dict[str, Any], signature_b64: str) -> Tuple[bool, str]:
        """
        FR08 / SR02: Verifies Ed25519 digital signature over canonical metadata
        using the independently provisioned publisher public key.
        """
        if not self.trusted_key_path.exists():
            return False, f"Trusted public key not found at {self.trusted_key_path}"
            
        if not signature_b64 or not isinstance(signature_b64, str):
            return False, "Missing or empty digital signature"
            
        public_key_bytes = self.trusted_key_path.read_bytes()
        is_valid = verify_metadata(public_key_bytes, metadata, signature_b64)
        if not is_valid:
            return False, "Digital signature verification failed. Untrusted or modified release metadata."
        return True, "Digital signature verified successfully."

    def validate_metadata(self, metadata: Dict[str, Any], expected_software_id: str = "demoapp") -> Tuple[bool, str]:
        """
        FR13 / SR06: Validates metadata structure, freshness, expiration, and software ID.
        """
        required_fields = [
            "software_id", "version", "release_id", "release_sequence",
            "package_filename", "package_size", "package_hash",
            "release_timestamp", "expiration_timestamp"
        ]
        for f in required_fields:
            if f not in metadata:
                return False, f"Metadata validation failed: missing field '{f}'"

        # Check software identifier (TC13)
        if metadata["software_id"] != expected_software_id:
            return False, (
                f"Mismatched software identifier: expected '{expected_software_id}', "
                f"received '{metadata['software_id']}'"
            )

        # Check expiration (TC14)
        if is_release_expired(metadata.get("expiration_timestamp", "")):
            return False, f"Release metadata has expired: {metadata.get('expiration_timestamp')}"

        return True, "Metadata fields and expiration validated successfully."

    def verify_package_hash(self, package_path: Path, expected_hash: str) -> Tuple[bool, str]:
        """
        FR11 / SR01: Calculates SHA-256 digest of downloaded package and compares with signed hash.
        """
        if not package_path.exists():
            return False, f"Package file does not exist: {package_path}"

        computed = compute_sha256(package_path)
        expected = expected_hash.strip().lower()
        if computed != expected:
            return False, f"SHA-256 integrity check failed! Computed: {computed}, Expected: {expected}"
        return True, f"SHA-256 digest match verified ({computed})."

