import os
import json
import base64
import hashlib
from pathlib import Path
from typing import Union, Dict, Any, Tuple
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def compute_sha256(source: Union[bytes, str, Path]) -> str:
    """
    Computes the SHA-256 hash of a file path or raw bytes.
    Uses 64KB chunking for streaming large files securely and efficiently.
    """
    hasher = hashlib.sha256()
    if isinstance(source, (str, Path)) and os.path.exists(source):
        with open(source, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
    elif isinstance(source, bytes):
        hasher.update(source)
    elif isinstance(source, str):
        hasher.update(source.encode("utf-8"))
    else:
        raise ValueError(f"Unsupported source type for SHA-256: {type(source)}")
    return hasher.hexdigest().lower()


def canonicalize_json(data: Dict[str, Any]) -> bytes:
    """
    Serializes a dictionary into deterministic canonical UTF-8 JSON bytes for
    cryptographic signing and verification.

    Supported Schema & Types:
      - Dictionary objects with string keys (recursively sorted lexicographically)
      - Strings (UTF-8 encoded, standard JSON escaping)
      - Integers (exact decimal formatting)
      - Booleans (true, false) and null
      - Lists / Arrays of supported types

    Delimiters:
      - Compact formatting: separators=(',', ':') with zero whitespace padding.

    Standards Scope & Limitations:
      - This function implements deterministic canonical serialization for the
        system's defined metadata schema. It does NOT claim full RFC 8785 (JCS)
        coverage because it does not implement IEEE 754 64-bit floating point
        ECMA-262 scientific notation normalization or negative zero handling (-0).
        Floating-point numbers, NaN, and Infinity are not permitted in release metadata.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """
    Generates a new Ed25519 keypair and returns (private_pem, public_pem).
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def load_private_key(pem_source: Union[bytes, str, Path]) -> ed25519.Ed25519PrivateKey:
    """Loads an Ed25519 private key from PEM bytes, string, or file path."""
    if isinstance(pem_source, (str, Path)) and os.path.exists(pem_source):
        with open(pem_source, "rb") as f:
            data = f.read()
    elif isinstance(pem_source, str):
        data = pem_source.encode("utf-8")
    elif isinstance(pem_source, bytes):
        data = pem_source
    else:
        raise ValueError("Invalid private key source")
    return serialization.load_pem_private_key(data, password=None)


def load_public_key(pem_source: Union[bytes, str, Path]) -> ed25519.Ed25519PublicKey:
    """Loads an Ed25519 public key from PEM bytes, string, or file path."""
    if isinstance(pem_source, (str, Path)) and os.path.exists(pem_source):
        with open(pem_source, "rb") as f:
            data = f.read()
    elif isinstance(pem_source, str):
        data = pem_source.encode("utf-8")
    elif isinstance(pem_source, bytes):
        data = pem_source
    else:
        raise ValueError("Invalid public key source")
    return serialization.load_pem_public_key(data)


def sign_data(private_key_pem: Union[bytes, str, Path], data_bytes: bytes) -> str:
    """
    Digitally signs data_bytes using the Ed25519 private key.
    Returns the signature encoded as a Base64 string.
    """
    priv_key = load_private_key(private_key_pem)
    raw_sig = priv_key.sign(data_bytes)
    return base64.b64encode(raw_sig).decode("ascii")


def verify_signature(public_key_pem: Union[bytes, str, Path], data_bytes: bytes, signature_b64: str) -> bool:
    """
    Verifies an Ed25519 signature over data_bytes against the public key.
    Returns True if valid, False otherwise.
    """
    try:
        pub_key = load_public_key(public_key_pem)
        raw_sig = base64.b64decode(signature_b64)
        pub_key.verify(raw_sig, data_bytes)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


def sign_metadata(private_key_pem: Union[bytes, str, Path], metadata: Dict[str, Any]) -> str:
    """Signs canonical metadata and returns the base64 signature."""
    canonical_bytes = canonicalize_json(metadata)
    return sign_data(private_key_pem, canonical_bytes)


def verify_metadata(public_key_pem: Union[bytes, str, Path], metadata: Dict[str, Any], signature_b64: str) -> bool:
    """Verifies canonical metadata against the given base64 signature."""
    canonical_bytes = canonicalize_json(metadata)
    return verify_signature(public_key_pem, canonical_bytes, signature_b64)


def parse_semver(version_str: str) -> Tuple[int, int, int]:
    """Parses standard semver strings into a (major, minor, patch) integer tuple."""
    clean = version_str.strip().lstrip("v")
    parts = clean.split(".")
    try:
        if len(parts) == 1:
            return (int(parts[0]), 0, 0)
        elif len(parts) == 2:
            return (int(parts[0]), int(parts[1]), 0)
        elif len(parts) >= 3:
            return (int(parts[0]), int(parts[1]), int(parts[2].split("-")[0].split("+")[0]))
    except Exception:
        raise ValueError(f"Invalid semver string: {version_str}")
    return (0, 0, 0)


def compare_versions(v1: str, v2: str) -> int:
    """
    Compares two SemVer strings:
    Returns:
       1 if v1 > v2
       0 if v1 == v2
      -1 if v1 < v2
    """
    t1 = parse_semver(v1)
    t2 = parse_semver(v2)
    if t1 > t2:
        return 1
    if t1 < t2:
        return -1
    return 0


def is_release_expired(expiration_iso: str) -> bool:
    """
    Checks whether an ISO 8601 UTC timestamp has expired compared to current UTC time.
    """
    try:
        if not expiration_iso:
            return False
        # Normalize timezone
        if expiration_iso.endswith("Z"):
            exp_dt = datetime.fromisoformat(expiration_iso.replace("Z", "+00:00"))
        else:
            exp_dt = datetime.fromisoformat(expiration_iso)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp_dt
    except Exception:
        # Fail secure: if expiration cannot be safely parsed, treat as expired/invalid
        return True

