import sys
import argparse
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common.crypto_engine import compute_sha256
from server.services.release_manager import ReleaseManager
from scripts.setup_demoapp import build_zip

def publish(version: str, sequence: int, description: str):
    source_dir = PROJECT_ROOT / "demoapp" / "versions" / version
    if not source_dir.exists():
        print(f"[-] Source directory {source_dir} does not exist.")
        sys.exit(1)

    packages_dir = PROJECT_ROOT / "storage" / "packages"
    packages_dir.mkdir(parents=True, exist_ok=True)
    out_zip = packages_dir / f"demoapp-{version}.zip"

    # Package into zip
    build_zip(source_dir, out_zip)
    file_size = out_zip.stat().st_size
    file_hash = compute_sha256(out_zip)

    # Publish in ReleaseManager
    rel = ReleaseManager.publish_release(
        software_id="demoapp",
        version=version,
        release_sequence=sequence,
        package_filename=out_zip.name,
        package_hash=file_hash,
        package_size=file_size,
        description=description
    )

    print(f"[+] Published Release ID {rel['id']} for version {version} (Seq: {sequence})")
    print(f"    SHA-256:   {file_hash}")
    print(f"    Signature: {rel['signature'][:32]}...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Update Publisher CLI")
    parser.add_argument("--version", required=True, help="Version string (e.g. 1.1.0)")
    parser.add_argument("--sequence", required=True, type=int, help="Release sequence number (e.g. 2)")
    parser.add_argument("--description", default="Standard update release", help="Release description")
    args = parser.parse_args()
    publish(args.version, args.sequence, args.description)

