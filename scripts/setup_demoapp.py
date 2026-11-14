import os
import sys
import shutil
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def build_zip(source_dir: Path, output_zip: Path):
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(source_dir):
            for file in files:
                file_path = Path(root) / file
                archive_name = file_path.relative_to(source_dir)
                zf.write(file_path, archive_name)
    print(f"[+] Packaged {output_zip.name} from {source_dir.name} ({output_zip.stat().st_size} bytes)")

def setup():
    demo_dir = PROJECT_ROOT / "demoapp"
    versions_dir = demo_dir / "versions"
    packages_dir = PROJECT_ROOT / "storage" / "packages"
    packages_dir.mkdir(parents=True, exist_ok=True)
    
    # Package 1.0.0, 1.1.0, 1.2.0, 1.3.0, 1.4.0
    for v in ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]:
        src = versions_dir / v
        out_zip = packages_dir / f"demoapp-{v}.zip"
        build_zip(src, out_zip)
        
    # Setup initial client installed version (1.0.0 in demoapp/current)
    current_dir = demo_dir / "current"
    if current_dir.exists():
        shutil.rmtree(current_dir)
    shutil.copytree(versions_dir / "1.0.0", current_dir)
    print(f"[+] Initialized client application at {current_dir} with version 1.0.0")

    # Seed canonical releases and start presentation session baseline
    from server.database.database import ensure_canonical_baseline
    sess = ensure_canonical_baseline(force_new_session=True, actor="setup_script")
    print(f"[+] Initialized Presentation Session: {sess['session_id']} (All 5 DemoApp releases published)")

if __name__ == "__main__":
    setup()

