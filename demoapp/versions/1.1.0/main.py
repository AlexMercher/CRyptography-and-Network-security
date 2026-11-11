import json
from pathlib import Path
from modules.core import get_status, run_diagnostics

def run():
    vpath = Path(__file__).parent / "version.json"
    with open(vpath, "r", encoding="utf-8") as f:
        vinfo = json.load(f)
    print("=" * 50)
    print(f"  DemoApp v{vinfo['version']} (Seq: {vinfo['release_sequence']}) [UPDATED]")
    print(f"  Build Date: {vinfo['build_date']}")
    print(f"  Status: {get_status()}")
    print("  Diagnostics:")
    for diag, val in run_diagnostics().items():
        print(f"    - {diag}: {val}")
    print("  Features:")
    for feat in vinfo.get("features", []):
        print(f"    - {feat}")
    print("=" * 50)

if __name__ == "__main__":
    run()

