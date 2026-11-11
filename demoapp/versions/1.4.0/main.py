import json
from pathlib import Path
from modules.core import (
    get_status,
    run_diagnostics,
    assess_password_strength,
    generate_compliance_audit,
    encode_security_token
)

def run():
    vpath = Path(__file__).parent / "version.json"
    with open(vpath, "r", encoding="utf-8") as f:
        vinfo = json.load(f)
    print("=" * 60)
    print(f"  DemoApp v{vinfo['version']} (Seq: {vinfo['release_sequence']}) [SECURITY HARDENED]")
    print(f"  Build Date: {vinfo['build_date']}")
    print(f"  Status: {get_status()}")
    print("  Diagnostics:")
    for diag, val in run_diagnostics().items():
        print(f"    - {diag}: {val}")
    print("  Security Compliance Audit:")
    for comp, val in generate_compliance_audit().items():
        print(f"    - {comp}: {val}")
    sample_pwd = "Admin@SecureUpdate2026!"
    eval_res = assess_password_strength(sample_pwd)
    print(f"  Credential Security Engine Assessment ('{sample_pwd}'):")
    print(f"    - Rating: {eval_res['rating']} (Score: {eval_res['score']}/5)")
    print(f"  Authorization Token Generated: {encode_security_token('admin', 'publisher')}")
    print("  Features:")
    for feat in vinfo.get("features", []):
        print(f"    - {feat}")
    print("=" * 60)

if __name__ == "__main__":
    run()

