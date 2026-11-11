import sys
import json
import shutil
import socket
import time
import threading
import argparse
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from client.updater import ClientUpdater
from client.version_manager import VersionManager
from common.crypto_engine import compute_sha256, sign_metadata

# Colors for terminal presentation
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def is_server_listening(host="127.0.0.1", port=5000) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0

def ensure_server_running():
    if not is_server_listening():
        print(f"{CYAN}[*] Initializing local HTTPS update server daemon...{RESET}")
        from server.app import create_app
        app = create_app({"DEMO_MODE": True})
        cert_file = PROJECT_ROOT / "certs" / "server.crt"
        key_file = PROJECT_ROOT / "certs" / "server.key"
        
        thread = threading.Thread(
            target=lambda: app.run(
                host="127.0.0.1",
                port=5000,
                ssl_context=(str(cert_file), str(key_file)),
                debug=False,
                use_reloader=False
            ),
            daemon=True
        )
        thread.start()
        for _ in range(15):
            if is_server_listening():
                break
            time.sleep(0.3)
        print(f"{GREEN}[+] Local HTTPS update server ready on port 5000.{RESET}")

def print_header(title: str):
    print("\n" + "=" * 70)
    print(f"{BOLD}{CYAN}{title}{RESET}")
    print("=" * 70)

def reset_client_baseline():
    state_file = PROJECT_ROOT / "client" / "storage" / "state.json"
    state_data = {
        "software_id": "demoapp",
        "installed_version": "1.0.0",
        "release_sequence": 1,
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "status": "HEALTHY",
        "last_rollback_attempt": None
    }
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")
    
    app_current = PROJECT_ROOT / "demoapp" / "current"
    v1_source = PROJECT_ROOT / "demoapp" / "versions" / "1.0.0"
    if app_current.exists():
        shutil.rmtree(app_current)
    shutil.copytree(v1_source, app_current)
    print(f"{YELLOW}[*] Client reset to baseline: DemoApp v1.0.0 (Seq: 1){RESET}")

def run_scenario_1():
    print_header("SCENARIO 1 — SUCCESSFUL GENUINE UPDATE")
    print(f"{CYAN}Initial State:{RESET} Client running DemoApp 1.0.0")
    print(f"{CYAN}Action:{RESET} Administrator publishes genuine signed DemoApp 1.1.0 update")
    print(f"{CYAN}Expected Outcome:{RESET} Signature valid, SHA-256 match, version newer -> Success!\n")
    
    reset_client_baseline()
    
    updater = ClientUpdater()
    pkg_110 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.1.0.zip"
    pub_priv = PROJECT_ROOT / "keys" / "publisher_private.pem"
    
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_id": "rel-demoapp-1.1.0-official",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_size": pkg_110.stat().st_size,
        "package_hash": compute_sha256(pkg_110),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Genuine DemoApp 1.1.0 update with performance features"
    }
    signature = sign_metadata(pub_priv, metadata)
    
    print(f"[*] Package Hash (SHA-256): {metadata['package_hash']}")
    print(f"[*] Ed25519 Signature:     {signature[:32]}...")
    
    res = updater.run_update_pipeline(override_payload={
        "metadata": metadata,
        "signature": signature,
        "release_id": 1
    })
    
    for s in res.get("steps", []):
        tag = f"{GREEN}[PASS]{RESET}" if s["success"] else f"{RED}[FAIL]{RESET}"
        print(f"  {tag} Step {s['step']}: {s['name']} -> {s['message']}")
        
    if res["success"]:
        print(f"\n{BOLD}{GREEN}[VERDICT] SUCCESS: Update to DemoApp v1.1.0 installed safely.{RESET}")
    else:
        print(f"\n{BOLD}{RED}[VERDICT] FAILED: {res['message']}{RESET}")
    return res["success"]

def run_scenario_2():
    print_header("SCENARIO 2 — PACKAGE TAMPERING ATTACK")
    print(f"{CYAN}Initial State:{RESET} Client running DemoApp 1.0.0")
    print(f"{CYAN}Attack Vector:{RESET} Adversary intercepts package and injects malicious bytes")
    print(f"{CYAN}Expected Outcome:{RESET} SHA-256 digest mismatch -> Installation rejected!\n")
    
    reset_client_baseline()
    updater = ClientUpdater()
    pkg_110 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.1.0.zip"
    pub_priv = PROJECT_ROOT / "keys" / "publisher_private.pem"
    
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_id": "rel-demoapp-1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_size": pkg_110.stat().st_size,
        "package_hash": compute_sha256(pkg_110),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "DemoApp 1.1.0 update"
    }
    signature = sign_metadata(pub_priv, metadata)
    
    print(f"[*] Expected SHA-256 Digest: {metadata['package_hash']}")
    print(f"{RED}[!] Simulating tampering: modifying archive bytes on disk...{RESET}")
    
    res = updater.run_update_pipeline(
        override_payload={"metadata": metadata, "signature": signature, "release_id": 1},
        simulate_tampered_package=True
    )
    
    for s in res.get("steps", []):
        tag = f"{GREEN}[PASS]{RESET}" if s["success"] else f"{RED}[BLOCKED]{RESET}"
        print(f"  {tag} Step {s['step']}: {s['name']} -> {s['message']}")
        
    if not res["success"] and res["error_stage"] in (6, 7):
        print(f"\n{BOLD}{GREEN}[VERDICT] ATTACK PREVENTED: Package tampering caught at Step 7 (SHA-256 Digest Mismatch).{RESET}")
        return True
    else:
        print(f"\n{BOLD}{RED}[VERDICT] FAILURE: Package tampering was not blocked correctly!{RESET}")
        return False

def run_scenario_3():
    print_header("SCENARIO 3 — UNAUTHORIZED PUBLISHER ATTACK")
    print(f"{CYAN}Initial State:{RESET} Client running DemoApp 1.0.0")
    print(f"{CYAN}Attack Vector:{RESET} Adversary signs an update using rogue / unauthorized private key")
    print(f"{CYAN}Expected Outcome:{RESET} Client verifies with trusted publisher public key -> Signature invalid!\n")
    
    reset_client_baseline()
    updater = ClientUpdater()
    pkg_110 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.1.0.zip"
    atk_priv = PROJECT_ROOT / "keys" / "attacker_private.pem"
    
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_id": "rel-rogue-1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_size": pkg_110.stat().st_size,
        "package_hash": compute_sha256(pkg_110),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Malicious payload signed by attacker key"
    }
    rogue_sig = sign_metadata(atk_priv, metadata)
    
    print(f"{RED}[!] Attacker Signed with Rogue Key: {rogue_sig[:32]}...{RESET}")
    print(f"[*] Client Trusted Public Key:    keys/publisher_public.pem")
    
    res = updater.run_update_pipeline(override_payload={
        "metadata": metadata,
        "signature": rogue_sig,
        "release_id": 999
    })
    
    for s in res.get("steps", []):
        tag = f"{GREEN}[PASS]{RESET}" if s["success"] else f"{RED}[BLOCKED]{RESET}"
        print(f"  {tag} Step {s['step']}: {s['name']} -> {s['message']}")
        
    if not res["success"] and res["error_stage"] == 2:
        print(f"\n{BOLD}{GREEN}[VERDICT] ATTACK PREVENTED: Rogue signature caught at Step 2 (Signature Verification Failed).{RESET}")
        return True
    else:
        print(f"\n{BOLD}{RED}[VERDICT] FAILURE: Rogue signature was not blocked!{RESET}")
        return False

def run_scenario_4():
    print_header("SCENARIO 4 — ROLLBACK ATTACK")
    print(f"{CYAN}Initial State:{RESET} Client running DemoApp 1.1.0 (Sequence 2)")
    print(f"{CYAN}Attack Vector:{RESET} Adversary replays previously valid, correctly signed DemoApp 1.0.0 (Seq 1)")
    print(f"{CYAN}Expected Outcome:{RESET} Signature valid, but client local version policy rejects older release!\n")
    
    # Set client to 1.1.0 first
    vm = VersionManager()
    vm.commit_installed_version("1.1.0", 2)
    print(f"[*] Client installed state updated to DemoApp v1.1.0 (Seq: 2)")
    
    updater = ClientUpdater()
    pkg_100 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.0.0.zip"
    pub_priv = PROJECT_ROOT / "keys" / "publisher_private.pem"
    
    metadata = {
        "software_id": "demoapp",
        "version": "1.0.0",
        "release_id": "rel-demoapp-1.0.0",
        "release_sequence": 1,
        "package_filename": "demoapp-1.0.0.zip",
        "package_size": pkg_100.stat().st_size,
        "package_hash": compute_sha256(pkg_100),
        "release_timestamp": "2026-11-01T00:00:00Z",
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Legitimate old release 1.0.0 replayed by attacker"
    }
    signature = sign_metadata(pub_priv, metadata)
    
    print(f"{YELLOW}[!] Supplying signed 1.0.0 release to client running 1.1.0...{RESET}")
    
    res = updater.run_update_pipeline(override_payload={
        "metadata": metadata,
        "signature": signature,
        "release_id": 100
    })
    
    for s in res.get("steps", []):
        tag = f"{GREEN}[PASS]{RESET}" if s["success"] else f"{RED}[BLOCKED]{RESET}"
        print(f"  {tag} Step {s['step']}: {s['name']} -> {s['message']}")
        
    if not res["success"] and res["error_stage"] == 4:
        print(f"\n{BOLD}{GREEN}[VERDICT] ATTACK PREVENTED: Rollback blocked at Step 4 (Older Version / Sequence Rejected).{RESET}")
        return True
    else:
        print(f"\n{BOLD}{RED}[VERDICT] FAILURE: Rollback was not blocked!{RESET}")
        return False

def run_scenario_5():
    print_header("SCENARIO 5 — METADATA TAMPERING ATTACK")
    print(f"{CYAN}Initial State:{RESET} Client running DemoApp 1.0.0")
    print(f"{CYAN}Attack Vector:{RESET} Adversary alters package hash in metadata, retains old signature")
    print(f"{CYAN}Expected Outcome:{RESET} Ed25519 verification fails immediately!\n")
    
    reset_client_baseline()
    updater = ClientUpdater()
    pkg_110 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.1.0.zip"
    pub_priv = PROJECT_ROOT / "keys" / "publisher_private.pem"
    
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_id": "rel-demoapp-1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_size": pkg_110.stat().st_size,
        "package_hash": compute_sha256(pkg_110),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Genuine update before tampering"
    }
    # Legitimate signature on original metadata
    original_sig = sign_metadata(pub_priv, metadata)
    
    # Attacker alters package_hash
    print(f"[*] Original Hash: {metadata['package_hash']}")
    metadata["package_hash"] = "9999999999999999999999999999999999999999999999999999999999999999"
    print(f"{RED}[!] Attacker modified package_hash in JSON to: {metadata['package_hash']}{RESET}")
    print(f"[*] Attacker kept original signature: {original_sig[:32]}...")
    
    res = updater.run_update_pipeline(override_payload={
        "metadata": metadata,
        "signature": original_sig,
        "release_id": 995
    })
    
    for s in res.get("steps", []):
        tag = f"{GREEN}[PASS]{RESET}" if s["success"] else f"{RED}[BLOCKED]{RESET}"
        print(f"  {tag} Step {s['step']}: {s['name']} -> {s['message']}")
        
    if not res["success"] and res["error_stage"] == 2:
        print(f"\n{BOLD}{GREEN}[VERDICT] ATTACK PREVENTED: Metadata alteration caught at Step 2 (Signature Verification Failed).{RESET}")
        return True
    else:
        print(f"\n{BOLD}{RED}[VERDICT] FAILURE: Tampered metadata was not blocked!{RESET}")
        return False

def run_scenario_6():
    print_header("SCENARIO 6 — EXPIRED RELEASE ATTACK")
    print(f"{CYAN}Initial State:{RESET} Client running DemoApp 1.0.0")
    print(f"{CYAN}Attack Vector:{RESET} Adversary supplies correctly signed release with expiration date in past")
    print(f"{CYAN}Expected Outcome:{RESET} Signature valid, but freshness check rejects expired release!\n")
    
    reset_client_baseline()
    updater = ClientUpdater()
    pkg_110 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.1.0.zip"
    pub_priv = PROJECT_ROOT / "keys" / "publisher_private.pem"
    
    past_date = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
    metadata = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_id": "rel-expired-1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_size": pkg_110.stat().st_size,
        "package_hash": compute_sha256(pkg_110),
        "release_timestamp": (datetime.now(timezone.utc) - timedelta(days=45)).isoformat(),
        "expiration_timestamp": past_date,
        "description": "Legitimate but expired update"
    }
    signature = sign_metadata(pub_priv, metadata)
    
    print(f"[*] Expiration Timestamp: {past_date} (Expired 15 days ago)")
    print(f"[*] Signature:            {signature[:32]}... (Valid)")
    
    res = updater.run_update_pipeline(override_payload={
        "metadata": metadata,
        "signature": signature,
        "release_id": 994
    })
    
    for s in res.get("steps", []):
        tag = f"{GREEN}[PASS]{RESET}" if s["success"] else f"{RED}[BLOCKED]{RESET}"
        print(f"  {tag} Step {s['step']}: {s['name']} -> {s['message']}")
        
    if not res["success"] and res["error_stage"] == 3:
        print(f"\n{BOLD}{GREEN}[VERDICT] ATTACK PREVENTED: Stale metadata caught at Step 3 (Expired Release Rejected).{RESET}")
        return True
    else:
        print(f"\n{BOLD}{RED}[VERDICT] FAILURE: Expired release was not blocked!{RESET}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Secure Software Update System — Attack Simulation & Demo Suite")
    parser.add_argument("--scenario", type=int, choices=[1, 2, 3, 4, 5, 6], help="Run a specific scenario (1-6)")
    parser.add_argument("--all", action="store_true", help="Run all 6 scenarios sequentially")
    args = parser.parse_args()
    
    scenarios = {
        1: run_scenario_1,
        2: run_scenario_2,
        3: run_scenario_3,
        4: run_scenario_4,
        5: run_scenario_5,
        6: run_scenario_6
    }
    
    ensure_server_running()

    if args.scenario:
        scenarios[args.scenario]()
    elif args.all or len(sys.argv) == 1:
        print(f"{BOLD}{GREEN}\nStarting Complete 6-Scenario Live Demonstration Suite...{RESET}")
        results = {}
        for num, fn in scenarios.items():
            results[num] = fn()
            
        print("\n" + "=" * 70)
        print(f"{BOLD}DEMONSTRATION SUMMARY REPORT{RESET}")
        print("=" * 70)
        all_passed = True
        for num, passed in results.items():
            status = f"{GREEN}PASSED (Fail-Secure Verified){RESET}" if passed else f"{RED}FAILED{RESET}"
            if not passed:
                all_passed = False
            print(f"  Scenario {num}: {status}")
        print("=" * 70)
        if all_passed:
            print(f"{BOLD}{GREEN}ALL 6 ATTACK SIMULATION SCENARIOS SUCCESSFULLY VERIFIED.{RESET}\n")
        else:
            print(f"{BOLD}{RED}SOME SCENARIOS FAILED.{RESET}\n")

if __name__ == "__main__":
    main()
