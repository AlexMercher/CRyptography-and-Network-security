import os
import sys
import json
import time
import shutil
import tempfile
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from client.updater import ClientUpdater
from client.version_manager import VersionManager
from common.crypto_engine import compute_sha256, sign_metadata, load_public_key, load_private_key
from server.database.database import get_db_connection, init_db
from server.services.release_manager import ReleaseManager
from server.app import create_app

def run_tests():
    print("=" * 70)
    print("STARTING WORKFLOW, RESET, SCENARIO & REPEATED UPDATE AUDIT SUITE")
    print("=" * 70)

    # Ensure DB is initialized
    init_db()

    # 1. Start server daemon
    app = create_app({"DEMO_MODE": True})
    cert_file = PROJECT_ROOT / "certs" / "server.crt"
    key_file = PROJECT_ROOT / "certs" / "server.key"
    ssl_context = (str(cert_file), str(key_file)) if cert_file.exists() and key_file.exists() else None
    
    server_thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=5000, ssl_context=ssl_context, debug=False, use_reloader=False),
        daemon=True
    )
    server_thread.start()
    time.sleep(2.5)

    test_results = {
        "reset_tests": {},
        "scenarios": {},
        "scenario_isolation": {},
        "repeated_updates": {},
        "cross_workflow": {},
        "preservation_check": {}
    }

    # Helper for reset
    client_test = app.test_client()

    def do_client_reset():
        res = client_test.post("/api/client/reset", headers={"X-Admin-Reset-Token": "cns-demo-reset-authorized-key-2026"})
        assert res.status_code == 200
        return res.get_json()

    # ====================================================================
    # SECTION 1: RESET TESTS R1 - R12
    # ====================================================================
    print("\n--- Running Reset Tests (R1 - R12) ---")

    # R1: Clean state reset
    do_client_reset()
    vm = VersionManager()
    st = vm.get_state()
    r1_pass = (st["installed_version"] == "1.0.0" and st["release_sequence"] == 1)
    test_results["reset_tests"]["R1_clean_state"] = "PASS" if r1_pass else "FAIL"
    print(f"[*] R1 (Startup Reset): {test_results['reset_tests']['R1_clean_state']}")

    # R2: Install 1.1.0, then reset, then install 1.1.0 again
    updater = ClientUpdater()
    pkg_110 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.1.0.zip"
    pub_priv = PROJECT_ROOT / "keys" / "publisher_private.pem"
    meta_110 = {
        "software_id": "demoapp",
        "version": "1.1.0",
        "release_id": "rel-r2-1.1.0",
        "release_sequence": 2,
        "package_filename": "demoapp-1.1.0.zip",
        "package_size": pkg_110.stat().st_size,
        "package_hash": compute_sha256(pkg_110),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Test R2 update"
    }
    sig_110 = sign_metadata(pub_priv, meta_110)
    up_res = updater.run_update_pipeline(override_payload={"metadata": meta_110, "signature": sig_110, "release_id": 201})
    assert up_res["success"], "Install 1.1.0 failed"
    # Reset
    do_client_reset()
    st_after_r2 = vm.get_state()
    # Install 1.1.0 again
    up_res2 = updater.run_update_pipeline(override_payload={"metadata": meta_110, "signature": sig_110, "release_id": 201})
    r2_pass = (st_after_r2["installed_version"] == "1.0.0" and up_res2["success"])
    test_results["reset_tests"]["R2_after_1.1.0_install"] = "PASS" if r2_pass else "FAIL"
    print(f"[*] R2 (Install 1.1.0 -> Reset -> Reinstall 1.1.0): {test_results['reset_tests']['R2_after_1.1.0_install']}")

    # R3: Reset after installing 1.2.0
    pkg_120 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.2.0.zip"
    meta_120 = {
        "software_id": "demoapp",
        "version": "1.2.0",
        "release_id": "rel-r3-1.2.0",
        "release_sequence": 3,
        "package_filename": "demoapp-1.2.0.zip",
        "package_size": pkg_120.stat().st_size,
        "package_hash": compute_sha256(pkg_120),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Test R3 update"
    }
    sig_120 = sign_metadata(pub_priv, meta_120)
    up_res3 = updater.run_update_pipeline(override_payload={"metadata": meta_120, "signature": sig_120, "release_id": 202})
    assert up_res3["success"]
    do_client_reset()
    st_r3 = vm.get_state()
    r3_pass = (st_r3["installed_version"] == "1.0.0" and st_r3["release_sequence"] == 1)
    test_results["reset_tests"]["R3_after_1.2.0_install"] = "PASS" if r3_pass else "FAIL"
    print(f"[*] R3 (Install 1.2.0 -> Reset): {test_results['reset_tests']['R3_after_1.2.0_install']}")

    # R4: Reset after package tampering attack
    updater.run_update_pipeline(override_payload={"metadata": meta_110, "signature": sig_110, "release_id": 201}, simulate_tampered_package=True)
    do_client_reset()
    r4_pass = (vm.get_state()["installed_version"] == "1.0.0")
    test_results["reset_tests"]["R4_after_package_tampering"] = "PASS" if r4_pass else "FAIL"
    print(f"[*] R4 (Reset After Tampering): {test_results['reset_tests']['R4_after_package_tampering']}")

    # R5: Reset after rogue key attack
    atk_priv = PROJECT_ROOT / "keys" / "attacker_private.pem"
    rogue_sig = sign_metadata(atk_priv, meta_110)
    updater.run_update_pipeline(override_payload={"metadata": meta_110, "signature": rogue_sig, "release_id": 999})
    do_client_reset()
    r5_pass = (vm.get_state()["installed_version"] == "1.0.0")
    test_results["reset_tests"]["R5_after_unauthorized_publisher"] = "PASS" if r5_pass else "FAIL"
    print(f"[*] R5 (Reset After Rogue Key): {test_results['reset_tests']['R5_after_unauthorized_publisher']}")

    # R6: Reset after rollback attack
    vm.commit_installed_version("1.1.0", 2)
    meta_100 = {
        "software_id": "demoapp",
        "version": "1.0.0",
        "release_id": "rel-r6-1.0.0",
        "release_sequence": 1,
        "package_filename": "demoapp-1.0.0.zip",
        "package_size": 1042,
        "package_hash": compute_sha256(PROJECT_ROOT / "storage" / "packages" / "demoapp-1.0.0.zip"),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Old release replay"
    }
    sig_100 = sign_metadata(pub_priv, meta_100)
    updater.run_update_pipeline(override_payload={"metadata": meta_100, "signature": sig_100, "release_id": 200})
    do_client_reset()
    r6_pass = (vm.get_state()["installed_version"] == "1.0.0" and vm.get_state()["release_sequence"] == 1)
    test_results["reset_tests"]["R6_after_rollback_attack"] = "PASS" if r6_pass else "FAIL"
    print(f"[*] R6 (Reset After Rollback Attack): {test_results['reset_tests']['R6_after_rollback_attack']}")

    # R7: Reset after metadata tampering
    tampered_meta = dict(meta_110)
    tampered_meta["package_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
    updater.run_update_pipeline(override_payload={"metadata": tampered_meta, "signature": sig_110, "release_id": 995})
    do_client_reset()
    r7_pass = (vm.get_state()["installed_version"] == "1.0.0")
    test_results["reset_tests"]["R7_after_metadata_tampering"] = "PASS" if r7_pass else "FAIL"
    print(f"[*] R7 (Reset After Metadata Tampering): {test_results['reset_tests']['R7_after_metadata_tampering']}")

    # R8: Reset after expired release
    expired_meta = dict(meta_110)
    expired_meta["expiration_timestamp"] = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    exp_sig = sign_metadata(pub_priv, expired_meta)
    updater.run_update_pipeline(override_payload={"metadata": expired_meta, "signature": exp_sig, "release_id": 996})
    do_client_reset()
    r8_pass = (vm.get_state()["installed_version"] == "1.0.0")
    test_results["reset_tests"]["R8_after_expired_release"] = "PASS" if r8_pass else "FAIL"
    print(f"[*] R8 (Reset After Expired Release): {test_results['reset_tests']['R8_after_expired_release']}")

    # R9: Reset after interrupted download
    dl_dir = PROJECT_ROOT / "client" / "storage" / "downloads"
    dl_dir.mkdir(parents=True, exist_ok=True)
    part_file = dl_dir / "interrupted_test.part"
    part_file.write_bytes(b"PARTIAL_CONTENT_BUFFER")
    do_client_reset()
    r9_pass = not part_file.exists()
    test_results["reset_tests"]["R9_after_interrupted_download"] = "PASS" if r9_pass else "FAIL"
    print(f"[*] R9 (Reset After Interrupted Download): {test_results['reset_tests']['R9_after_interrupted_download']}")

    # R10: Reset after activation failure
    updater.run_update_pipeline(override_payload={"metadata": meta_110, "signature": sig_110, "release_id": 201}, simulate_activation_failure=True)
    do_client_reset()
    r10_pass = (vm.get_state()["installed_version"] == "1.0.0")
    test_results["reset_tests"]["R10_after_installation_failure"] = "PASS" if r10_pass else "FAIL"
    print(f"[*] R10 (Reset After Install Failure): {test_results['reset_tests']['R10_after_installation_failure']}")

    # R11: Consecutive resets (idempotence)
    do_client_reset()
    do_client_reset()
    do_client_reset()
    st_r11 = vm.get_state()
    r11_pass = (st_r11["installed_version"] == "1.0.0" and st_r11["release_sequence"] == 1)
    test_results["reset_tests"]["R11_consecutive_resets"] = "PASS" if r11_pass else "FAIL"
    print(f"[*] R11 (Consecutive Resets): {test_results['reset_tests']['R11_consecutive_resets']}")

    # R12: Browser status persistence after reset
    status_res = client_test.get("/api/client/status")
    st_browser = status_res.get_json()
    r12_pass = (st_browser["installed_version"] == "1.0.0" and st_browser["release_sequence"] == 1)
    test_results["reset_tests"]["R12_browser_persistence"] = "PASS" if r12_pass else "FAIL"
    print(f"[*] R12 (Browser Status Matches Reset): {test_results['reset_tests']['R12_browser_persistence']}")

    # ====================================================================
    # SECTION 2: SIX DEMONSTRATION SCENARIOS INDEPENDENTLY
    # ====================================================================
    print("\n--- Running Six Scenarios Independently ---")
    
    # Scenario 1: Successful Genuine Update
    do_client_reset()
    sc1_res = client_test.post("/api/client/run-scenario/1").get_json()
    sc1_ok = sc1_res["result"]["success"] and sc1_res["result"]["version"] == "1.1.0"
    test_results["scenarios"]["Scenario_1_Genuine_Update"] = "PASS" if sc1_ok else "FAIL"
    print(f"[*] Scenario 1 (Genuine Update): {test_results['scenarios']['Scenario_1_Genuine_Update']}")

    # Scenario 2: Package Tampering Attack
    do_client_reset()
    sc2_res = client_test.post("/api/client/run-scenario/2").get_json()
    sc2_ok = not sc2_res["result"]["success"] and sc2_res["result"]["error_stage"] in (6, 7)
    test_results["scenarios"]["Scenario_2_Package_Tampering"] = "PASS" if sc2_ok else "FAIL"
    print(f"[*] Scenario 2 (Package Tampering): {test_results['scenarios']['Scenario_2_Package_Tampering']} (Blocked at Step {sc2_res['result']['error_stage']})")

    # Scenario 3: Unauthorized Publisher Attack
    do_client_reset()
    sc3_res = client_test.post("/api/client/run-scenario/3").get_json()
    sc3_ok = not sc3_res["result"]["success"] and sc3_res["result"]["error_stage"] == 2
    test_results["scenarios"]["Scenario_3_Rogue_Publisher"] = "PASS" if sc3_ok else "FAIL"
    print(f"[*] Scenario 3 (Rogue Publisher): {test_results['scenarios']['Scenario_3_Rogue_Publisher']} (Blocked at Step {sc3_res['result']['error_stage']})")

    # Scenario 4: Rollback Attack
    do_client_reset()
    sc4_res = client_test.post("/api/client/run-scenario/4").get_json()
    sc4_ok = not sc4_res["result"]["success"] and sc4_res["result"]["error_stage"] == 4
    test_results["scenarios"]["Scenario_4_Rollback_Attack"] = "PASS" if sc4_ok else "FAIL"
    print(f"[*] Scenario 4 (Rollback Attack): {test_results['scenarios']['Scenario_4_Rollback_Attack']} (Blocked at Step {sc4_res['result']['error_stage']})")

    # Scenario 5: Metadata Tampering Attack
    do_client_reset()
    sc5_res = client_test.post("/api/client/run-scenario/5").get_json()
    sc5_ok = not sc5_res["result"]["success"] and sc5_res["result"]["error_stage"] == 2
    test_results["scenarios"]["Scenario_5_Metadata_Tampering"] = "PASS" if sc5_ok else "FAIL"
    print(f"[*] Scenario 5 (Metadata Tampering): {test_results['scenarios']['Scenario_5_Metadata_Tampering']} (Blocked at Step {sc5_res['result']['error_stage']})")

    # Scenario 6: Expired Release Attack
    do_client_reset()
    sc6_res = client_test.post("/api/client/run-scenario/6").get_json()
    sc6_ok = not sc6_res["result"]["success"] and sc6_res["result"]["error_stage"] == 3
    test_results["scenarios"]["Scenario_6_Expired_Release"] = "PASS" if sc6_ok else "FAIL"
    print(f"[*] Scenario 6 (Expired Release): {test_results['scenarios']['Scenario_6_Expired_Release']} (Blocked at Step {sc6_res['result']['error_stage']})")

    # ====================================================================
    # SECTION 3: SCENARIO ISOLATION TEST (Sequence 4 -> 1 -> 2 -> 3 -> 5 -> 6)
    # ====================================================================
    print("\n--- Running Scenario Isolation Test (Sequence: 4, 1, 2, 3, 5, 6 without manual reset) ---")
    s4 = client_test.post("/api/client/run-scenario/4").get_json()
    s1 = client_test.post("/api/client/run-scenario/1").get_json()
    s2 = client_test.post("/api/client/run-scenario/2").get_json()
    s3 = client_test.post("/api/client/run-scenario/3").get_json()
    s5 = client_test.post("/api/client/run-scenario/5").get_json()
    s6 = client_test.post("/api/client/run-scenario/6").get_json()

    iso_ok = (
        not s4["result"]["success"] and s4["result"]["error_stage"] == 4 and
        s1["result"]["success"] and
        not s2["result"]["success"] and s2["result"]["error_stage"] in (6, 7) and
        not s3["result"]["success"] and s3["result"]["error_stage"] == 2 and
        not s5["result"]["success"] and s5["result"]["error_stage"] == 2 and
        not s6["result"]["success"] and s6["result"]["error_stage"] == 3
    )
    test_results["scenario_isolation"]["sequence_4_1_2_3_5_6"] = "PASS" if iso_ok else "FAIL"
    print(f"[*] Isolation Sequence (4 -> 1 -> 2 -> 3 -> 5 -> 6): {test_results['scenario_isolation']['sequence_4_1_2_3_5_6']}")

    # Post-attack recovery: Run genuine update after attack
    s1_recovery = client_test.post("/api/client/run-scenario/1").get_json()
    test_results["scenario_isolation"]["genuine_update_after_attacks"] = "PASS" if s1_recovery["result"]["success"] else "FAIL"
    print(f"[*] Positive Control (Genuine Update After All Attacks): {test_results['scenario_isolation']['genuine_update_after_attacks']}")

    # ====================================================================
    # SECTION 4: REPEATED UPDATES SEQUENCE (1.0.0 -> 1.1.0 -> 1.2.0 -> 1.3.0 -> 1.4.0)
    # ====================================================================
    print("\n--- Running Repeated Updates Sequence (1.0.0 -> 1.1.0 -> 1.2.0 -> 1.3.0 -> 1.4.0) ---")
    do_client_reset()
    
    versions_to_test = [
        ("1.1.0", 2, "demoapp-1.1.0.zip"),
        ("1.2.0", 3, "demoapp-1.2.0.zip"),
        ("1.3.0", 4, "demoapp-1.3.0.zip"),
        ("1.4.0", 5, "demoapp-1.4.0.zip")
    ]

    chain_ok = True
    for ver, seq, pkg_name in versions_to_test:
        pkg_path = PROJECT_ROOT / "storage" / "packages" / pkg_name
        meta = {
            "software_id": "demoapp",
            "version": ver,
            "release_id": f"rel-rep-{ver}",
            "release_sequence": seq,
            "package_filename": pkg_name,
            "package_size": pkg_path.stat().st_size,
            "package_hash": compute_sha256(pkg_path),
            "release_timestamp": datetime.now(timezone.utc).isoformat(),
            "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "description": f"Repeated update step to {ver}"
        }
        sig = sign_metadata(pub_priv, meta)
        res = updater.run_update_pipeline(override_payload={"metadata": meta, "signature": sig, "release_id": 300 + seq})
        curr_st = vm.get_state()
        step_pass = res["success"] and curr_st["installed_version"] == ver and curr_st["release_sequence"] == seq
        test_results["repeated_updates"][f"update_to_{ver}_seq_{seq}"] = "PASS" if step_pass else "FAIL"
        print(f"  [+] Upgrade to v{ver} (Seq {seq}): {'PASS' if step_pass else 'FAIL'}")
        if not step_pass:
            chain_ok = False
            break

    # Reinstall older version (1.3.0 while on 1.4.0)
    pkg_130 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.3.0.zip"
    meta_130_rollback = {
        "software_id": "demoapp",
        "version": "1.3.0",
        "release_id": "rel-rb-1.3.0",
        "release_sequence": 4,
        "package_filename": "demoapp-1.3.0.zip",
        "package_size": pkg_130.stat().st_size,
        "package_hash": compute_sha256(pkg_130),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Rollback attempt to 1.3.0"
    }
    sig_130 = sign_metadata(pub_priv, meta_130_rollback)
    rb_res = updater.run_update_pipeline(override_payload={"metadata": meta_130_rollback, "signature": sig_130, "release_id": 399})
    rb_blocked = (not rb_res["success"] and rb_res["error_stage"] == 4)
    test_results["repeated_updates"]["rollback_1.4.0_to_1.3.0"] = "REJECTED (Correct)" if rb_blocked else "FAIL"
    print(f"  [+] Rollback Attempt 1.4.0 -> 1.3.0: {test_results['repeated_updates']['rollback_1.4.0_to_1.3.0']}")

    # Reinstall same version (1.4.0 again)
    pkg_140 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.4.0.zip"
    meta_140_reinstall = {
        "software_id": "demoapp",
        "version": "1.4.0",
        "release_id": "rel-same-1.4.0",
        "release_sequence": 5,
        "package_filename": "demoapp-1.4.0.zip",
        "package_size": pkg_140.stat().st_size,
        "package_hash": compute_sha256(pkg_140),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Reinstall attempt 1.4.0"
    }
    sig_140 = sign_metadata(pub_priv, meta_140_reinstall)
    same_res = updater.run_update_pipeline(override_payload={"metadata": meta_140_reinstall, "signature": sig_140, "release_id": 400})
    same_blocked = (not same_res["success"] and same_res["error_stage"] == 4)
    test_results["repeated_updates"]["reinstall_same_1.4.0"] = "REJECTED (Correct)" if same_blocked else "FAIL"
    print(f"  [+] Reinstall Attempt Same Version (1.4.0): {test_results['repeated_updates']['reinstall_same_1.4.0']}")

    # Replay older sequence (version 1.5.0 but sequence 2)
    meta_seq_replay = {
        "software_id": "demoapp",
        "version": "1.5.0",
        "release_id": "rel-seq-replay",
        "release_sequence": 2,  # seq 2 is <= current seq 5
        "package_filename": "demoapp-1.4.0.zip",
        "package_size": pkg_140.stat().st_size,
        "package_hash": compute_sha256(pkg_140),
        "release_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "description": "Sequence replay attempt"
    }
    sig_replay = sign_metadata(pub_priv, meta_seq_replay)
    seq_res = updater.run_update_pipeline(override_payload={"metadata": meta_seq_replay, "signature": sig_replay, "release_id": 401})
    seq_blocked = (not seq_res["success"] and seq_res["error_stage"] == 4)
    test_results["repeated_updates"]["sequence_replay_blocked"] = "REJECTED (Correct)" if seq_blocked else "FAIL"
    print(f"  [+] Sequence Replay Attempt (Seq 2 <= 5): {test_results['repeated_updates']['sequence_replay_blocked']}")

    # ====================================================================
    # SECTION 5: PRESERVATION CHECK
    # ====================================================================
    print("\n--- Checking Critical Security Resource Preservation ---")
    do_client_reset()
    test_results["preservation_check"]["keys_publisher_private"] = (PROJECT_ROOT / "keys" / "publisher_private.pem").exists()
    test_results["preservation_check"]["keys_publisher_public"] = (PROJECT_ROOT / "keys" / "publisher_public.pem").exists()
    test_results["preservation_check"]["certs_ca"] = (PROJECT_ROOT / "certs" / "ca.crt").exists()
    test_results["preservation_check"]["certs_server"] = (PROJECT_ROOT / "certs" / "server.crt").exists()
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM releases")
    rel_cnt = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM security_events")
    sec_cnt = c.fetchone()[0]
    conn.close()

    test_results["preservation_check"]["database_releases_preserved"] = rel_cnt > 0
    test_results["preservation_check"]["security_logs_preserved"] = sec_cnt > 0
    print(f"[*] Keys & Certs Preserved: {all(test_results['preservation_check'].values())}")
    print(f"[*] Database Releases Count: {rel_cnt}")
    print(f"[*] Database Security Events Count: {sec_cnt}")

    # Output JSON summary
    out_file = PROJECT_ROOT / "audit_workflow_results.json"
    out_file.write_text(json.dumps(test_results, indent=2), encoding="utf-8")
    print(f"\n[+] Results written to {out_file}")
    print("=" * 70)
    return test_results

if __name__ == "__main__":
    run_tests()

