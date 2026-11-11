import json
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify

from client.updater import ClientUpdater
from client.version_manager import VersionManager
from common.crypto_engine import compute_sha256, sign_metadata

client_ui_bp = Blueprint("client_ui", __name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

@client_ui_bp.route("/status", methods=["GET"])
def get_client_status():
    vm = VersionManager()
    state = vm.get_state()
    return jsonify(state), 200

@client_ui_bp.route("/reset", methods=["POST"])
def reset_client_to_baseline():
    """Resets client demoapp to 1.0.0 baseline for clean repeatable demonstrations."""
    # Reset state.json
    state_file = PROJECT_ROOT / "client" / "storage" / "state.json"
    initial_state = {
        "software_id": "demoapp",
        "installed_version": "1.0.0",
        "release_sequence": 1,
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "status": "HEALTHY",
        "last_rollback_attempt": None
    }
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(initial_state, indent=2), encoding="utf-8")
    
    # Reset current app directory
    app_current = PROJECT_ROOT / "demoapp" / "current"
    v1_source = PROJECT_ROOT / "demoapp" / "versions" / "1.0.0"
    if app_current.exists():
        shutil.rmtree(app_current)
    shutil.copytree(v1_source, app_current)
    
    return jsonify({"message": "Client reset to DemoApp v1.0.0 baseline successfully.", "state": initial_state}), 200

@client_ui_bp.route("/run-update", methods=["POST"])
def run_client_update():
    updater = ClientUpdater(
        server_url="https://127.0.0.1:5000",
        client_id="demo-client-ui"
    )
    result = updater.run_update_pipeline()
    return jsonify(result), 200

@client_ui_bp.route("/run-scenario/<int:scenario_num>", methods=["POST"])
def run_scenario(scenario_num: int):
    updater = ClientUpdater(
        server_url="https://127.0.0.1:5000",
        client_id="demo-scenario-runner"
    )
    pkg_110 = PROJECT_ROOT / "storage" / "packages" / "demoapp-1.1.0.zip"
    pub_priv = PROJECT_ROOT / "keys" / "publisher_private.pem"
    atk_priv = PROJECT_ROOT / "keys" / "attacker_private.pem"
    
    if scenario_num == 1:
        # Scenario 1: Genuine Successful Update (1.0.0 -> 1.1.0)
        res = updater.run_update_pipeline()
        return jsonify({
            "scenario": 1,
            "title": "Scenario 1 — Successful Update",
            "expected": "Update authentic, verified and installed successfully.",
            "result": res
        })
        
    elif scenario_num == 2:
        # Scenario 2: Package Tampering (SHA-256 mismatch)
        res = updater.run_update_pipeline(simulate_tampered_package=True)
        return jsonify({
            "scenario": 2,
            "title": "Scenario 2 — Package Tampering Attack",
            "expected": "SHA-256 mismatch detected. Update rejected before installation.",
            "result": res
        })
        
    elif scenario_num == 3:
        # Scenario 3: Unauthorized Publisher (Attacker Ed25519 key)
        meta = {
            "software_id": "demoapp",
            "version": "1.1.0",
            "release_id": "rel-rogue-1.1.0",
            "release_sequence": 2,
            "package_filename": "demoapp-1.1.0.zip",
            "package_size": pkg_110.stat().st_size,
            "package_hash": compute_sha256(pkg_110),
            "release_timestamp": datetime.now(timezone.utc).isoformat(),
            "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "description": "Malicious release signed by unauthorized attacker key"
        }
        rogue_sig = sign_metadata(atk_priv, meta)
        res = updater.run_update_pipeline(override_payload={
            "metadata": meta,
            "signature": rogue_sig,
            "release_id": 999
        })
        return jsonify({
            "scenario": 3,
            "title": "Scenario 3 — Unauthorized Publisher Attack",
            "expected": "Ed25519 signature verification fails against trusted public key.",
            "result": res
        })
        
    elif scenario_num == 4:
        # Scenario 4: Rollback Attack
        # Ensure client state is at 1.1.0 or higher first, then attempt to supply 1.0.0 release
        vm = VersionManager()
        vm.commit_installed_version("1.1.0", 2)
        
        meta = {
            "software_id": "demoapp",
            "version": "1.0.0",
            "release_id": "rel-demoapp-1.0.0",
            "release_sequence": 1,
            "package_filename": "demoapp-1.0.0.zip",
            "package_size": 1041,
            "package_hash": compute_sha256(PROJECT_ROOT / "storage" / "packages" / "demoapp-1.0.0.zip"),
            "release_timestamp": "2026-11-01T00:00:00Z",
            "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "description": "Legitimate old release replayed"
        }
        valid_sig = sign_metadata(pub_priv, meta)
        res = updater.run_update_pipeline(override_payload={
            "metadata": meta,
            "signature": valid_sig,
            "release_id": 100
        })
        return jsonify({
            "scenario": 4,
            "title": "Scenario 4 — Rollback Attack",
            "expected": "Signature passes, but client version policy rejects older release.",
            "result": res
        })
        
    elif scenario_num == 5:
        # Scenario 5: Metadata Tampering
        meta = {
            "software_id": "demoapp",
            "version": "1.1.0",
            "release_id": "rel-demoapp-1.1.0",
            "release_sequence": 2,
            "package_filename": "demoapp-1.1.0.zip",
            "package_size": pkg_110.stat().st_size,
            "package_hash": compute_sha256(pkg_110),
            "release_timestamp": datetime.now(timezone.utc).isoformat(),
            "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "description": "Valid update metadata before tampering"
        }
        original_sig = sign_metadata(pub_priv, meta)
        # Attacker tampers with package_hash
        meta["package_hash"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        res = updater.run_update_pipeline(override_payload={
            "metadata": meta,
            "signature": original_sig,
            "release_id": 995
        })
        return jsonify({
            "scenario": 5,
            "title": "Scenario 5 — Metadata Tampering Attack",
            "expected": "Ed25519 verification fails because metadata hash was modified.",
            "result": res
        })
        
    elif scenario_num == 6:
        # Scenario 6: Expired Release
        past_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        meta = {
            "software_id": "demoapp",
            "version": "1.1.0",
            "release_id": "rel-expired-1.1.0",
            "release_sequence": 2,
            "package_filename": "demoapp-1.1.0.zip",
            "package_size": pkg_110.stat().st_size,
            "package_hash": compute_sha256(pkg_110),
            "release_timestamp": (datetime.now(timezone.utc) - timedelta(days=60)).isoformat(),
            "expiration_timestamp": past_time,
            "description": "Expired release metadata"
        }
        valid_sig = sign_metadata(pub_priv, meta)
        res = updater.run_update_pipeline(override_payload={
            "metadata": meta,
            "signature": valid_sig,
            "release_id": 994
        })
        return jsonify({
            "scenario": 6,
            "title": "Scenario 6 — Expired Release Attack",
            "expected": "Signature passes, but client expiration validation rejects it.",
            "result": res
        })
        
    return jsonify({"error": f"Unknown scenario {scenario_num}"}), 400

