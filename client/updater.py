import sys
import json
import requests
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from client.verifier import Verifier
from client.version_manager import VersionManager
from client.downloader import Downloader
from client.installer import SecureInstaller
from common.crypto_engine import compute_sha256

class ClientUpdater:
    def __init__(
        self,
        server_url: str = "https://127.0.0.1:5000",
        client_id: str = "client-alpha",
        software_id: str = "demoapp",
        trusted_public_key_path: Path = None,
        ca_cert_path: Path = None,
        state_file_path: Path = None,
        target_app_dir: Path = None
    ):
        self.server_url = server_url.rstrip("/")
        self.client_id = client_id
        self.software_id = software_id
        
        self.verifier = Verifier(trusted_public_key_path)
        self.version_manager = VersionManager(state_file_path)
        self.downloader = Downloader(ca_cert_path, self.server_url)
        self.installer = SecureInstaller(target_app_dir)

    def report_to_server(
        self,
        action: str,
        verification_result: str,
        installation_result: str = "N/A",
        details: str = "",
        release_id: Optional[int] = None,
        security_event: Optional[Dict[str, str]] = None
    ):
        try:
            report_url = f"{self.server_url}/api/updates/report"
            payload = {
                "client_id": self.client_id,
                "action": action,
                "verification_result": verification_result,
                "installation_result": installation_result,
                "details": details,
                "release_id": release_id,
                "security_event": security_event
            }
            requests.post(
                report_url,
                json=payload,
                verify=str(self.downloader.ca_cert_path),
                timeout=5
            )
        except Exception:
            # Server reporting should not crash the client
            pass

    def check_for_updates(self, custom_verify: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Queries the server for available releases and returns (available, release_payload, message).
        """
        current_state = self.version_manager.get_state()
        check_url = f"{self.server_url}/api/updates/check"
        params = {
            "software_id": self.software_id,
            "client_id": self.client_id,
            "current_version": current_state["installed_version"]
        }
        verify_target = custom_verify if custom_verify is not None else str(self.downloader.ca_cert_path)
        
        try:
            res = requests.get(check_url, params=params, verify=verify_target, timeout=10)
            if res.status_code != 200:
                return False, None, f"Server check returned HTTP {res.status_code}: {res.text}"
            data = res.json()
            if not data.get("update_available"):
                return False, None, data.get("message", "No updates available.")
            return True, data, "Update available."
        except requests.exceptions.SSLError as e:
            return False, None, f"TLS certificate error: {e}"
        except Exception as e:
            return False, None, f"Network check failed: {e}"

    def run_update_pipeline(
        self,
        override_payload: Optional[Dict[str, Any]] = None,
        simulate_tampered_package: bool = False,
        simulate_interrupted_download: bool = False,
        simulate_activation_failure: bool = False,
        custom_verify: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes the mandatory 11-Step Verification and Installation Pipeline (FR14).
        Returns a detailed report dictionary of each step and overall success status.
        """
        steps = []
        overall_success = False

        def record_step(step_num: int, name: str, success: bool, message: str):
            steps.append({
                "step": step_num,
                "name": name,
                "success": success,
                "status": "PASSED" if success else "FAILED",
                "message": message
            })

        def populate_skipped_steps(failed_stage: int):
            pipeline_names = {
                1: "Retrieve Signed Release Metadata",
                2: "Ed25519 Digital Signature Verification",
                3: "Metadata Validation and Freshness Check",
                4: "Version and Rollback Validation",
                5: "Package Download",
                6: "Calculate Package SHA-256 Digest",
                7: "Verify Package Hash Match",
                8: "Package Format & Path Traversal Inspection",
                9: "Secure Staged Installation & Health Check",
                10: "Commit Trusted Installed Version State",
                11: "Telemetry & Final Audit Logging"
            }
            for s_num in range(failed_stage + 1, 12):
                steps.append({
                    "step": s_num,
                    "name": pipeline_names.get(s_num, f"Step {s_num}"),
                    "success": False,
                    "status": "SKIPPED",
                    "message": f"Step skipped because verification halted at step {failed_stage}."
                })

        # Step 1: Retrieve signed release metadata
        if override_payload:
            payload = override_payload
            record_step(1, "Retrieve Signed Release Metadata", True, "Retrieved metadata from custom payload.")
        else:
            avail, payload, msg = self.check_for_updates(custom_verify=custom_verify)
            if not avail:
                record_step(1, "Retrieve Signed Release Metadata", False, msg)
                populate_skipped_steps(1)
                return {"success": False, "error_stage": 1, "message": msg, "steps": steps}
            record_step(1, "Retrieve Signed Release Metadata", True, f"Retrieved release metadata: {msg}")

        metadata = payload.get("metadata", {})
        signature = payload.get("signature", "")
        release_id = payload.get("release_id")
        candidate_version = metadata.get("version", "unknown")
        candidate_sequence = metadata.get("release_sequence", 0)

        # Step 2: Verify Publisher's Digital Signature (Ed25519)
        sig_valid, sig_msg = self.verifier.verify_publisher_signature(metadata, signature)
        if not sig_valid:
            record_step(2, "Ed25519 Digital Signature Verification", False, sig_msg)
            self.report_to_server(
                "VERIFY", "SIGNATURE_INVALID",
                details=sig_msg, release_id=release_id,
                security_event={"type": "INVALID_SIGNATURE", "description": sig_msg}
            )
            populate_skipped_steps(2)
            return {"success": False, "error_stage": 2, "message": sig_msg, "steps": steps}
        record_step(2, "Ed25519 Digital Signature Verification", True, sig_msg)

        # Step 3: Validate Metadata Fields and Release Expiration
        meta_valid, meta_msg = self.verifier.validate_metadata(metadata, self.software_id)
        if not meta_valid:
            record_step(3, "Metadata Validation and Freshness Check", False, meta_msg)
            self.report_to_server(
                "VERIFY", "METADATA_INVALID",
                details=meta_msg, release_id=release_id,
                security_event={"type": "EXPIRED_OR_INVALID_METADATA", "description": meta_msg}
            )
            populate_skipped_steps(3)
            return {"success": False, "error_stage": 3, "message": meta_msg, "steps": steps}
        record_step(3, "Metadata Validation and Freshness Check", True, meta_msg)

        # Step 4: Validate Software Identifier and Release Version Sequence (Rollback Protection)
        ver_valid, ver_msg = self.version_manager.validate_version_sequence(candidate_version, candidate_sequence)
        if not ver_valid:
            record_step(4, "Version and Rollback Validation", False, ver_msg)
            self.report_to_server(
                "VERIFY", "ROLLBACK_BLOCKED",
                details=ver_msg, release_id=release_id,
                security_event={"type": "ROLLBACK_ATTEMPT", "description": ver_msg}
            )
            populate_skipped_steps(4)
            return {"success": False, "error_stage": 4, "message": ver_msg, "steps": steps}
        record_step(4, "Version and Rollback Validation", True, ver_msg)

        # Step 5: Download the Update Package
        pkg_filename = metadata.get("package_filename")
        pkg_size = metadata.get("package_size")
        dl_success, pkg_path, dl_msg = self.downloader.download_package(
            package_filename=pkg_filename,
            expected_size=pkg_size,
            simulate_interruption=simulate_interrupted_download,
            custom_verify=custom_verify
        )
        if not dl_success:
            record_step(5, "Package Download", False, dl_msg)
            self.report_to_server(
                "DOWNLOAD", "FAILED",
                details=dl_msg, release_id=release_id,
                security_event={"type": "DOWNLOAD_FAILED", "description": dl_msg}
            )
            populate_skipped_steps(5)
            return {"success": False, "error_stage": 5, "message": dl_msg, "steps": steps}
        record_step(5, "Package Download", True, dl_msg)

        # (Attack Simulation Hook for Scenario 2 / TC04: Modify package on disk)
        if simulate_tampered_package and pkg_path:
            with open(pkg_path, "ab") as f:
                f.write(b"\x00\xDE\xAD\xBE\xEF_TAMPERED_INJECTION")

        # Step 6: Calculate Package SHA-256 Digest
        computed_hash = compute_sha256(pkg_path)
        record_step(6, "Calculate Package SHA-256 Digest", True, f"Calculated SHA-256: {computed_hash}")

        # Step 7: Compare Calculated Hash with Signed Metadata Hash
        expected_hash = metadata.get("package_hash", "").strip().lower()
        if computed_hash != expected_hash:
            hash_msg = f"SHA-256 integrity check failed! Computed: {computed_hash}, Expected: {expected_hash}"
            record_step(7, "Verify Package Hash Match", False, hash_msg)
            self.report_to_server(
                "VERIFY", "HASH_MISMATCH",
                details=hash_msg, release_id=release_id,
                security_event={"type": "PACKAGE_TAMPER_DETECTED", "description": hash_msg}
            )
            populate_skipped_steps(7)
            return {"success": False, "error_stage": 7, "message": hash_msg, "steps": steps}
        record_step(7, "Verify Package Hash Match", True, f"SHA-256 digest match verified ({computed_hash}).")

        # Step 8: Validate Package Format and Installation Contents (Anti-Traversal)
        safe_archive, safe_msg = self.installer.validate_package_contents(pkg_path)
        if not safe_archive:
            record_step(8, "Package Format & Path Traversal Inspection", False, safe_msg)
            self.report_to_server(
                "VERIFY", "UNSAFE_ARCHIVE",
                details=safe_msg, release_id=release_id,
                security_event={"type": "ZIP_SLIP_ATTEMPT", "description": safe_msg}
            )
            populate_skipped_steps(8)
            return {"success": False, "error_stage": 8, "message": safe_msg, "steps": steps}
        record_step(8, "Package Format & Path Traversal Inspection", True, safe_msg)

        # Step 9: Install the Update (Staged extraction, backup & atomic activation)
        inst_success, inst_msg = self.installer.install(
            zip_path=pkg_path,
            expected_version=candidate_version,
            simulate_failure_during_activation=simulate_activation_failure
        )
        if not inst_success:
            record_step(9, "Secure Staged Installation & Health Check", False, inst_msg)
            self.report_to_server(
                "INSTALL", "FAILED",
                installation_result="FAILED",
                details=inst_msg, release_id=release_id,
                security_event={"type": "INSTALLATION_FAILURE", "description": inst_msg}
            )
            populate_skipped_steps(9)
            return {"success": False, "error_stage": 9, "message": inst_msg, "steps": steps}
        record_step(9, "Secure Staged Installation & Health Check", True, inst_msg)

        # Step 10: Update Locally Stored Installed Version
        self.version_manager.commit_installed_version(candidate_version, candidate_sequence)
        record_step(10, "Commit Trusted Installed Version State", True, f"Installed state updated to v{candidate_version} (seq: {candidate_sequence}).")

        # Step 11: Record and Report Installation Result
        self.report_to_server(
            "INSTALL", "SUCCESS",
            installation_result="SUCCESS",
            details=f"DemoApp successfully updated to v{candidate_version}",
            release_id=release_id
        )
        record_step(11, "Telemetry & Final Audit Logging", True, "Successfully reported update completion to server.")

        return {
            "success": True,
            "version": candidate_version,
            "sequence": candidate_sequence,
            "message": f"DemoApp successfully updated to v{candidate_version}",
            "steps": steps
        }

