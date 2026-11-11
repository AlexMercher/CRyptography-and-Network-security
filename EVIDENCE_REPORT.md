# Project Demonstration & Security Evidence Report
**Generated:** 2026-11-11 06:50:16 UTC

**Project Name:** Secure Software Update System with Cryptographic Verification

**Course / Subject:** Computer Networks & Security (CNS)

---

## 1. Executive Summary
This report documents the empirical evidence gathered during automated verification of the 7 system components, the 18 mandatory test cases (TC01-TC18), and the 6 live demonstration attack scenarios. All verification pipelines adhere to the **Zero-Trust Fail-Secure Principle**.

## 2. Six Demonstration Attack Scenarios Results

| Scenario ID | Title / Attack Vector | Target Security Layer | Outcome | Status |
|---|---|---|---|:---:|
| **Scenario 1** | Successful Update | Full 11-Step Cryptographic Pipeline | Fail-Secure Enforced | **`PASSED`** |
| **Scenario 2** | Package Tampering Attack | SHA-256 Digest Verification (Step 6) | Fail-Secure Enforced | **`PASSED`** |
| **Scenario 3** | Unauthorized Publisher Attack | Ed25519 Signature Verification (Step 2) | Fail-Secure Enforced | **`PASSED`** |
| **Scenario 4** | Rollback Attack | Monotonic Sequence / Version State (Step 4) | Fail-Secure Enforced | **`PASSED`** |
| **Scenario 5** | Metadata Tampering Attack | Canonical JSON & Ed25519 (Step 2) | Fail-Secure Enforced | **`PASSED`** |
| **Scenario 6** | Expired Release Attack | Freshness & UTC Validity Window (Step 3) | Fail-Secure Enforced | **`PASSED`** |

---

## 3. Mandatory Test Case Matrix (TC01 - TC18)

| Test Case | Description | Tested Mechanism | Verification Module | Result |
|---|---|---|---|:---:|
| **TC01** | Upload genuine software update | ZIP inspection, size, SHA-256 calculation | `server/services/package_manager.py` | **`PASSED`** |
| **TC02** | Publish valid signed update | Ed25519 private key signing & DB persistence | `server/services/release_manager.py` | **`PASSED`** |
| **TC03** | Download untampered update | TLS 1.3 streaming download over HTTPS | `client/downloader.py` | **`PASSED`** |
| **TC04** | Modify downloaded package bytes | SHA-256 integrity mismatch detection | `tests/test_tampering.py` | **`PASSED`** |
| **TC05** | Modify signed metadata fields | Ed25519 canonical JSON verification failure | `tests/test_tampering.py` | **`PASSED`** |
| **TC06** | Use corrupted digital signature | Base64 signature decoding & verification failure | `tests/test_signatures.py` | **`PASSED`** |
| **TC07** | Sign using unauthorized attacker key | Signature rejected by trusted public key | `tests/test_integration.py` | **`PASSED`** |
| **TC08** | Attempt to install older version | SemVer comparison against trusted local state | `tests/test_rollback.py` | **`PASSED`** |
| **TC09** | Replay older release sequence | Monotonic sequence validation | `tests/test_rollback.py` | **`PASSED`** |
| **TC10** | Unauthenticated admin access | Flask session authentication decorator | `tests/test_server_api.py` | **`PASSED`** |
| **TC11** | Unauthorized release publishing | Role-based authorization check | `tests/test_server_api.py` | **`PASSED`** |
| **TC12** | Interrupted update download | Incomplete package size verification | `client/downloader.py` | **`PASSED`** |
| **TC13** | Mismatched software identifier | Software ID equality check ('demoapp') | `tests/test_integration.py` | **`PASSED`** |
| **TC14** | Expired release metadata | UTC timestamp expiration window check | `tests/test_signatures.py` | **`PASSED`** |
| **TC15** | Extract archive with unsafe paths | Zip-Slip & Path Traversal inspection | `tests/test_installation.py` | **`PASSED`** |
| **TC16** | Install valid newer update | Staged extraction & atomic directory swap | `tests/test_installation.py` | **`PASSED`** |
| **TC17** | Simulate installation failure | Automatic backup restoration / rollback | `tests/test_installation.py` | **`PASSED`** |
| **TC18** | Untrusted HTTPS TLS certificate | Strict CA certificate verification | `tests/test_integration.py` | **`PASSED`** |

---

## 4. Pytest Execution Output

```text
============================= test session starts =============================
platform win32 -- Python 3.10.0, pytest-8.4.2, pluggy-1.7.0 -- D:\projects\CNS\venv\python.exe
cachedir: .pytest_cache
rootdir: D:\projects\CNS
configfile: pytest.ini
testpaths: tests
collecting ... collected 29 items

tests/test_hashing.py::test_sha256_deterministic_bytes PASSED            [  3%]
tests/test_hashing.py::test_sha256_file_vs_bytes PASSED                  [  6%]
tests/test_hashing.py::test_sha256_tamper_detection PASSED               [ 10%]
tests/test_hashing.py::test_sha256_demoapp_packages PASSED               [ 13%]
tests/test_installation.py::test_tc15_zip_slip_traversal_rejected PASSED [ 17%]
tests/test_installation.py::test_tc16_valid_update_installation PASSED   [ 20%]
tests/test_installation.py::test_tc17_failed_installation_recovery PASSED [ 24%]
tests/test_integration.py::test_scenario_3_unauthorized_publisher_rejected PASSED [ 27%]
tests/test_integration.py::test_scenario_6_expired_release_rejected PASSED [ 31%]
tests/test_integration.py::test_tc13_mismatched_software_id_rejected PASSED [ 34%]
tests/test_integration.py::test_tc18_invalid_https_cert_rejected PASSED  [ 37%]
tests/test_rollback.py::test_tc08_rollback_older_version_rejected PASSED [ 41%]
tests/test_rollback.py::test_reinstallation_same_version_rejected PASSED [ 44%]
tests/test_rollback.py::test_tc09_sequence_replay_rejected PASSED        [ 48%]
tests/test_rollback.py::test_newer_version_and_sequence_accepted PASSED  [ 51%]
tests/test_server_api.py::test_unauthenticated_admin_access_rejected PASSED [ 55%]
tests/test_server_api.py::test_unauthorized_publishing_rejected PASSED   [ 58%]
tests/test_server_api.py::test_admin_login_success PASSED                [ 62%]
tests/test_server_api.py::test_admin_login_failure PASSED                [ 65%]
tests/test_server_api.py::test_admin_upload_and_publish_flow PASSED      [ 68%]
tests/test_signatures.py::test_canonicalize_json_order_independent PASSED [ 72%]
tests/test_signatures.py::test_valid_signature_verification PASSED       [ 75%]
tests/test_signatures.py::test_metadata_tampering_fails_verification PASSED [ 79%]
tests/test_signatures.py::test_unauthorized_key_fails_verification PASSED [ 82%]
tests/test_signatures.py::test_invalid_signature_string PASSED           [ 86%]
tests/test_signatures.py::test_expiration_check PASSED                   [ 89%]
tests/test_signatures.py::test_semver_comparison PASSED                  [ 93%]
tests/test_tampering.py::test_tc04_package_tampering_rejected PASSED     [ 96%]
tests/test_tampering.py::test_tc05_metadata_tampering_rejected PASSED    [100%]

============================= 29 passed in 1.62s ==============================
```

---

## 5. Live SQLite Security Event Audit Trail

Extract of recent security events captured in `server/database/update_system.db`:

| Event ID | Timestamp | Event Type | User / Client | Description | Result |
|---|---|---|---|---|:---:|
| 28 | `2026-11-11T06:50:16` | `LOGIN_SUCCESS` | admin | Administrator 'admin' logged in successfully | **`ALLOWED`** |
| 27 | `2026-11-11T06:50:16` | `LOGIN_FAILED` | admin | Failed login attempt for username: admin | **`BLOCKED`** |
| 26 | `2026-11-11T06:50:16` | `LOGIN_SUCCESS` | admin | Administrator 'admin' logged in successfully | **`ALLOWED`** |
| 25 | `2026-11-11T06:50:16` | `UNAUTHORIZED_ACCESS` | anonymous | Unauthorized attempt to access protected endpoint: /api/admin/publish | **`BLOCKED`** |
| 24 | `2026-11-11T06:50:16` | `UNAUTHORIZED_ACCESS` | anonymous | Unauthorized attempt to access protected endpoint: /api/admin/releases | **`BLOCKED`** |
| 23 | `2026-11-11T06:50:15` | `EXPIRED_OR_INVALID_METADATA` | test-client-1 | Mismatched software identifier: expected 'demoapp', received 'other_application' | **`BLOCKED`** |
| 22 | `2026-11-11T06:50:15` | `EXPIRED_OR_INVALID_METADATA` | test-client-1 | Release metadata has expired: 2026-11-06T06:50:15.842241+00:00 | **`BLOCKED`** |
| 21 | `2026-11-11T06:50:15` | `INVALID_SIGNATURE` | test-client-1 | Digital signature verification failed. Untrusted or modified release metadata. | **`BLOCKED`** |
| 20 | `2026-11-11T06:50:14` | `EXPIRED_OR_INVALID_METADATA` | client-alpha | Release metadata has expired: 2026-10-27T06:50:14.611897+00:00 | **`BLOCKED`** |
| 19 | `2026-11-11T06:50:14` | `INVALID_SIGNATURE` | client-alpha | Digital signature verification failed. Untrusted or modified release metadata. | **`BLOCKED`** |
| 18 | `2026-11-11T06:50:14` | `ROLLBACK_ATTEMPT` | client-alpha | Rollback blocked: candidate version 1.0.0 is older than installed version 1.1.0. | **`BLOCKED`** |
| 17 | `2026-11-11T06:50:14` | `INVALID_SIGNATURE` | client-alpha | Digital signature verification failed. Untrusted or modified release metadata. | **`BLOCKED`** |
| 16 | `2026-11-11T06:50:14` | `PACKAGE_TAMPER_DETECTED` | client-alpha | SHA-256 integrity check failed! Computed: 72ed688e1ff2b5da6fd38245d6fb3ba2077268b3156909b9883149bbb2e88296, Expected: b4cc50772e707fbbbf607d107642f5247a04ea0adc951021fada55847c4d013e | **`BLOCKED`** |
| 15 | `2026-11-11T06:43:02` | `LOGIN_SUCCESS` | admin | Administrator 'admin' logged in successfully | **`ALLOWED`** |
| 14 | `2026-11-11T06:43:02` | `LOGIN_FAILED` | admin | Failed login attempt for username: admin | **`BLOCKED`** |

---

## 6. Live SQLite Client Activity Log

| Activity ID | Timestamp | Client ID | Action | Verification | Install Result | Details |
|---|---|---|---|---|---|---|
| 19 | `2026-11-11T06:50:15` | `test-client-1` | `VERIFY` | `METADATA_INVALID` | `N/A` | Mismatched software identifier: expected 'demoapp', received 'other_application' |
| 18 | `2026-11-11T06:50:15` | `test-client-1` | `VERIFY` | `METADATA_INVALID` | `N/A` | Release metadata has expired: 2026-11-06T06:50:15.842241+00:00 |
| 17 | `2026-11-11T06:50:15` | `test-client-1` | `VERIFY` | `SIGNATURE_INVALID` | `N/A` | Digital signature verification failed. Untrusted or modified release metadata. |
| 16 | `2026-11-11T06:50:14` | `client-alpha` | `VERIFY` | `METADATA_INVALID` | `N/A` | Release metadata has expired: 2026-10-27T06:50:14.611897+00:00 |
| 15 | `2026-11-11T06:50:14` | `client-alpha` | `VERIFY` | `SIGNATURE_INVALID` | `N/A` | Digital signature verification failed. Untrusted or modified release metadata. |
| 14 | `2026-11-11T06:50:14` | `client-alpha` | `VERIFY` | `ROLLBACK_BLOCKED` | `N/A` | Rollback blocked: candidate version 1.0.0 is older than installed version 1.1.0. |
| 13 | `2026-11-11T06:50:14` | `client-alpha` | `VERIFY` | `SIGNATURE_INVALID` | `N/A` | Digital signature verification failed. Untrusted or modified release metadata. |
| 12 | `2026-11-11T06:50:14` | `client-alpha` | `VERIFY` | `HASH_MISMATCH` | `N/A` | SHA-256 integrity check failed! Computed: 72ed688e1ff2b5da6fd38245d6fb3ba2077268b3156909b9883149bbb2e88296, Expected: b4cc50772e707fbbbf607d107642f5247a04ea0adc951021fada55847c4d013e |
| 11 | `2026-11-11T06:50:14` | `unknown-client` | `DOWNLOAD` | `DISPATCHED` | `N/A` | File: demoapp-1.1.0.zip, Size: 1268 bytes |
| 10 | `2026-11-11T06:50:14` | `client-alpha` | `INSTALL` | `SUCCESS` | `SUCCESS` | DemoApp successfully updated to v1.1.0 |
| 9 | `2026-11-11T06:50:14` | `unknown-client` | `DOWNLOAD` | `DISPATCHED` | `N/A` | File: demoapp-1.1.0.zip, Size: 1268 bytes |
| 8 | `2026-11-11T06:42:22` | `client-alpha` | `VERIFY` | `METADATA_INVALID` | `N/A` | Release metadata has expired: 2026-10-27T06:42:22.097872+00:00 |
| 7 | `2026-11-11T06:42:22` | `client-alpha` | `VERIFY` | `SIGNATURE_INVALID` | `N/A` | Digital signature verification failed. Untrusted or modified release metadata. |
| 6 | `2026-11-11T06:42:22` | `client-alpha` | `VERIFY` | `ROLLBACK_BLOCKED` | `N/A` | Rollback blocked: candidate version 1.0.0 is older than installed version 1.1.0. |
| 5 | `2026-11-11T06:42:21` | `client-alpha` | `VERIFY` | `SIGNATURE_INVALID` | `N/A` | Digital signature verification failed. Untrusted or modified release metadata. |

---

## 7. Published Releases Ledger

| Release ID | Software | Version | Sequence | SHA-256 Digest | Status |
|---|---|---|---|---|:---:|
| 1 | `demoapp` | `v1.1.0` | 2 | `b4cc50772e707fbb...` | **`PUBLISHED`** |