# Complete Execution & Demonstration Guide (`run.md`)
### Secure Software Update System with Cryptographic Verification (CNS)

This document provides a comprehensive, step-by-step walkthrough to run, test, and demonstrate the Secure Software Update System in front of your professor or evaluator.

---

## 1. Environment Setup

Always ensure the project's conda environment is activated before running commands or starting servers:

```powershell
# 1. Activate the environment
conda activate ./venv

# 2. Verify dependencies (installed strictly from requirements.txt)
pip install -r requirements.txt
```

> **Note on PowerShell:** If `conda activate ./venv` encounters an empty environment argument in your terminal session, run:
> ```powershell
> Remove-Item Env:\_CE_M -ErrorAction SilentlyContinue; Remove-Item Env:\_CE_CONDA -ErrorAction SilentlyContinue; conda activate ./venv
> ```

---

## 2. Presentation Session Lifecycle & Execution Workflows

The system incorporates **Presentation Session Management** to guarantee predictable, reproducible demonstrations while preserving all mutable actions during an active session.

### Workflow A: Preparing for a Fresh Professor Demonstration
To start from a clean canonical baseline where:
- DemoApp **v1.0.0 (Seq 1)** is published and installed on the client device.
- DemoApp releases **1.1.0, 1.2.0, 1.3.0, and 1.4.0** are in a **Prepared (unpublished)** state awaiting administrative publication.
- Client discovers zero unapproved updates until you explicitly publish them.

```powershell
# 1. Ensure all packages are built and signed
python scripts/setup_demoapp.py

# 2. Start server in demonstration mode with a fresh presentation session
python run_server.py --demo --new-demo-session
```

*Alternatively, click the **Start New Presentation Session** button in the Admin Dashboard at any time.*

### Workflow B: Resuming / Restarting During an Active Presentation
If you restart the server during a presentation or refresh the browser, the application **automatically preserves** the existing session state (including published releases, revocations, installed versions, and audit logs):

```powershell
python run_server.py --demo
```

### Presentation Session Principles:
1. **In-Session Persistence:** When you publish a prepared release, revoke a release, or advance client versions, changes persist across page refreshes, dashboard navigation, and server process restarts.
2. **Prepared vs Published Segregation:** The Admin Dashboard separates **Prepared Releases (Awaiting Publication)** from **Published Releases**. Releasing an update is an explicit, authenticated administrative action.
3. **Sequential Release Publication:** Prepared releases must be published in monotonic sequence (v1.1.0 -> v1.2.0 -> v1.3.0 -> v1.4.0). Out-of-order publication is strictly blocked.
4. **Predictable Baseline on Demand:** Triggering a new session (`--new-demo-session` or dashboard button) restores v1.0.0 as published, sets 1.1.0–1.4.0 to prepared, resets the client baseline to 1.0.0 (seq 1), clears demonstration logs, and issues a new session identifier.
5. **Security Anchor Preservation:** Administrator credentials (`admin`), publisher Ed25519 keys, and TLS certificates are strictly preserved and never wiped or regenerated.

---

## 3. Complete Verification Suite (Pytest — 95 Tests)

Run the comprehensive automated test suite covering Unit, Integration, Security, Reset, Archive Safety, Session Management, and Publication Lifecycle layers:

```powershell
pytest -v
```

### Verified Test Categories (95 / 95 Passed):
- **`tests/test_presentation_sessions.py` (22 Tests)**:
  - **Group A (Session Persistence)**: Initial creation, revocation persistence, browser refresh persistence, dashboard navigation persistence, server restart persistence, and client update filtering.
  - **Group B (New Session Lifecycle)**: Baseline restoration after revocation, 5-version catalogue restoration, client baseline reset, unique session IDs, session isolation, key preservation, and administrator login preservation.
  - **Group C (Release Visibility)**: Database records for 1.0.0–1.4.0, API serialization, Admin Dashboard rendering, progressive candidate detection (1.1.0 after publish, 1.4.0 when all published), intermediate revocation handling (skipping 1.2.0), and latest revocation fallback (1.4.0 -> 1.3.0).
  - **Group D (Publication Lifecycle & Pipeline States)**: Out-of-order publication prevention, complete end-to-end multi-version update cycle (1.0 -> 1.1 -> 1.2 -> 1.3 -> 1.4), and explicit pipeline statuses (`PASSED`, `FAILED`, `SKIPPED`).
- **`tests/test_hashing.py` (4 Tests)**: SHA-256 determinism, byte tampering detection, and streaming file hashing.
- **`tests/test_signatures.py` (7 Tests)**: Ed25519 canonical JSON signing, valid signature verification, metadata tampering detection, unauthorized key rejection, expiration validation, and SemVer comparisons.
- **`tests/test_installation.py` (9 Tests)**: ZipSlip path traversal protection, valid staged installation, failed installation recovery, archive size limits, single file limits, total uncompressed size limits, member count limits, compression ratio limits, encrypted entry rejection, duplicate member rejection, corrupt archive rejection, and streaming extraction byte-limit enforcement.
- **`tests/test_reset_and_scenarios.py` (32 Tests)**: Token hygiene (absent from HTML/DOM and API responses), fail-closed loopback authorization, constant-time `hmac.compare_digest`, operational conditions R1–R12, regressions SIZ-001, ISO-001, RST-001, TST-001, all 6 scenario API runs, and repeated updates 1.0.0 through 1.4.0.
- **`tests/test_rollback.py` (4 Tests)**: Older version rollback rejection, same-version reinstallation rejection, sequence replay rejection, and monotonic sequence advancement.
- **`tests/test_server_api.py` (11 Tests)**: Authentication enforcement, unauthorized publishing rejection, admin login, release details inspection, audit log filtering, client history, diagnostic export, and `/how-it-works` rendering.
- **`tests/test_integration.py` (4 Tests)**: Unauthorized publisher attack, expired release rejection, mismatched software ID, and invalid HTTPS certificate rejection.
- **`tests/test_tampering.py` (2 Tests)**: Package tampering (TC04) and metadata tampering (TC05).

---

## 4. Demonstration Mode 1: Automated Attack Simulation CLI

Run the attack demonstration runner to execute the **6 core presentation scenarios** with detailed cryptographic output:

```powershell
python simulate_attacks.py --all
```

*The script automatically connects to or starts the local HTTPS update server daemon.*

### Running Scenarios Individually:

```powershell
# Scenario 1 — Successful Genuine Update (DemoApp 1.0.0 -> 1.1.0)
python simulate_attacks.py --scenario 1

# Scenario 2 — Package Tampering Attack (SHA-256 Digest Mismatch)
python simulate_attacks.py --scenario 2

# Scenario 3 — Rogue Publisher Attack (Unauthorized Ed25519 Private Key)
python simulate_attacks.py --scenario 3

# Scenario 4 — Rollback Attack (Replaying Genuine Older 1.0.0 Release)
python simulate_attacks.py --scenario 4

# Scenario 5 — Metadata Tampering Attack (Altering Hash/Version in JSON)
python simulate_attacks.py --scenario 5

# Scenario 6 — Expired Release Attack (Release Window in Past)
python simulate_attacks.py --scenario 6
```

### The 11-Step Verification Pipeline Mapping:

| Step # | Pipeline Stage | Security Guarantee Enforced | Intercepted Attack Scenarios |
|:---:|---|---|---|
| **Step 1** | Retrieve Signed Release Metadata | TLS transit encryption & JSON schema parsing | Network MITM truncation, malformed manifest |
| **Step 2** | Ed25519 Digital Signature Verification | Asymmetric authorship against pinned public key | **Scenario 3 (Rogue Key)**, **Scenario 5 (Tampered Metadata)** |
| **Step 3** | Metadata Validation & Freshness Check | UTC validity timestamp vs client system clock | **Scenario 6 (Expired Release)**, freeze attacks |
| **Step 4** | Version and Rollback Validation | Monotonic sequence (`candidate > installed`) & SemVer | **Scenario 4 (Rollback / Replay)** |
| **Step 5** | Package Download | Isolated streaming into quarantine `.tmp` buffer | Connection aborts, partial downloads |
| **Step 6** | Calculate Package SHA-256 Digest | 64 KB chunked cryptographic digest generation | Stream-level corruption |
| **Step 7** | Verify Package Hash Match | Strict equality with signed `package_hash` | **Scenario 2 (Package Tampering)** |
| **Step 8** | Package Format & Path Traversal | ZipSlip & ZIP bomb protection (limits, ratio, paths) | Directory traversal, resource exhaustion |
| **Step 9** | Secure Staged Installation & Health Check | Extract to `.staging/`, verify health, preserve `.backup/` | Broken/incomplete application binaries |
| **Step 10** | Commit Trusted Installed Version State | Atomic filesystem swap, commit `state.json` | Desynchronization between disk & state |
| **Step 11** | Telemetry & Final Audit Logging | Post cryptographically signed audit report to server | Fleet compliance drift, silent failures |

---

## 5. Demonstration Mode 2: Live Interactive Web Dashboards

### Step 5.1: Start the HTTPS Update Server
```powershell
python run_server.py --demo
```

Server Controller Banner:
```text
============================================================
   SECURE SOFTWARE UPDATE SYSTEM — SERVER CONTROLLER
============================================================
Default Admin Credentials:
  Username: admin
  Password: [PASSWORD]
------------------------------------------------------------
Presentation Session: sess-20261114042926-c84ca32f
Session Started:      2026-11-14T04:29:26.123456+00:00
------------------------------------------------------------
[+] Demonstration Mode: ENABLED (Authorized client reset enabled on loopback)
------------------------------------------------------------
[+] HTTPS Enabled (TLS 1.3)
    Admin Dashboard:  https://127.0.0.1:5000/admin
    Client Dashboard: https://127.0.0.1:5000/client
    How It Works:     https://127.0.0.1:5000/how-it-works
    CA Certificate:   .../certs/ca.crt
============================================================
```

> **Browser Security Notice:** When opening `https://127.0.0.1:5000` in Chrome/Edge/Firefox, your browser will display a development certificate warning because the certificate was self-generated for this prototype. Click **Advanced** &rarr; **Proceed to 127.0.0.1 (unsafe)** to open the dashboard.

---

### Step 5.2: Administrator Dashboard Walkthrough
Open [`https://127.0.0.1:5000/admin`](https://127.0.0.1:5000/admin):

1. **Active Presentation Session Indicator:**
   - Displays current session identifier (e.g. `sess-20261114...`).
   - Click **Start New Presentation Session** to return the database and client to their initial baseline with full confirmation dialog.
2. **Prepared Releases (Awaiting Publication) Table:**
   - Displays releases that have been cryptographically packaged and signed on the server, but not yet published to clients (e.g. `1.1.0`, `1.2.0`, `1.3.0`, `1.4.0`).
   - Sorted in ascending sequence order so the next release to publish is clearly visible at the top.
   - Click **Publish** to transition a release to `published`. The server enforces strict monotonic ordering (e.g. attempting to publish 1.3.0 before 1.1.0 is rejected).
3. **Published Software Releases Table:**
   - Displays all currently published and revoked releases, sorted strictly by monotonic `release_sequence` descending (highest sequence at top).
   - Click any row to open the **Release Inspector Modal** displaying complete cryptographic metadata, Ed25519 signature, and expiration window.
4. **Live Revocation Demonstration:**
   - Click **Revoke** on any published release (e.g. DemoApp v1.2.0).
   - Enter a revocation reason (e.g., *Security vulnerability in network optimizer*).
   - The status immediately turns red **REVOKED**, client checks will ignore v1.2.0, and the revocation persists across browser refreshes and server restarts.
5. **Quick Demonstration Publisher:**
   - One-click publishing buttons for DemoApp 1.1.0 through 1.4.0.
6. **Security Threat Logs & Real-Time Filters:**
   - Filter events by Type (`PACKAGE_TAMPER_DETECTED`, `INVALID_SIGNATURE`, `ROLLBACK_ATTEMPT`, `RELEASE_REVOKED`, etc.) and Result (`ALL`, `BLOCKED`, `SUCCESS`).

---

### Step 5.3: Client Dashboard Walkthrough
Open [`https://127.0.0.1:5000/client`](https://127.0.0.1:5000/client):

1. **Client Device Telemetry:**
   - Displays currently installed version (`DemoApp v1.0.0`), sequence (`Seq: 1`), health status, and cryptographic anchors.
2. **Sequential Multi-Version Update Demonstration:**
   - **Step 1:** In Admin Dashboard, click **Publish** on DemoApp v1.1.0.
   - **Step 2:** In Client Dashboard, click **Check for Updates**. The server identifies **DemoApp v1.1.0 (Sequence 2)** as an eligible candidate.
   - **Step 3:** Click **Run Secure Update**. All 11 verification steps execute with green checkmarks, DemoApp is updated to 1.1.0, and all 11 green steps remain displayed.
   - **Step 4:** Repeat the process: publish 1.2.0 -> client updates to 1.2.0; publish 1.3.0 -> client updates to 1.3.0; publish 1.4.0 -> client updates to 1.4.0.
3. **11-Step Verification Pipeline Visualizer:**
   - Reflects true execution states: **Pending** (not yet reached), **Running** (actively executing), **Passed** (verified successfully), **Failed** (security violation), and **Skipped** (halted due to earlier failure).
   - Checking for updates preserves existing completed pipeline cards without wiping them back to pending.
   - Double-clicks and duplicate submissions while an update is running are blocked.
4. **Attack Simulation Suite (6 One-Click Scenarios):**
   - Click any of the 6 scenario buttons (Successful Update, Package Tampering, Rogue Publisher, Rollback, Metadata Tampering, Expired Release).
   - Intercepted attacks display the **Security Alert** card with What Happened, Why It Was Blocked, and the Security Guarantee Enforced.
5. **Diagnostic Export:**
   - Click **Export Report** to download an audit JSON manifest containing device state, cryptographic anchors, runtime checksums, and recent incident logs.

---

### Step 5.4: Interactive "How It Works" Architecture & Cryptography Page
Open [`https://127.0.0.1:5000/how-it-works`](https://127.0.0.1:5000/how-it-works):

- **Interactive Architecture SVG**: Clickable components detailing cryptographic responsibilities.
- **SHA-256 Avalanche Lab**: Flip characters and watch 50%+ bit divergence live.
- **Ed25519 Signatures Lab**: Toggle valid vs rogue keys and tampered metadata.
- **Lifecycle Animation Player**: Step-by-step playback with speed controls.
- **Attack Simulations Terminal**: Embedded real-time execution console.
- **Security Limitations & Threat Model**: Transparent prototype boundaries.
