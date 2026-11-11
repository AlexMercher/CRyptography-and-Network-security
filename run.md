# Complete Execution & Demonstration Guide (`run.md`)
### Secure Software Update System with Cryptographic Verification (CNS)

This document provides a comprehensive, step-by-step walkthrough to run, test, and demonstrate the full nature of the Secure Software Update System in front of your professor or evaluator.

---

## 1. Environment Setup

Always ensure the project's conda environment is activated before running commands or starting servers.

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

## 2. Complete Verification Suite (Pytest)

Run the comprehensive automated test suite covering all mandatory test cases across Unit, Integration, Security, and UI endpoint layers:

```powershell
pytest -v
```

### Expected Test Results:
All **34 tests** pass with 100% success rate:
- **`tests/test_hashing.py`**: Verifies SHA-256 determinism, byte tampering detection, and chunked streaming file hashing.
- **`tests/test_signatures.py`**: Verifies Ed25519 canonical JSON signing, valid signature verification, metadata alteration detection, rogue key rejection, and expiration checks.
- **`tests/test_tampering.py`**: Verifies TC04 (package byte tampering) and TC05 (metadata tampering).
- **`tests/test_rollback.py`**: Verifies TC08 (version rollback rejection) and TC09 (sequence replay rejection).
- **`tests/test_installation.py`**: Verifies TC15 (Zip-Slip / path traversal rejection), TC16 (valid update installation), and TC17 (installation failure rollback to backup).
- **`tests/test_server_api.py`**: Verifies TC10 & TC11 (unauthorized admin access & publishing rejection), admin login, release details inspection, log filtering, client history, diagnostic export, and `/how-it-works` template rendering.
- **`tests/test_integration.py`**: Verifies TC07 (unauthorized publisher), TC12 (interrupted download), TC13 (mismatched software ID), TC14 (expired metadata), and TC18 (invalid HTTPS certificate rejection).

---

## 3. Demonstration Mode 1: Automated Attack Simulation CLI

Run the dedicated demonstration runner to execute the **6 core presentation scenarios** with detailed cryptographic output:

```powershell
python simulate_attacks.py --all
```

*The script automatically starts the local HTTPS update server daemon if it is not already running.*

### Running Scenarios Individually:

You can trigger any individual scenario on demand:

```powershell
# Scenario 1 — Successful Update (Genuine DemoApp 1.0.0 -> 1.1.0)
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
| **Step 8** | Package Format & Path Traversal | ZipSlip protection (no `..` or root escaping paths) | Directory traversal malicious archives |
| **Step 9** | Secure Staged Installation & Health Check | Extract to `.staging/`, verify health, preserve `.backup/` | Broken/incomplete application binaries |
| **Step 10** | Commit Trusted Installed Version State | Atomic filesystem swap, commit `state.json` | Desynchronization between disk & state |
| **Step 11** | Telemetry & Final Audit Logging | Post cryptographically signed audit report to server | Fleet compliance drift, silent failures |

---

## 4. Demonstration Mode 2: Live Interactive Web Dashboards

To demonstrate the full graphical interface with real-time pipeline visualization and administrative telemetry:

### Step 4.1: Start the HTTPS Update Server
In your terminal, execute:

```powershell
conda activate ./venv

# To enable demonstration mode with authorized loopback reset:
python run_server.py --demo

# Note: Production mode defaults to fail-closed (DEMO_MODE=False):
# python run_server.py
```

Output:
```text
============================================================
   SECURE SOFTWARE UPDATE SYSTEM — SERVER CONTROLLER
============================================================
Default Admin Credentials:
  Username: admin
  Password: Admin@SecureUpdate2026!
------------------------------------------------------------
[+] Demonstration Mode: ENABLED (Authorized client reset enabled on loopback)
------------------------------------------------------------
[+] HTTPS Enabled (TLS 1.3)
    Admin Dashboard:  https://127.0.0.1:5000/admin
    Client Dashboard: https://127.0.0.1:5000/client
    CA Certificate:   .../certs/ca.crt
============================================================
```

> **Security Architecture Note on Client Reset:**
> In production mode (`DEMO_MODE=False`), the client state reset capability is completely disabled. In demonstration mode (`--demo`), client state reset is restricted strictly to local loopback connections (`127.0.0.1`) and requires an authenticated administrator session with CSRF verification. No secret reset tokens are ever exposed to client HTML, DOM, or JavaScript.
    Admin Dashboard:   https://127.0.0.1:5000/admin
    Client Dashboard:  https://127.0.0.1:5000/client
    How It Works:      https://127.0.0.1:5000/how-it-works
    CA Certificate:    D:\projects\CNS\certs\ca.crt
============================================================
```

> **Browser Security Notice:** When opening `https://127.0.0.1:5000` in Chrome/Edge/Firefox, your browser will display a development certificate warning because the certificate was self-generated for this prototype. Click **Advanced** &rarr; **Proceed to 127.0.0.1 (unsafe)** to open the dashboard.

---

### Step 4.2: Administrator Dashboard Walkthrough
Open [`https://127.0.0.1:5000/admin`](https://127.0.0.1:5000/admin) in your browser:

1. **Automatic / Manual Session Authentication:**
   - The dashboard automatically authenticates using default demo credentials or allows manual login (`admin` / `Admin@SecureUpdate2026!`).
   - The badge displays glowing green **Active: admin**.
2. **Review Live Database Metrics:**
   - Real-time counts of Published Releases, Connected Clients, Attacks Blocked (Fail-Secure), and Successful Installs drawn directly from SQLite tables.
3. **Clickable Release Rows & Release Details Modal:**
   - Click on any release row in the **Published Software Releases** table.
   - An inspector modal displays full release metadata: Software ID, Version, Monotonic Sequence, Package Filename, File Size, SHA-256 Digest (with 1-click copy), Ed25519 Signature (with 1-click copy), Expiration Timestamp, and Revocation Status.
4. **Release Revocation with Reason:**
   - Click **Revoke** on any active release.
   - A modal dialog prompts for the revocation reason (e.g., *Discovered zero-day vulnerability in dependencies*).
   - Once confirmed, the release is marked **REVOKED**, client checks will ignore it, and the revocation reason and timestamp are persisted in the database.
5. **Interactive Security Event Filters:**
   - Filter logs by **Event Type** (`ALL`, `SIGNATURE_VERIFY_FAILURE`, `PACKAGE_TAMPER_DETECTED`, `ROLLBACK_BLOCKED`, `MALICIOUS_PACKAGE_UPLOAD`, etc.).
   - Filter by **Outcome** (`ALL`, `BLOCKED`, `SUCCESS`).
   - Search logs in real time via the search box.

---

### Step 4.3: Client Dashboard & Visual Verification Pipeline Walkthrough
Open [`https://127.0.0.1:5000/client`](https://127.0.0.1:5000/client) in your browser:

1. **Version Comparison Card:**
   - Displays a side-by-side comparison between **Currently Installed Version** (e.g. `v1.0.0`, Sequence 1) and **Available Server Version** (e.g. `v1.1.0`, Sequence 2) with status badge (*Update Available* or *Up to Date*).
2. **Package Metadata & Digest Inspection:**
   - Displays target package filename, archive size, SHA-256 digest, and expiration date.
3. **11-Step Cryptographic Verification Pipeline:**
   - Click **Check & Apply Genuine Update**.
   - Watch the pipeline execute sequentially across all 11 discrete steps.
   - Cards display glowing cyan indicators during execution, turning green `[PASS]` on success.
4. **Understandable Threat & Failure Breakdown:**
   - When an attack scenario is run, an alert card renders:
     - **What Happened:** Plain-English description of the intercepted threat.
     - **Why It Was Blocked:** Technical explanation of the failed check.
     - **Security Guarantee Enforced:** The cryptographic principle maintaining system integrity.
5. **Client Installation & Audit History Table:**
   - Shows historical updates, checks, and verification attempts with timestamps and status badges.
6. **Export Diagnostic Report:**
   - Click **Export Diagnostic Report (JSON)** to download a full client health report including client state, cryptographic anchors, runtime manifest, and recent logs.

---

### Step 4.4: Interactive "How It Works" Architecture & Cryptography Page
Open [`https://127.0.0.1:5000/how-it-works`](https://127.0.0.1:5000/how-it-works) in your browser:

This page provides an interactive, visual explanation of the entire system architecture across 6 comprehensive sections:

1. **System Architecture Diagram (Interactive SVG):**
   - Clickable SVG diagram containing Publisher, Package Processor, SHA-256 Engine, Ed25519 Signer, Central Update Server, Client Verifier, and Staged Installer.
   - Clicking any node opens the **Component Inspector** showing its cryptographic role, threat mitigations, and source code reference.
2. **Cryptography Explained:**
   - **SHA-256 Hashing Lab:** Real-time hashing via WebCrypto API. Click **Flip Single Character** to witness the **Avalanche Effect** with character-by-character red diff highlighting!
   - **Ed25519 Signatures:** Interactive verifier demonstrating mathematical verification with toggles for Valid Key, Rogue Attacker Key, and Tampered Metadata.
   - **Integrity vs Authenticity:** Comprehensive comparison matrix explaining why both SHA-256 and Ed25519 are mandatory.
3. **Complete Update Lifecycle Player:**
   - Step-by-step interactive player walking through all 11 real pipeline steps.
   - Controls: **Play**, **Pause**, **Previous**, **Next**, **Restart**, and **Speed (0.5x, 1.0x, 2.0x)**.
   - Highlights the active step on a timeline track with detailed operational explanation.
4. **Attack Simulations Lab:**
   - Cards for all 6 scenarios featuring threat explanations and visual defense highlights.
   - Each card includes an interactive **Execute Real Attack** button that executes the actual backend simulation endpoint (`/api/client/run-scenario/<id>`) and streams real-time console output into an embedded terminal.
5. **Trust & Key Management:**
   - Breakdown of Publisher Private Key, Client Public Key, TLS Certificates, and why transport security (HTTPS) must be paired with end-to-end payload authenticity.
6. **Security Limitations & Threat Model:**
   - Honest, rigorous disclosure of prototype boundaries (key compromise, host OS root malware, local rollback state tampering, NTP spoofing, and freeze attacks).

---

## 5. UI Screenshots

High-resolution screenshots are located in `docs/screenshots/`:
- `docs/screenshots/admin_dashboard.png`: Administrator Dashboard with clickable release rows, metrics, and security filters.
- `docs/screenshots/client_dashboard.png`: Client Dashboard with version comparison, 11-step pipeline, failure explanations, and history.
- `docs/screenshots/how_it_works.png`: Interactive How It Works page with SVG architecture, crypto animations, lifecycle player, and attack lab.
