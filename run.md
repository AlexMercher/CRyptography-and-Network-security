# Complete Execution & Demonstration Guide (`run.md`)
### Secure Software Update System with Cryptographic Verification (CNS)

This document provides a step-by-step walkthrough to run, test, and demonstrate the full nature of the Secure Software Update System in front of your professor or evaluator.

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

Run the comprehensive automated test suite covering all **18 mandatory test cases (TC01 - TC18)** across Unit, Integration, and Security layers:

```powershell
pytest -v
```

### Expected Test Results:
All **29 tests** should pass in under 10 seconds:
- **`tests/test_hashing.py`**: Verifies SHA-256 determinism, byte tampering detection, and chunked streaming file hashing.
- **`tests/test_signatures.py`**: Verifies Ed25519 canonical JSON signing, valid signature verification, metadata alteration detection, rogue key rejection, and expiration checks.
- **`tests/test_tampering.py`**: Verifies TC04 (package byte tampering) and TC05 (metadata tampering).
- **`tests/test_rollback.py`**: Verifies TC08 (version rollback rejection) and TC09 (sequence replay rejection).
- **`tests/test_installation.py`**: Verifies TC15 (Zip-Slip / path traversal rejection), TC16 (valid update installation), and TC17 (installation failure rollback to backup).
- **`tests/test_server_api.py`**: Verifies TC10 & TC11 (unauthorized admin access & publishing rejection).
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

### What Each Scenario Proves to the Professor:

| Scenario | Simulated Action | Exact Security Layer Intercepting | Result |
|---|---|---|:---:|
| **Scenario 1** | Administrator publishes authentic DemoApp 1.1.0 update. | Passes all 11 pipeline steps: Ed25519 signature valid, SHA-256 match, staged install. | **`SUCCESS`**<br>App upgraded to 1.1.0 |
| **Scenario 2** | Adversary injects malicious payload inside package ZIP after signing. | **Step 6 (SHA-256 Digest Verification)** calculates digest and catches mismatch before extraction. | **`BLOCKED`**<br>Installation rejected |
| **Scenario 3** | Attacker signs a malicious release using a rogue Ed25519 private key. | **Step 2 (Ed25519 Signature Verification)** rejects signature against trusted publisher public key. | **`BLOCKED`**<br>Signature invalid |
| **Scenario 4** | Attacker replays validly signed DemoApp 1.0.0 release to client on 1.1.0. | **Step 4 (Version & Sequence Validation)** checks local `state.json` and rejects older version. | **`BLOCKED`**<br>Rollback prevented |
| **Scenario 5** | Adversary alters package hash in metadata while retaining original signature. | **Step 2 (Canonical Verification)** detects canonical byte mismatch. | **`BLOCKED`**<br>Signature invalid |
| **Scenario 6** | Attacker supplies a validly signed release whose expiration date has elapsed. | **Step 3 (Freshness Validation)** checks UTC validity window against system clock. | **`BLOCKED`**<br>Expired release rejected |

---

## 4. Demonstration Mode 2: Live Interactive Web Dashboards

To demonstrate the full graphical interface with real-time pipeline visualization and administrative telemetry:

### Step 4.1: Start the HTTPS Update Server
In your terminal, execute:

```powershell
conda activate ./venv
python run_server.py
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
[+] HTTPS Enabled (TLS 1.3)
    Admin Dashboard:  https://127.0.0.1:5000/admin
    Client Dashboard: https://127.0.0.1:5000/client
    CA Certificate:   D:\projects\CNS\certs\ca.crt
============================================================
```

> **Browser Security Notice:** When opening `https://127.0.0.1:5000` in Chrome/Edge/Firefox, your browser will display a development certificate warning because the certificate was self-generated for this prototype. Click **Advanced** &rarr; **Proceed to 127.0.0.1 (unsafe)** to open the dashboard.

---

### Step 4.2: Administrator Dashboard Walkthrough
Open [`https://127.0.0.1:5000/admin`](https://127.0.0.1:5000/admin) in your browser:

1. **Authenticate Admin Session:**
   - Click **Login as Admin**.
   - Enter `admin` / `Admin@SecureUpdate2026!`.
   - The status badge changes to glowing green **Active: admin**.
2. **Review System Overview Metrics:**
   - View Published Releases, Active Clients, Blocked Security Incidents, and Successful Installs.
3. **Upload & Digitally Sign an Update:**
   - In the **Upload & Sign Software Package** card, select `storage/packages/demoapp-1.2.0.zip`.
   - Click **1. Upload & Calculate SHA-256 Hash**.
   - Notice the server automatically parses the ZIP, verifies archive safety, and displays the exact SHA-256 digest.
   - Enter Version `1.2.0`, Sequence `3`, and click **2. Sign Metadata & Publish Release**.
   - The release metadata is canonicalized, signed using the publisher's Ed25519 private key, stored in the database, and added to the **Published Software Releases** table.
4. **Live Security & Telemetry Logs:**
   - Watch the **Security Event Logs** terminal display real-time intrusion and tampering attempts with timestamps and `[BLOCKED]` verdicts.
   - Watch the **Client Update Activity** feed record every update check, download, and installation.

---

### Step 4.3: Client Dashboard & Visual Verification Pipeline Walkthrough
Open [`https://127.0.0.1:5000/client`](https://127.0.0.1:5000/client) in a second browser tab:

1. **Inspect Client Identity:**
   - Shows installed baseline: `DemoApp v1.0.0` (Sequence 1) with `HEALTHY` zero-trust status.
2. **Check for Updates:**
   - Click **Check for Updates**.
   - The client queries the server over TLS and detects available release `v1.1.0` (Sequence 2) or `v1.2.0` (Sequence 3) with signed digest details.
3. **Run the 11-Step Verification Pipeline:**
   - Click **Run Secure Update**.
   - Watch each step in the **Mandatory 11-Step Cryptographic Verification Pipeline** illuminate green sequentially:
     - *Step 1:* Retrieve Signed Metadata
     - *Step 2:* Ed25519 Signature Verification
     - *Step 3:* Freshness & Expiration Check
     - *Step 4:* Version & Sequence Anti-Rollback Check
     - *Step 5:* Encrypted HTTPS Download
     - *Step 6:* SHA-256 Digest Verification
     - *Step 7:* Package Anti-Traversal Inspection
     - *Step 8:* Staged Installation & Safe Activation
     - *Step 9:* Commit Trusted Local State
     - *Step 10:* Audit Logging & Telemetry Reporting
   - The client status updates to `DemoApp v1.1.0` (Sequence 2).
4. **Demonstrating Live Attack Scenarios via Web UI:**
   - Under the **Professor Demonstration Attack Matrix**, click any scenario button:
     - **Click Scenario 2 (Package Tampering):** Watch Step 6 immediately turn **red `[BLOCKED]`** with the message `SHA-256 integrity check failed`.
     - **Click Scenario 3 (Unauthorized Publisher):** Watch Step 2 turn **red `[BLOCKED]`** with `Digital signature verification failed`.
     - **Click Scenario 4 (Rollback Attack):** Watch Step 4 turn **red `[BLOCKED]`** with `Rollback blocked: candidate version 1.0.0 is older than installed version 1.1.0`.
     - **Click Scenario 5 (Metadata Tampering):** Watch Step 2 turn **red `[BLOCKED]`** with `Untrusted or modified release metadata`.
     - **Click Scenario 6 (Expired Release):** Watch Step 3 turn **red `[BLOCKED]`** with `Release metadata has expired`.
5. **Reset Client Baseline:**
   - Click **Reset to v1.0.0 Baseline** at the top right anytime to restore DemoApp back to version 1.0.0 for a fresh demonstration.

---

## 5. Demonstration Mode 3: Verifying the Running Application

You can also run the actual DemoApp software directly from your terminal to prove that the application files on disk were genuinely updated:

```powershell
# Run the current installed application
python demoapp/current/main.py
```

### Before Update (Version 1.0.0):
```text
==================================================
  DemoApp v1.0.0 (Seq: 1)
  Build Date: 2026-11-01T00:00:00Z
  Status: DemoApp 1.0.0 is running stably.
  Features:
    - Baseline diagnostic engine
    - Basic local logging
==================================================
```

### After Update (Version 1.1.0):
```text
==================================================
  DemoApp v1.1.0 (Seq: 2) [UPDATED]
  Build Date: 2026-11-10T12:00:00Z
  Status: DemoApp 1.1.0 is running with improved performance.
  Diagnostics:
    - memory_optimization: active
    - crypto_telemetry: healthy
    - network_latency_ms: 14
  Features:
    - Baseline diagnostic engine
    - Basic local logging
    - Network performance optimizer
    - Enhanced cryptographic telemetry
==================================================
```

---

## 6. Generating Formal Evidence Report

To export a complete markdown audit report with test results, attack scenario proofs, and recent database security logs:

```powershell
python scripts/generate_evidence_report.py
```

This generates [`EVIDENCE_REPORT.md`](file:///d:/projects/CNS/EVIDENCE_REPORT.md) containing:
- Test case matrix (TC01 - TC18)
- Exact SHA-256 hashes and Ed25519 signatures
- Live SQLite database audit logs
- Full pytest execution transcripts

---

## 7. Key Distinctions to Explain to Your Professor

1. **Ed25519 Signing Keys vs. TLS Server Certificates:**
   - **Ed25519 Publisher Keypair:** Confirms **who authored the update**. The private key never leaves the publisher's secure workstation. The public key is baked into the client before distribution.
   - **TLS Certificate:** Confirms **who operates the update server** and encrypts network traffic between client and server.
   - *Even if an attacker compromises the update server or tampers with the database, the client rejects modified or unauthorized updates because the attacker does not possess the publisher's Ed25519 private key.*
2. **Canonical JSON Serialization (RFC 8785):**
   - Cryptographic signatures require identical byte sequences. The system uses deterministic key sorting with compact separators `(',', ':')` and UTF-8 encoding so whitespace variations cannot invalidate genuine signatures.
3. **Fail-Secure Architecture:**
   - If any verification step fails, the update process immediately halts.
   - Incomplete downloads, mismatched hashes, older versions, or expired metadata are never extracted or executed.
4. **Safe Staging & Automatic Recovery:**
   - Packages are verified in temporary staging.
   - The active version is backed up before installation.
   - If activation fails post-installation health verification, the installer automatically rolls back to the previous working version.

