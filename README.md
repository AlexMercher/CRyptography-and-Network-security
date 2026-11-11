# Secure Software Update System with Cryptographic Verification

A robust, fail-secure, production-grade software update distribution prototype implemented for **Computer Networks & Security (CNS)**.

This system guarantees that every software update package received by a client device is authentic, untampered, authorized, fresh, and newer than the currently installed version before any installation code can execute.

---

## 1. System Architecture

The architecture enforces a **Zero-Trust Client Principle**: *The server distributes software, but the client independently decides whether that software is authentic and secure enough to install.*

```
                 +-----------------------------------+
                 |     Administrator / Publisher     |
                 | - Ed25519 Private Key (Secured)   |
                 | - Package Upload & SHA-256 Digest |
                 | - Detached Signature Generation   |
                 +-----------------+-----------------+
                                   |
                                   | HTTPS (TLS 1.3)
                                   v
                 +-----------------------------------+
                 |       Central Update Server       |
                 | - Flask REST API & SQLite DB      |
                 | - Release Metadata & Audit Logs   |
                 | - Admin Dashboard: /admin         |
                 | - Client Dashboard: /client       |
                 +-----------------+-----------------+
                                   |
                                   | HTTPS (Encrypted Download)
                                   v
                 +-----------------------------------+
                 |         Client Application        |
                 | - Provisioned Ed25519 Public Key  |
                 | - Local Trusted Version State     |
                 | - 11-Step Verification Pipeline   |
                 | - Safe Staging & Rollback Engine  |
                 +-----------------------------------+
```

---

## 2. The 7 System Components

| Component | Modules & Files | Functionality |
|---|---|---|
| **1. Admin Dashboard** | `server/templates/admin.html`<br>`server/static/js/admin.js` | Web interface to authenticate, upload packages, auto-hash with SHA-256, sign with Ed25519, publish releases, view audit and security logs. |
| **2. Update Server** | `server/app.py`<br>`server/routes/`<br>`server/database/` | Flask backend, SQLite DB (`update_system.db`), REST endpoints for update checks, encrypted package distribution, activity logging. |
| **3. Cryptographic Engine** | `common/crypto_engine.py` | Deterministic JSON canonicalization, streaming SHA-256 chunked hashing, Ed25519 key generation, detached signature creation & verification. |
| **4. Client Application** | `client/updater.py`<br>`client/downloader.py`<br>`client/verifier.py` | Client updater with 11-step pipeline, TLS download with CA cert validation, independent cryptographic verification. |
| **5. Secure Installation Engine** | `client/installer.py`<br>`client/version_manager.py` | Anti-traversal / Zip-Slip defense, pre-installation backup, staged extraction, health verification, atomic commit to `state.json`, automatic recovery. |
| **6. Logging and Monitoring** | `server/database/database.py` | Records package publication, client checks, downloads, hash mismatches, signature failures, rollback attempts, and installations. |
| **7. Attack Simulation Suite** | `simulate_attacks.py`<br>`tests/` | CLI simulation runner and 29 automated test cases covering tampering, replay, rogue signatures, path traversal, expired releases. |

---

## 3. Cryptographic Key Distinction

| Key / Certificate | Mechanism | Role in System | Storage Location |
|---|---|---|---|
| **Publisher Private Key** | Ed25519 Private Key | Signs canonical release metadata | Kept exclusively by publisher (`keys/publisher_private.pem`) |
| **Publisher Public Key** | Ed25519 Public Key | Verifies release authenticity | Provisioned to clients (`client/trusted_keys/publisher_public.pem`) |
| **Package Digest** | SHA-256 Hash | Detects any payload tampering | Calculated over package bytes & signed inside metadata |
| **TLS Server Certificate** | X.509 RSA Certificate | Authenticates update server hostname & encrypts transport | Update Server (`certs/server.crt`) |
| **Root Certificate Authority (CA)** | X.509 Root CA | Validates server TLS cert during HTTPS | Client trusted store (`client/trusted_certs/ca.crt`) |

---

## 4. Quick Start & Execution Guide

### 4.1 Activate Conda Environment & Install Dependencies

```powershell
# Activate environment
conda activate ./venv

# Ensure all dependencies are installed strictly from requirements.txt
pip install -r requirements.txt
```

### 4.2 Run All Unit, Integration & Security Tests

Run the full pytest suite (29 test cases covering TC01 through TC18):

```powershell
pytest -v
```

All 29 tests pass with 100% success rate:
- `tests/test_hashing.py`: SHA-256 determinism, tampering detection, and chunked verification.
- `tests/test_signatures.py`: Ed25519 signing, verification, metadata alteration detection, rogue key rejection, expiration check.
- `tests/test_tampering.py`: TC04 (package byte tampering) and TC05 (metadata tampering).
- `tests/test_rollback.py`: TC08 (version rollback blocked) and TC09 (sequence replay blocked).
- `tests/test_installation.py`: TC15 (Zip-Slip path traversal blocked), TC16 (valid update), TC17 (installation failure rollback to backup).
- `tests/test_server_api.py`: TC10 & TC11 (unauthorized access and publishing blocked).
- `tests/test_integration.py`: TC07 (unauthorized publisher), TC12 (interrupted download), TC13 (mismatched software ID), TC14 (expired metadata), TC18 (invalid TLS certificate rejected).

---

## 5. Live Professor Demonstration Scenarios

To conduct the live demonstration in front of your professor, you can use either the **Automated CLI Suite** or the **Interactive Web Dashboards**.

### Option A: Automated CLI Demonstration Suite

Run all 6 scenarios sequentially with rich cryptographic output:

```powershell
python simulate_attacks.py --all
```

Or run any scenario individually:
```powershell
python simulate_attacks.py --scenario 1   # Genuine update (1.0.0 -> 1.1.0)
python simulate_attacks.py --scenario 2   # Package tampering (SHA-256 mismatch)
python simulate_attacks.py --scenario 3   # Rogue publisher (Attacker Ed25519 key)
python simulate_attacks.py --scenario 4   # Rollback attack (Replaying older 1.0.0)
python simulate_attacks.py --scenario 5   # Metadata tampering (Hash altered)
python simulate_attacks.py --scenario 6   # Expired release (Timestamp in past)
```

---

### Option B: Interactive Web Dashboards

1. Start the HTTPS Update Server:
```powershell
python run_server.py
```

2. Open the **Admin Dashboard** in your browser:
   - URL: `https://127.0.0.1:5000/admin`
   - Default Administrator Credentials:
     - Username: `admin`
     - Password: `Admin@SecureUpdate2026!`
   - Capabilities:
     - View real-time security events and client download telemetry.
     - Upload custom `.zip` software update packages.
     - Automatically compute SHA-256 hashes.
     - Digitally sign and publish releases using Ed25519.
     - Revoke compromised releases with a single click.

3. Open the **Client Dashboard** in your browser:
   - URL: `https://127.0.0.1:5000/client`
   - Capabilities:
     - View currently installed DemoApp version (`v1.0.0`, Sequence 1).
     - Query server for available updates.
     - Watch the live **11-Step Cryptographic Verification Pipeline** execute step-by-step with glowing indicators.
     - Click any scenario in the **Professor Demonstration Attack Matrix** to show instant fail-secure detection!

---

## 6. Detailed Demonstration Scenario Walkthrough

### Scenario 1 — Successful Update
- **Initial State:** Client has DemoApp 1.0.0 installed.
- **Action:** Administrator signs and publishes DemoApp 1.1.0 (Sequence 2).
- **Execution:** Client retrieves signed metadata over HTTPS, verifies Ed25519 signature with trusted public key, verifies version is newer, downloads package, confirms SHA-256 hash match, validates archive safety, stages, and installs.
- **Verdict:** `PASSED` — DemoApp successfully upgraded to 1.1.0.

### Scenario 2 — Package Tampering Attack
- **Initial State:** Client has DemoApp 1.0.0 installed.
- **Attack Vector:** An adversary intercepts the package during transit or modifies archive bytes on disk.
- **Client Defense:** Client computes SHA-256 hash over the downloaded file and compares it to the signed package hash from the metadata.
- **Verdict:** `ATTACK PREVENTED` — SHA-256 mismatch detected at Step 6. Installation rejected.

### Scenario 3 — Unauthorized Publisher Attack
- **Initial State:** Client has DemoApp 1.0.0 installed.
- **Attack Vector:** An adversary generates their own rogue Ed25519 keypair and signs a malicious update.
- **Client Defense:** Client verifies signature using only the pre-provisioned trusted public key (`keys/publisher_public.pem`).
- **Verdict:** `ATTACK PREVENTED` — Signature verification fails at Step 2. Update rejected.

### Scenario 4 — Rollback Attack
- **Initial State:** Client has DemoApp 1.1.0 installed (Sequence 2).
- **Attack Vector:** An attacker supplies a previously valid, legitimately signed DemoApp 1.0.0 release (Sequence 1).
- **Client Defense:** Client inspects its local trusted state (`client/storage/state.json`). Even though the digital signature is genuine, the client detects `1.0.0 <= 1.1.0` and `sequence 1 <= 2`.
- **Verdict:** `ATTACK PREVENTED` — Rollback blocked at Step 4. Update rejected.

### Scenario 5 — Metadata Tampering Attack
- **Initial State:** Client has DemoApp 1.0.0 installed.
- **Attack Vector:** An adversary alters the version number or package hash inside `release.json` while attempting to keep the publisher's original signature.
- **Client Defense:** Canonical JSON representation ensures any byte-level change causes Ed25519 verification to fail.
- **Verdict:** `ATTACK PREVENTED` — Tampering detected at Step 2. Update rejected.

### Scenario 6 — Expired Release Attack
- **Initial State:** Client has DemoApp 1.0.0 installed.
- **Attack Vector:** An adversary replays a signed release whose `expiration_timestamp` has elapsed.
- **Client Defense:** Client checks metadata expiration window against UTC clock.
- **Verdict:** `ATTACK PREVENTED` — Freshness validation fails at Step 3. Update rejected.

---

## 7. Security Incident Logging & Fail-Secure Design

Every rejection records a security event in SQLite containing:
- Timestamp (UTC ISO 8601)
- Incident Classification (`PACKAGE_TAMPER_DETECTED`, `INVALID_SIGNATURE`, `ROLLBACK_ATTEMPT`, `EXPIRED_OR_INVALID_METADATA`, `ZIP_SLIP_ATTEMPT`)
- Source Client / Target User
- Action Taken: `BLOCKED`

The system strictly adheres to the **Fail-Secure Principle**: If any single check encounters an error, the pipeline immediately halts and aborts before package extraction or execution.

