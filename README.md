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
                 | - How It Works Page: /how-it-works|
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
| **1. Admin Dashboard** | `server/templates/admin.html`<br>`server/static/js/admin.js` | Web interface to authenticate, upload packages, auto-hash with SHA-256, sign with Ed25519, publish releases, view clickable release metadata, revoke releases with reasons, and filter security events. |
| **2. Update Server** | `server/app.py`<br>`server/routes/`<br>`server/database/` | Flask backend, SQLite DB (`update_system.db`), REST endpoints for update checks, encrypted package distribution, activity logging, diagnostic reports. |
| **3. Cryptographic Engine** | `common/crypto_engine.py` | Deterministic JSON canonicalization, streaming SHA-256 chunked hashing, Ed25519 key generation, detached signature creation & verification. |
| **4. Client Application** | `client/updater.py`<br>`client/downloader.py`<br>`client/verifier.py` | Client updater with 11-step pipeline, TLS download with CA cert validation, independent cryptographic verification. |
| **5. Secure Installation Engine** | `client/installer.py`<br>`client/version_manager.py` | Anti-traversal / Zip-Slip defense, pre-installation backup, staged extraction, health verification, atomic commit to `state.json`, automatic recovery. |
| **6. Logging and Monitoring** | `server/database/database.py` | Records package publication, client checks, downloads, hash mismatches, signature failures, rollback attempts, and installations. |
| **7. Attack Simulation & Education** | `simulate_attacks.py`<br>`server/templates/how_it_works.html` | CLI simulation runner (6 real attack scenarios), automated pytest suite (34 tests), and interactive web education page with SVG diagram and crypto labs. |

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

## 4. The 11-Step Fail-Secure Verification Pipeline

1. **Step 1: Retrieve Signed Release Metadata** &mdash; Fetches signed manifest via HTTPS; parses JSON schema.
2. **Step 2: Ed25519 Digital Signature Verification** &mdash; Canonicalizes JSON fields and verifies detached signature against pinned publisher public key.
3. **Step 3: Metadata Validation and Freshness Check** &mdash; Validates schema integrity and checks UTC expiration against system clock.
4. **Step 4: Version and Rollback Validation** &mdash; Ensures candidate version follows SemVer and `candidate_sequence > installed_sequence`.
5. **Step 5: Package Download to Isolated Staging** &mdash; Streams download into quarantine `.tmp` buffer.
6. **Step 6: Calculate Package SHA-256 Digest** &mdash; Computes cryptographic digest over downloaded archive in 64 KB memory chunks.
7. **Step 7: Verify Package Hash Match** &mdash; Strict constant-time equality check against metadata signed `package_hash`.
8. **Step 8: Package Format & Path Traversal Inspection** &mdash; Inspects ZIP entries to block Zip Slip (`..`, absolute paths).
9. **Step 9: Secure Staged Installation & Health Check** &mdash; Extracts to `.staging/`, backs up current version, verifies manifest integrity.
10. **Step 10: Commit Trusted Installed Version State** &mdash; Atomically swaps directories and writes updated `demoapp/state.json`.
11. **Step 11: Telemetry & Final Audit Logging** &mdash; Sends installation completion telemetry to server audit logs.

---

## 5. Quick Start & Execution Guide

### 5.1 Activate Conda Environment & Install Dependencies

```powershell
# Activate environment
conda activate ./venv

# Ensure all dependencies are installed strictly from requirements.txt
pip install -r requirements.txt
```

### 5.2 Run All Unit, Integration & Security Tests

Run the full pytest suite (**34 tests** covering TC01 through TC18 and UI endpoints):

```powershell
pytest -v
```

All 34 tests pass with 100% success rate:
- `tests/test_hashing.py`: SHA-256 determinism, tampering detection, and chunked verification.
- `tests/test_signatures.py`: Ed25519 signing, verification, metadata alteration detection, rogue key rejection, expiration check.
- `tests/test_tampering.py`: TC04 (package byte tampering) and TC05 (metadata tampering).
- `tests/test_rollback.py`: TC08 (version rollback blocked) and TC09 (sequence replay blocked).
- `tests/test_installation.py`: TC15 (Zip-Slip path traversal blocked), TC16 (valid update), TC17 (installation failure rollback to backup).
- `tests/test_server_api.py`: TC10 & TC11 (unauthorized access and publishing blocked), login, log filtering, release details, client history, diagnostic export, and `/how-it-works` template rendering.
- `tests/test_integration.py`: TC07 (unauthorized publisher), TC12 (interrupted download), TC13 (mismatched software ID), TC14 (expired metadata), TC18 (invalid TLS certificate rejected).

---

## 6. Live Professor Demonstration Scenarios

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

1. **Start the HTTPS Update Server:**
```powershell
python run_server.py
```

2. **Open the Admin Dashboard:**
   - URL: `https://127.0.0.1:5000/admin`
   - Features: Clickable release rows with detailed metadata inspector modal, release revocation with reasons, security event filtering (event type, result, search), and live database statistics.

3. **Open the Client Dashboard:**
   - URL: `https://127.0.0.1:5000/client`
   - Features: Side-by-side version comparison card, package metadata/digest inspection, live 11-step verification pipeline cards, understandable threat failure breakdown, installation history, and downloadable JSON diagnostic report.

4. **Open the "How It Works" Explanation Page:**
   - URL: `https://127.0.0.1:5000/how-it-works`
   - Features:
     1. Interactive SVG Architecture Diagram with clickable component inspector.
     2. Cryptography Explained with live WebCrypto SHA-256 avalanche effect simulator and Ed25519 signature verifier.
     3. 11-step interactive Complete Update Lifecycle player (Play, Pause, Prev, Next, Restart, Speed controls).
     4. Attack Simulations Lab executing live backend tests for all 6 attack scenarios.
     5. Trust & Key Management breakdown (transport vs payload authenticity).
     6. Rigorous disclosure of prototype security limitations & threat model boundaries.

---

## 7. System UI Screenshots

- **Admin Dashboard**: `docs/screenshots/admin_dashboard.png`
- **Client Dashboard**: `docs/screenshots/client_dashboard.png`
- **How It Works Interactive Page**: `docs/screenshots/how_it_works.png`
