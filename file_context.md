# Project Context: Secure Software Update System (CNS)

## 1. System Overview
The Secure Software Update System provides cryptographically verifiable, rollback-protected software updates to distributed endpoints.

### Key Components
1. **Publisher Environment:** Authors software versions in `demoapp/versions/<version>`, packages them into ZIP archives in `storage/packages/`, computes SHA-256 digests, and generates detached Ed25519 signatures over deterministic canonical JSON metadata.
2. **Update Server (`server/`):** Hosts signed packages, exposes discovery APIs (`/api/updates/check`, `/api/updates/catalog`), and provides an administrative interface for release preparation, publication, revocation, and security audit telemetry.
3. **Client Application (`client/`):** Executes the mandatory 11-step verification pipeline (retrieval, Ed25519 signature check, freshness check, rollback protection, streaming download, SHA-256 hash match, archive safety inspection, staged installation, state commitment, and central telemetry reporting).
4. **Interactive Learning & Diagnostics (`/how-it-works`):** Demonstrates architectural workflows, cryptographic algorithms (SHA-256 avalanche effect, Ed25519 verification), and attack simulation vectors.

## 2. Release Publication Lifecycle
The release lifecycle strictly separates:
- **Prepared Releases:** Software packages that have been authored, validated, and signed by the publisher, but have NOT yet been published for general client deployment. These releases are not discoverable by clients.
- **Published Releases:** Releases that have been explicitly approved and published by an administrator. Only published releases are discoverable via `/api/updates/check`.
- **Revoked Releases:** Releases that were previously published but subsequently revoked due to security or operational defects. Revoked releases cannot be offered to clients or installed.

## 3. Cryptographic and Transport Standards
- **Asymmetric Signatures:** PureEd25519 (RFC 8032) using 32-byte seeds and Edwards-curve Curve25519.
- **Hash Algorithm:** SHA-256 (FIPS 180-4) with streaming 64 KB chunking.
- **Transport:** HTTPS enforced with server-certificate validation against custom Root CA.
- **Rollback Mitigation:** Monotonic sequence enforcement and Semantic Versioning (SemVer).
- **Archive Safety:** Static pre-extraction validation (Zip Slip directory traversal rejection, file size limits, compression ratio bounds, encryption flags) combined with dynamic streaming extraction byte-counting.

## 4. Verification Pipeline Execution States & Monotonic Ordering
- **Pipeline States:** Each of the 11 pipeline stages adheres to explicit execution states: `PENDING` (not yet reached), `RUNNING` (currently executing), `PASSED` (cryptographically or logically verified), `FAILED` (encountered error or security violation), and `SKIPPED` (subsequent stages bypassed due to an earlier failure).
- **Sequence Invariance:** Releases are strictly ordered by monotonic `release_sequence`. Sequential publication is enforced on the server, and the client verification pipeline halts if an out-of-order or rollback candidate is evaluated.
- **Client State Synchronization:** Authoritative state is maintained in `client/storage/state.json` and mirrored in `demoapp/current/version.json`. Checking for updates queries server state without altering or wiping completed pipeline visualizers.
- **Presentation Session Baseline:** A new presentation session initializes DemoApp v1.0.0 (sequence 1) as the sole published version on client and server, placing versions 1.1.0 through 1.4.0 in a prepared state awaiting progressive publication.


