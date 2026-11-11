# GOAL.md — Secure Software Update System with Cryptographic Verification

## 1. Project Overview

### Project Name
**Secure Software Update System with Cryptographic Verification**

### Project Goal

The goal of this project is to develop a secure, web-based software update distribution system that ensures every software update received by a client is authentic, untampered, authorized, and newer than the currently installed version.

Software update mechanisms are a potential target for attackers. An attacker may intercept update communication, modify a software package, replace a legitimate update with a malicious package, distribute an unauthorized update, or attempt to install an older vulnerable version of the software.

The system must address these threats through cryptographic verification, secure communication, version validation, access control, and controlled installation.

The project will implement a centralized update server and multiple clients that communicate through a secure client-server architecture.

The administrator will be responsible for publishing and managing updates. Clients will periodically check for available updates, download authorized packages, independently verify their authenticity and integrity, validate their version, and install them only after all security checks have passed.

**The fundamental security principle of this project is that no software update must be installed unless it has passed every required verification step.**

This project must be implemented using traditional Computer Networks and Security concepts. No Machine Learning, Deep Learning, Artificial Intelligence, or AI-based detection mechanisms are to be used.

---

# 2. Overall System Architecture

The system will consist of three primary components.

### 2.1 Administrator / Update Publisher

The administrator is responsible for:

- Authenticating into the update management dashboard.
- Uploading software update packages.
- Providing update version information and release details.
- Generating SHA-256 hashes for uploaded packages.
- Signing update metadata using the developer's Ed25519 private key.
- Publishing verified updates.
- Managing previously released versions.
- Viewing update distribution and security logs.

Only authorized administrators must be allowed to publish or modify update releases.

### 2.2 Central Update Server

The update server acts as the centralized distribution and management system.

Its responsibilities include:

- Maintaining the available software versions.
- Storing uploaded update packages.
- Maintaining package hashes and signed release metadata.
- Providing update information to authenticated or authorized clients, according to the configured access policy.
- Distributing update packages through HTTPS.
- Maintaining update history and security logs.
- Rejecting unauthorized publishing operations.
- Providing clients with the information required to verify updates independently.

The update server must not be treated as the ultimate source of trust by the client. Even if an attacker compromises the update server or modifies a stored package, the client must independently verify the publisher's digital signature and package integrity before installation.

### 2.3 Client Application

The client is responsible for:

- Connecting to the central update server.
- Checking whether a newer software version is available.
- Retrieving signed update metadata.
- Downloading the update package.
- Calculating the SHA-256 hash of the downloaded package.
- Verifying the Ed25519 digital signature using the trusted publisher's public key.
- Validating the package version and release metadata.
- Rejecting unauthorized, modified, expired, or outdated updates.
- Installing an update only after all verification steps succeed.
- Recording installation results and verification failures.

The client must maintain its own trusted public key and locally stored version state.

The client must never blindly trust update information received from the server.

---

# 3. Functional Requirements

All the following functionalities must be implemented.

## 3.1 Administrator Authentication and Access Control

**FR01 — Administrator Login**

The system must provide an administrator login interface.

- Administrators must authenticate before accessing the management dashboard.
- Passwords must be stored using secure password hashing rather than plaintext.
- Unauthorized users must not be allowed to upload, modify, publish, or delete update releases.
- Authentication failures must be recorded.

**FR02 — Administrator Dashboard**

The dashboard must allow authorized administrators to:

- View all published updates.
- Upload new update packages.
- View package information and versions.
- Publish and manage releases.
- View update distribution history.
- View security and administrative logs.

## 3.2 Update Package Management

**FR03 — Update Upload**

The administrator must be able to upload software update packages.

The system must:

- Accept supported package formats.
- Validate the uploaded file.
- Calculate the package size.
- Store the package securely.
- Prevent unauthorized modification of published releases.

**FR04 — Version Management**

Every update must have version information.

The system must maintain:

- Software name or identifier.
- Version number.
- Release identifier.
- Release description.
- Release date.
- Package filename.
- Package size.
- SHA-256 hash.
- Digital signature.
- Release status.

Version management must prevent accidental publication of conflicting or older releases.

**FR05 — Update Distribution**

The update server must make published updates available to clients.

Clients must be able to:

- Check for available updates.
- Retrieve update metadata.
- Download the corresponding package.
- Identify the latest authorized release.

Unpublished or unauthorized releases must never be distributed as valid updates.

## 3.3 Cryptographic Operations

**FR06 — SHA-256 Hash Generation**

The system must generate a SHA-256 hash for every uploaded update package.

- Hash generation must happen on the server after upload.
- The hash must be stored alongside the corresponding release metadata.
- The client must independently calculate the hash after downloading the package.
- Both hashes must match before the package can proceed to installation.

**FR07 — Ed25519 Digital Signature Generation**

The publisher must digitally sign the release metadata using an Ed25519 private key.

The signed metadata must bind the package to its important release information, including:

- Software identifier.
- Release version.
- Package SHA-256 hash.
- Release identifier.
- Release timestamp.
- Expiration information, where applicable.

The signing operation must use a deterministic, documented serialization format for the metadata.

The private signing key must remain exclusively under the publisher's control.

It must never be included in the update package or distributed to clients.

**FR08 — Ed25519 Digital Signature Verification**

The client must independently verify the digital signature using the trusted publisher's public key.

- A valid signature must be accepted.
- An invalid signature must be rejected.
- A signature created using an unauthorized key must be rejected.
- Modified signed metadata must be rejected.
- Missing signatures must be rejected.

The client must perform signature verification before trusting the release metadata.

## 3.4 Client Update Operations

**FR09 — Update Checking**

The client must periodically or manually check the update server for available releases.

The client must identify whether:

- A newer version is available.
- The installed version is already up to date.
- No authorized release is available.
- The server cannot be reached.

**FR10 — Update Download**

The client must download the update package over HTTPS.

The client must handle:

- Interrupted downloads.
- Incomplete packages.
- Failed network connections.
- Invalid server responses.
- Missing packages.

Incomplete or failed downloads must never be installed.

**FR11 — Package Integrity Verification**

After downloading an update, the client must independently calculate its SHA-256 hash.

The calculated hash must be compared with the hash contained in the verified release metadata.

If the hashes differ:

- The package must be rejected.
- Installation must not proceed.
- The failure must be recorded.
- The client must display an appropriate error.

**FR12 — Version Validation**

The client must verify that the downloaded update is newer than its currently installed version.

- Older versions must be rejected.
- Reinstallation of the same version must be rejected unless an explicitly authorized recovery operation is implemented.
- Version comparison must follow a clearly defined versioning scheme.
- An update must not be accepted merely because the server identifies it as the latest release.

**FR13 — Expiration and Replay Protection**

The client must validate the freshness of signed release metadata.

- Expired releases must be rejected.
- Previously published release metadata must not be accepted when it violates the client's version or release-state policy.
- The client must maintain the highest successfully installed version or release sequence.
- Replayed older metadata must not bypass version validation.

Expiration checking must use a clearly defined time policy. The client must not silently accept expired metadata when its system clock is invalid or cannot be trusted.

**FR14 — Secure Installation**

Installation must only begin after all required checks succeed.

The required verification sequence is:

1. Retrieve signed release metadata.
2. Verify the publisher's digital signature.
3. Validate metadata fields and release expiration.
4. Validate the software identifier and release version.
5. Download the update package.
6. Calculate its SHA-256 hash.
7. Compare the calculated hash with the signed package hash.
8. Validate the package format and installation contents.
9. Install the update.
10. Update the locally stored installed version.
11. Record the installation result.

If any verification step fails, installation must be stopped.

The client must never execute or install an unverified package.

## 3.5 Logging and Monitoring

**FR15 — Update History**

The system must maintain a record of:

- Published updates.
- Downloaded packages.
- Successful installations.
- Failed installations.
- Rejected packages.
- Version changes.

**FR16 — Security Logs**

The system must record security-related events, including:

- Unauthorized administrator access.
- Invalid digital signatures.
- Package hash mismatches.
- Version rollback attempts.
- Expired update metadata.
- Failed downloads.
- Installation failures.
- Unauthorized publishing attempts.

Logs must include timestamps and sufficient information to investigate security incidents.

Logs must not expose passwords or private cryptographic keys.

**FR17 — Error Handling**

The system must handle errors without crashing or entering an insecure state.

Any failed security verification must result in rejection of the update.

The system must provide understandable error messages while maintaining detailed technical logs for administrators.

---

# 4. Security Requirements

Security is the most important aspect of this project. The following requirements are mandatory.

### SR01 — Data Integrity

SHA-256 must be used to identify changes in update package contents.

Any modification to a downloaded package must result in a hash mismatch and rejection.

### SR02 — Publisher Authentication

Ed25519 digital signatures must establish that the update metadata was signed by an authorized publisher.

The client must verify signatures using a trusted public key obtained through a secure provisioning process.

### SR03 — Confidentiality and Secure Communication

HTTPS must be used for communication between the update server and clients.

TLS certificate verification must be enabled.

Clients must reject invalid server certificates rather than silently falling back to HTTP.

### SR04 — Private Key Protection

The publisher's Ed25519 private key must never be exposed to clients.

- Private keys must not be stored in the public web directory.
- Private keys must not be committed to Git.
- Access to signing operations must be restricted.
- Key permissions must be appropriately configured.

The prototype must document its key storage and protection mechanism.

### SR05 — Rollback Attack Prevention

The client must maintain trusted local version state.

A downloaded package with an older version or release sequence must be rejected even if it has a valid publisher signature.

The client must not rely exclusively on the update server to determine whether a version is acceptable.

### SR06 — Replay Attack Prevention

Signed release metadata must include freshness information, such as a release sequence and expiration timestamp.

The client must validate these fields and maintain previously accepted release state.

A previously valid but outdated release must not be accepted simply because its signature remains valid.

### SR07 — Unauthorized Publishing Prevention

Only authenticated administrators must be able to publish updates.

The system must distinguish between update upload, signing, and publication permissions where appropriate.

### SR08 — Fail-Secure Behaviour

If a security check fails, the system must reject the update.

Examples include:

- Signature verification failure.
- SHA-256 mismatch.
- Invalid metadata.
- Expired metadata.
- Older version.
- Unauthorized signing key.
- Incomplete download.
- Invalid package structure.

The system must never continue installation after a failed verification.

### SR09 — Secure Package Handling

The client must validate the contents of downloaded archives before installation.

It must prevent unsafe archive extraction, including path traversal, absolute-path extraction, and unexpected file replacement.

The installation process must not overwrite files outside the intended installation directory.

### SR10 — Secure Recovery

If installation fails, the system must avoid leaving the software in an inconsistent state.

The client must preserve the previous working version or provide a recovery mechanism before activating the new version.

---

# 5. Cryptographic Design

The project must use the following cryptographic mechanisms.

## 5.1 SHA-256

SHA-256 will be used to calculate the digest of each update package.

The same package must produce the same digest.

Any change to the package contents must produce a different digest with overwhelming probability.

## 5.2 Ed25519

Ed25519 will be used for digital signing and verification.

The publisher will:

1. Maintain an Ed25519 private key.
2. Generate a digital signature over the canonical release metadata.
3. Publish the signed metadata alongside the update package.

The client will:

1. Retrieve the metadata and signature.
2. Obtain the trusted publisher public key.
3. Verify the signature.
4. Trust the signed package hash and release information only after successful verification.

The digital signature must cover the package hash and version information, not just the package filename.

## 5.3 Cryptographic Verification Flow

The expected verification flow is:

**Publisher side:**

- Upload package.
- Calculate SHA-256 digest.
- Create release metadata.
- Sign the metadata using the Ed25519 private key.
- Publish the package and signed metadata.

**Client side:**

- Download signed metadata.
- Verify Ed25519 signature.
- Validate release version and expiration.
- Download package.
- Calculate SHA-256 digest.
- Compare the digest against the signed metadata.
- Proceed to installation only if every verification succeeds.

The client must not trust a package hash received from an unsigned or unverified source.

---

# 6. System Behaviour and Expected Workflows

## 6.1 Publishing a New Update

When an administrator publishes an update:

1. The administrator logs into the dashboard.
2. The administrator uploads a software package.
3. The system validates the package.
4. The system calculates the SHA-256 hash.
5. The administrator provides release information.
6. The system generates canonical release metadata.
7. The signing component signs the metadata using the Ed25519 private key.
8. The release is stored and marked as published.
9. The update becomes available to clients.

A release must not become publicly available as an authorized update before the signing operation succeeds.

## 6.2 Checking for Updates

When a client checks for updates:

1. The client connects to the update server over HTTPS.
2. The server provides the latest available release information.
3. The client retrieves the signed metadata.
4. The client verifies the signature.
5. The client validates the software identifier and version.
6. The client compares the available version with its installed version.
7. If a valid newer version exists, the client offers the update for download.

If no newer version exists, the client must report that the software is up to date.

## 6.3 Downloading and Installing an Update

When the client installs an update:

1. The client downloads the package.
2. The client calculates its SHA-256 hash.
3. The client compares it against the hash in the verified metadata.
4. The client checks package structure and installation paths.
5. The client stages the update.
6. The installation process is executed.
7. The installed version is updated only after successful installation.
8. The installation result is recorded.

If any step fails, the update must not be activated.

## 6.4 Handling a Tampered Update

If an attacker modifies an update package:

1. The client downloads the modified package.
2. The client calculates its SHA-256 hash.
3. The calculated hash does not match the signed metadata.
4. The client rejects the package.
5. Installation is prevented.
6. A security event is recorded.

## 6.5 Handling an Unauthorized Update

If an attacker provides an update signed using an unauthorized key:

1. The client retrieves the update metadata.
2. The client verifies the signature using its trusted public key.
3. Signature verification fails.
4. The client rejects the update.
5. No installation is performed.

## 6.6 Handling a Rollback Attempt

If an attacker attempts to install an older release:

1. The client retrieves the signed release metadata.
2. The client verifies the publisher signature.
3. The client compares the release version and sequence against its trusted local state.
4. The client identifies that the update is older.
5. The client rejects the update.
6. The rollback attempt is recorded.

A valid digital signature must not be sufficient to authorize an older release.

---

# 7. User Interface Requirements

## 7.1 Administrator Dashboard

The administrator dashboard must provide:

- Secure login and logout.
- Update package upload.
- Software version management.
- Release descriptions and publication dates.
- Package hash information.
- Release publication status.
- Update history.
- Security event logs.

## 7.2 Client Dashboard

The client dashboard must provide:

- Currently installed version.
- Latest available version.
- Update availability status.
- Update download option.
- Signature verification status.
- Package integrity verification status.
- Installation progress.
- Installation success or failure.
- Update history.
- Security error messages.

The interface must clearly distinguish between an available update, a verified update, a rejected update, and an installed update.

---

# 8. Database Requirements

SQLite will be used for persistent application data.

The database should maintain separate records for the following entities:

### Administrators
- Administrator ID.
- Username.
- Password hash.
- Account status.
- Creation timestamp.

### Software Releases
- Release ID.
- Software identifier.
- Version.
- Release sequence.
- Description.
- Package filename.
- Package size.
- SHA-256 digest.
- Signed metadata.
- Digital signature.
- Publication timestamp.
- Expiration timestamp.
- Release status.

### Clients
- Client ID.
- Client identifier.
- Installed software version.
- Last update check.
- Client status.

### Update Activity
- Activity ID.
- Client ID.
- Release ID.
- Action performed.
- Verification result.
- Installation result.
- Timestamp.

### Security Events
- Event ID.
- Event type.
- Related client or administrator.
- Description.
- Timestamp.
- Result.

Sensitive information, especially private signing keys and administrator passwords, must never be stored as plaintext database values.

The client must maintain its trusted installed-version state independently of server-controlled release records.

---

# 9. Non-Functional Requirements

### Reliability
The application must handle interrupted downloads, invalid packages, failed verification, and installation errors without crashing.

### Performance
Hash generation and signature verification must be efficient enough for normal software update packages.

### Scalability
The architecture should support multiple clients downloading updates from the centralized server.

### Usability
The administrator and client dashboards must be understandable and straightforward.

### Maintainability
The project must use modular code with separate components for authentication, package management, cryptographic operations, update distribution, verification, installation, and logging.

### Portability
The prototype should support the agreed Windows/Linux development and demonstration environments.

### Security
All security-sensitive operations must follow the fail-secure principle. No verification failure should be bypassed to complete an installation.

### Reproducibility
The project must provide clear execution instructions, dependencies, configuration, test cases, and evidence of successful execution.

---

# 10. Required Attack Simulations and Test Cases

The following scenarios must be implemented and demonstrated.

| ID | Test scenario | Expected behaviour |
|---|---|---|
| TC01 | Upload a genuine software update | Package accepted and processed |
| TC02 | Publish a valid signed update | Release published successfully |
| TC03 | Download an untampered update | Hash and signature verification succeed |
| TC04 | Modify the downloaded package | SHA-256 verification fails; installation rejected |
| TC05 | Modify the signed metadata | Ed25519 verification fails |
| TC06 | Use an invalid digital signature | Update rejected |
| TC07 | Sign using an unauthorized key | Update rejected |
| TC08 | Attempt to install an older version | Rollback prevented |
| TC09 | Replay previously published release metadata | Rejected if stale or below trusted client state |
| TC10 | Attempt to access the admin dashboard without authentication | Access denied |
| TC11 | Attempt to publish an update as an unauthorized user | Publishing denied |
| TC12 | Interrupt an update download | Incomplete package rejected |
| TC13 | Attempt installation with a mismatched software identifier | Update rejected |
| TC14 | Use expired release metadata | Update rejected |
| TC15 | Attempt to extract an archive containing unsafe paths | Package rejected |
| TC16 | Install a valid newer update | Update installed successfully |
| TC17 | Simulate installation failure | Previous working version preserved or restored |
| TC18 | Attempt communication with an invalid HTTPS certificate | Connection rejected |

Every test must produce observable evidence, including relevant application output, security logs, and the resulting client/server state.

---

# 11. Advanced Features

The following features should be implemented only after the primary system is complete.

## 11.1 Failed Update Recovery

If an update installation fails:

- The previous working version must remain available.
- The client must detect the failed installation.
- The client must restore the previous working state where necessary.
- The failure must be recorded.

## 11.2 A/B Update Mechanism

The client may maintain two installation locations:

- Active environment: currently running software.
- Inactive environment: location where the new update is prepared.

The update is installed into the inactive environment, verified, and activated only after successful installation.

If activation fails, the client must return to the previous working environment.

This feature is an advanced extension and is not a prerequisite for the initial working prototype.

---

# 12. Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.11 | Main programming language |
| Flask | Backend and REST API |
| HTML | Frontend structure |
| CSS | Frontend styling |
| JavaScript | Frontend interactions |
| SQLite | Persistent storage |
| Python cryptography library | Cryptographic operations |
| SHA-256 | Package integrity verification |
| Ed25519 | Digital signature generation and verification |
| HTTPS/TLS | Secure client-server communication |
| Git and GitHub | Version control |
| Postman | API testing |
| VS Code | Development environment |

All components should be selected with the goal of producing a working, reproducible prototype within the project deadline.

---

# 13. Project Deliverables

The completed project must contain:

1. A functional administrator dashboard.
2. A functional client dashboard.
3. An update package upload and management system.
4. SHA-256 package hashing.
5. Ed25519 signing and verification.
6. Secure update distribution over HTTPS.
7. Client-side package integrity verification.
8. Software version and release management.
9. Replay and rollback protection.
10. Secure update installation.
11. Update and security event logging.
12. Tampering and unauthorized-update simulations.
13. Failed-update recovery, if time permits.
14. Complete source code and database schema.
15. Test execution evidence and screenshots.
16. Technical research paper and final project report.
17. A working live demonstration.

---

# 14. Project Completion Criteria

The project will be considered complete only when the following conditions are satisfied:

- [ ] An administrator can authenticate and publish a new update.
- [ ] The server calculates the SHA-256 digest of uploaded packages.
- [ ] The publisher can sign release metadata using Ed25519.
- [ ] A client can retrieve signed release metadata over HTTPS.
- [ ] The client can verify the signature independently.
- [ ] The client can download the corresponding update package.
- [ ] The client can independently verify package integrity.
- [ ] The client rejects modified packages.
- [ ] The client rejects updates signed by unauthorized keys.
- [ ] The client rejects expired release metadata.
- [ ] The client rejects older versions and replayed outdated releases.
- [ ] The client installs a valid, newer update.
- [ ] The client does not install a package if any security check fails.
- [ ] Failed downloads and installations are handled safely.
- [ ] Security events and update activities are recorded.
- [ ] All mandatory attack simulations execute successfully.
- [ ] The entire project can be started and demonstrated using documented instructions.

---

# 15. Development Priorities

Development must follow the sequence below.

### Phase 1 — Core Update System
- Administrator authentication.
- Update package upload.
- Update metadata management.
- Client-server communication.
- Update download.

### Phase 2 — Cryptographic Security
- SHA-256 hash generation.
- Ed25519 key generation.
- Digital signature generation.
- Digital signature verification.
- Client-side package integrity verification.

### Phase 3 — Update Security
- Version validation.
- Replay protection.
- Rollback protection.
- HTTPS configuration.
- Unauthorized update rejection.

### Phase 4 — Installation and Logging
- Secure package extraction.
- Controlled installation.
- Installation status management.
- Update history.
- Security event logging.
- Error handling.

### Phase 5 — Attack Simulation and Validation
- Package tampering.
- Invalid signature.
- Unauthorized signing key.
- Rollback attempts.
- Expired metadata.
- Interrupted downloads.
- Invalid certificates.
- Unauthorized administration.

### Phase 6 — Advanced Extensions
- Failed-update recovery.
- A/B update mechanism.
- Additional client support and performance testing.

Phases 1–5 are mandatory. Phase 6 is optional and must not delay completion of the primary system.

---

# 16. Final Project Objective

The final objective is to demonstrate a working, cryptographically protected software update distribution system in which the update publisher, update server, and client follow a clearly defined security protocol.

The system must demonstrate that:

1. Software packages can be securely published and distributed.
2. Digital signatures establish publisher authenticity.
3. SHA-256 verification detects package modifications.
4. HTTPS protects communication between clients and the server.
5. Version and release-state validation prevent unauthorized rollback and stale-update acceptance.
6. Only authenticated, authorized, verified, and newer software updates can be installed.
7. Failed verification or installation never results in an unsafe update being activated.

**Final principle: The update server distributes software, but the client independently decides whether that software is trusted enough to install.**

The project must prioritize correctness, security, reproducibility, and demonstrable evidence over unnecessary complexity.