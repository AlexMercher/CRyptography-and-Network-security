// Secure Software Update System - How It Works Interactive Logic

document.addEventListener('DOMContentLoaded', () => {
  initArchitectureSvg();
  initCryptoDemo();
  initLifecyclePlayer();
  initSubnavScrollSpy();
});

/* ====================================================================
   1. SYSTEM ARCHITECTURE COMPONENT INSPECTOR
   ==================================================================== */
const ARCH_COMPONENTS = {
  publisher: {
    title: 'Administrator / Publisher Environment',
    icon: 'fa-user-shield',
    tag: 'Build Environment (Offline/HSM)',
    tagClass: 'badge-info',
    desc: 'The software publisher packages application code, defines version numbers adhering to SemVer, sets sequential release numbers, and calculates cryptographic digests. Release metadata is signed using an offline Ed25519 private key before publication.',
    crypto: 'Ed25519 signing (RFC 8032) & SHA-256 binary hashing (FIPS 180-4).',
    threat: 'Unauthorized releases, forged code injections, man-in-the-middle manifest modifications.',
    code: 'server/services/release_manager.py'
  },
  processing: {
    title: 'Package Processing & Canonical Archive Layout',
    icon: 'fa-box',
    tag: 'Packaging Pipeline',
    tagClass: 'badge-info',
    desc: 'The application artifact is archived into a standardized ZIP container. Archive contents are validated against path traversal (Zip Slip), ensuring relative paths do not escape the destination target.',
    crypto: 'ZIP format canonicalization & internal structure verification.',
    threat: 'Directory traversal vulnerabilities, hidden root-level payload execution.',
    code: 'server/services/release_manager.py'
  },
  sha256: {
    title: 'SHA-256 Cryptographic Hashing Engine',
    icon: 'fa-fingerprint',
    tag: 'Cryptographic Primitive',
    tagClass: 'badge-cyan',
    desc: 'Computes a 256-bit collision-resistant digest over the entire release ZIP file byte stream. This digest is embedded directly into the signed release metadata, binding the manifest to the exact package contents.',
    crypto: 'SHA-256 (256-bit digest, avalanche property, pre-image resistance).',
    threat: 'Bit-rot, corrupted downloads, in-flight malicious byte injection by proxies.',
    code: 'common/crypto.py:calculate_sha256()'
  },
  ed25519: {
    title: 'Ed25519 Digital Signing Engine',
    icon: 'fa-key',
    tag: 'Asymmetric Authentication',
    tagClass: 'badge-warning',
    desc: 'Produces a compact 64-byte Edwards-curve digital signature over the canonical JSON representation of the release metadata. Canonical serialization guarantees that JSON key ordering and whitespace cannot invalidate valid signatures.',
    crypto: 'Ed25519 (Curve25519, SHA-512, RFC 8032).',
    threat: 'Unauthorized publishers, malicious forged metadata, rogue CDN updates.',
    code: 'common/crypto.py:sign_data()'
  },
  server: {
    title: 'HTTPS Update Distribution Server',
    icon: 'fa-server',
    tag: 'Public Distribution Network',
    tagClass: 'badge-info',
    desc: 'Flask-based distribution hub serving signed metadata manifests, hosting package ZIP files, and recording client diagnostic telemetry. Operates strictly under TLS encryption with client certificate verification.',
    crypto: 'TLS 1.2+ encryption & SQLite ACID transaction audit logs.',
    threat: 'Network eavesdropping, traffic tampering, denial-of-service, replay attacks.',
    code: 'server/app.py & server/routes/updates.py'
  },
  verifier: {
    title: 'Client 11-Step Fail-Secure Verification Engine',
    icon: 'fa-shield-alt',
    tag: 'Client Security Core',
    tagClass: 'badge-success',
    desc: 'The independent client-side validation engine. Executes 11 discrete, non-bypassable verification steps before any code is extracted or executed. If any single step fails, the operation immediately aborts with zero modification to the system.',
    crypto: 'Pinned public key verification, freshness comparison, monotonic sequence check.',
    threat: 'Rollback attacks, stale release replay, forged keys, package tampering.',
    code: 'client/updater.py:check_and_apply_update()'
  },
  installer: {
    title: 'Safe Staged Installation & Atomic State Engine',
    icon: 'fa-tools',
    tag: 'Execution Sandbox',
    tagClass: 'badge-success',
    desc: 'Extracts validated archives into an isolated temporary staging directory, performs structural sanity checks, backs up the previous version, executes an atomic directory swap, and commits state only upon verified success.',
    crypto: 'Filesystem staging isolation, atomic rename, and automatic rollback on failure.',
    threat: 'Partial write corruption, interrupted downloads, incomplete package execution.',
    code: 'client/updater.py:stage_and_install_package()'
  }
};

function initArchitectureSvg() {
  const nodes = document.querySelectorAll('.svg-interactive-node');
  nodes.forEach(node => {
    node.addEventListener('click', () => {
      nodes.forEach(n => n.classList.remove('active-node'));
      node.classList.add('active-node');
      const compKey = node.getAttribute('data-component');
      renderArchComponent(compKey);
    });
  });
}

function renderArchComponent(key) {
  const comp = ARCH_COMPONENTS[key];
  if (!comp) return;

  const titleEl = document.getElementById('arch-title');
  const tagEl = document.getElementById('arch-tag');
  const descEl = document.getElementById('arch-desc');
  const cryptoEl = document.getElementById('arch-crypto');
  const threatEl = document.getElementById('arch-threat');
  const codeEl = document.getElementById('arch-code');

  titleEl.innerHTML = `<i class="fas ${comp.icon}" style="color: var(--accent-cyan);"></i> ${comp.title}`;
  tagEl.className = `badge ${comp.tagClass}`;
  tagEl.textContent = comp.tag;
  descEl.textContent = comp.desc;
  cryptoEl.textContent = comp.crypto;
  threatEl.textContent = comp.threat;
  codeEl.textContent = comp.code;
}

/* ====================================================================
   2. CRYPTOGRAPHY EXPLAINED
   ==================================================================== */
function switchCryptoTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));

  event.currentTarget.classList.add('active');
  const targetPane = document.getElementById(tabId);
  if (targetPane) targetPane.classList.add('active');

  if (tabId === 'tab-sha256') {
    recalcShaDemo();
  }
}

// Compute SHA-256 via WebCrypto API
async function computeSha256Hex(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function recalcShaDemo() {
  const origText = document.getElementById('sha-input-orig').value;
  const tamperText = document.getElementById('sha-input-tamper').value;

  const origHash = await computeSha256Hex(origText);
  const tamperHash = await computeSha256Hex(tamperText);

  document.getElementById('sha-digest-orig').textContent = origHash;

  // Diff highlighting
  let diffHtml = '';
  let mismatchCount = 0;
  for (let i = 0; i < tamperHash.length; i++) {
    if (tamperHash[i] !== origHash[i]) {
      diffHtml += `<span class="diff-char">${tamperHash[i]}</span>`;
      mismatchCount++;
    } else {
      diffHtml += tamperHash[i];
    }
  }

  document.getElementById('sha-digest-tamper').innerHTML = diffHtml;

  const matchBadge = document.getElementById('sha-match-badge');
  const verdictBox = document.getElementById('sha-verdict-box');

  if (origHash === tamperHash) {
    matchBadge.className = 'badge badge-success';
    matchBadge.textContent = '100% Hash Match';
    verdictBox.style.background = 'rgba(16, 185, 129, 0.15)';
    verdictBox.style.borderColor = 'var(--success)';
    verdictBox.innerHTML = `
      <strong style="color: #6ee7b7; display: flex; align-items: center; gap: 0.4rem;">
        <i class="fas fa-check-circle"></i> Step 7 Defense Verdict: INTEGRITY VERIFIED
      </strong>
      <p style="color: var(--text-main); font-size: 0.85rem; margin-top: 0.25rem;">
        Computed package hash strictly matches the signed digest. Package extraction permitted to proceed to Step 8.
      </p>
    `;
  } else {
    matchBadge.className = 'badge badge-danger';
    matchBadge.textContent = `${mismatchCount} Diff Chars`;
    verdictBox.style.background = 'rgba(239, 68, 68, 0.15)';
    verdictBox.style.borderColor = 'var(--danger)';
    verdictBox.innerHTML = `
      <strong style="color: #fca5a5; display: flex; align-items: center; gap: 0.4rem;">
        <i class="fas fa-shield-alt"></i> Step 7 Defense Verdict: REJECTED BEFORE EXECUTION
      </strong>
      <p style="color: var(--text-main); font-size: 0.85rem; margin-top: 0.25rem;">
        The Avalanche Effect ensures that changing even 1 bit changes roughly 50% of the resulting digest bits.
        The client detects this digest mismatch at <strong>Step 7</strong> and deletes the downloaded archive without extracting a single byte.
      </p>
    `;
  }
}

function tamperShaPayload() {
  const tamperInput = document.getElementById('sha-input-tamper');
  if (tamperInput.value.endsWith('!')) {
    tamperInput.value = tamperInput.value.slice(0, -1);
  } else {
    tamperInput.value += '!';
  }
  recalcShaDemo();
}

function initCryptoDemo() {
  recalcShaDemo();
}

function runEd25519Demo() {
  const selectedCase = document.querySelector('input[name="ed25519-case"]:checked').value;
  const titleEl = document.getElementById('ed25519-status-title');
  const badgeEl = document.getElementById('ed25519-status-badge');
  const descEl = document.getElementById('ed25519-status-desc');
  const boxEl = document.getElementById('ed25519-result-box');

  if (selectedCase === 'valid') {
    titleEl.innerHTML = '<i class="fas fa-check-circle" style="color: var(--success);"></i> Ed25519 Verification: SUCCESS';
    badgeEl.className = 'badge badge-success';
    badgeEl.textContent = 'Cryptographically Valid';
    descEl.textContent = "Signature matches canonical bytes evaluated against the client's pinned public key (keys/publisher_public.pem). Metadata authenticity guaranteed.";
    boxEl.style.borderColor = 'var(--success)';
  } else if (selectedCase === 'rogue') {
    titleEl.innerHTML = '<i class="fas fa-times-circle" style="color: var(--danger);"></i> Ed25519 Verification: REJECTED (Untrusted Key)';
    badgeEl.className = 'badge badge-danger';
    badgeEl.textContent = 'Signature Invalid';
    descEl.textContent = "Attacker's private key does not correspond to the client's trusted public key. Verification formula returns False. Blocked at Step 2!";
    boxEl.style.borderColor = 'var(--danger)';
  } else if (selectedCase === 'tampered') {
    titleEl.innerHTML = '<i class="fas fa-times-circle" style="color: var(--danger);"></i> Ed25519 Verification: REJECTED (Payload Modified)';
    badgeEl.className = 'badge badge-danger';
    badgeEl.textContent = 'Digest Altered';
    descEl.textContent = "Signature was generated over original metadata. Because payload fields were modified, the hash of canonical bytes does not match signature. Blocked at Step 2!";
    boxEl.style.borderColor = 'var(--danger)';
  }
}

/* ====================================================================
   3. COMPLETE UPDATE LIFECYCLE PLAYER (11 REAL STEPS)
   ==================================================================== */
const LIFECYCLE_STEPS = [
  {
    step: 1,
    title: 'Step 1: Retrieve Signed Release Metadata',
    phase: 'Phase: Discovery',
    phaseClass: 'badge-info',
    operation: 'Client sends HTTPS GET to `/api/updates/check`. Parses server response JSON containing package filename, version, sequence, expiration, package_hash, and Ed25519 signature.',
    security: 'HTTPS TLS encryption prevents passive eavesdropping. JSON schema parsing validates all mandatory metadata fields exist.',
    threat: 'Network eavesdropping, malformed response payload injection.',
    failsecure: 'Aborts with exit code 1; no temporary files created; installed version remains unchanged.',
    code: 'client/updater.py:retrieve_metadata()'
  },
  {
    step: 2,
    title: 'Step 2: Ed25519 Digital Signature Verification',
    phase: 'Phase: Authenticity',
    phaseClass: 'badge-warning',
    operation: 'Serializes metadata fields into canonical, alphabetically sorted JSON without whitespace. Verifies Base64 Ed25519 signature against trusted pinned public key (`keys/publisher_public.pem`).',
    security: 'Asymmetric elliptic curve verification (RFC 8032). Proves metadata was authored by the holder of the publisher private key and has not been altered.',
    threat: 'Rogue publisher attacks, unauthorized update injection, metadata tampering in transit.',
    failsecure: 'Aborts immediately before contacting package endpoint; logs signature verification failure.',
    code: 'client/updater.py:verify_signature()'
  },
  {
    step: 3,
    title: 'Step 3: Metadata Validation and Freshness Check',
    phase: 'Phase: Freshness',
    phaseClass: 'badge-warning',
    operation: 'Parses `expiration` ISO-8601 UTC timestamp and checks that current client system time `datetime.now(timezone.utc)` is strictly before expiration.',
    security: 'Enforces release validity window (default 30 days). Prevents adversaries from saving expired updates and re-serving them indefinitely.',
    threat: 'Expired release attacks, indefinite freeze attacks serving old vulnerable builds.',
    failsecure: 'Aborts update flow; logs release expiration alert.',
    code: 'client/updater.py:validate_metadata()'
  },
  {
    step: 4,
    title: 'Step 4: Version and Rollback Validation',
    phase: 'Phase: Anti-Rollback',
    phaseClass: 'badge-danger',
    operation: 'Reads client local state (`demoapp/state.json`). Compares candidate `version` using SemVer semantics and ensures `sequence` integer is strictly greater than currently installed sequence.',
    security: 'Monotonic sequence counter + SemVer strict ordering check.',
    threat: 'Rollback / downgrade attacks replaying older, vulnerable genuine releases.',
    failsecure: 'Rejects downgrade attempt; logs security warning with installed vs candidate version.',
    code: 'client/updater.py:validate_version_order()'
  },
  {
    step: 5,
    title: 'Step 5: Package Download to Isolated Staging',
    phase: 'Phase: Transport',
    phaseClass: 'badge-info',
    operation: 'Streams binary package from `/api/updates/download/<filename>` over HTTPS into an isolated temporary staging file with a `.tmp` extension.',
    security: 'Download streams into dedicated quarantine location without execution permissions.',
    threat: 'Partial transmission failure, connection truncation, network timeout.',
    failsecure: 'Deletes partial `.tmp` file immediately on connection error or size mismatch.',
    code: 'client/updater.py:download_package()'
  },
  {
    step: 6,
    title: 'Step 6: Calculate Package SHA-256 Digest',
    phase: 'Phase: Integrity',
    phaseClass: 'badge-cyan',
    operation: 'Reads downloaded `.tmp` file in 64 KB memory chunks through Python `hashlib.sha256()`. Generates 64-character lowercase hexadecimal hash digest.',
    security: 'Cryptographic digest computation directly over received raw file bytes on disk.',
    threat: 'Stream-level corruption, memory corruption, non-deterministic file reading.',
    failsecure: 'If file read fails, unlinks temporary artifact and halts.',
    code: 'client/updater.py:calculate_package_hash()'
  },
  {
    step: 7,
    title: 'Step 7: Verify Package Hash Match',
    phase: 'Phase: Integrity Verification',
    phaseClass: 'badge-cyan',
    operation: 'Performs constant-time comparison between calculated package SHA-256 digest and the `package_hash` in the signed metadata.',
    security: 'Second pre-image resistance of SHA-256 ensures modified package cannot match expected hash.',
    threat: 'Package tampering, man-in-the-middle binary injection, corrupt mirrors.',
    failsecure: 'Deletes downloaded ZIP immediately; logs SHA-256 mismatch; prevents extraction.',
    code: 'client/updater.py:verify_package_hash()'
  },
  {
    step: 8,
    title: 'Step 8: Package Format & Path Traversal Inspection',
    phase: 'Phase: Archive Inspection',
    phaseClass: 'badge-info',
    operation: 'Inspects ZIP archive using Python `zipfile.ZipFile`. Tests archive integrity (`testzip()`) and validates that no file entry contains directory traversal tokens (`..`, absolute paths, leading slashes).',
    security: 'Zip Slip defense: ensures every member path resolves within intended extraction directory.',
    threat: 'Zip Slip path traversal overwriting system files outside application directory.',
    failsecure: 'Halts before extracting any files; purges archive; logs directory traversal attempt.',
    code: 'client/updater.py:inspect_package_archive()'
  },
  {
    step: 9,
    title: 'Step 9: Secure Staged Installation & Health Check',
    phase: 'Phase: Staged Execution',
    phaseClass: 'badge-success',
    operation: 'Extracts files into temporary `.staging/` folder. Backs up current application directory to `.backup/`. Verifies critical files (`version.json`, `main.py`) exist in staged output.',
    security: 'Staged sandboxing and automatic rollback restoration if health check fails.',
    threat: 'Incomplete updates leaving application in broken or non-bootable state.',
    failsecure: 'Restores previous application version from `.backup/`; deletes broken staging directory.',
    code: 'client/updater.py:stage_and_install_package()'
  },
  {
    step: 10,
    title: 'Step 10: Commit Trusted Installed Version State',
    phase: 'Phase: State Commit',
    phaseClass: 'badge-success',
    operation: 'Atomically replaces `demoapp/current` with verified staged content. Atomically writes updated version, sequence, package hash, and timestamp into `demoapp/state.json`.',
    security: 'Atomic state commit ensures version state only increments after 100% verified installation.',
    threat: 'Desynchronization between disk contents and recorded version state.',
    failsecure: 'If state write fails, rolls back filesystem and preserves previous sequence number.',
    code: 'client/updater.py:commit_installed_state()'
  },
  {
    step: 11,
    title: 'Step 11: Telemetry & Final Audit Logging',
    phase: 'Phase: Audit & Telemetry',
    phaseClass: 'badge-success',
    operation: 'Sends structured installation audit report to update server (`/api/updates/report`). Logs local success message with execution timing and updated version.',
    security: 'Server records client update completion in audit log for fleet observability.',
    threat: 'Silent update failures, fleet compliance drift, unmonitored endpoints.',
    failsecure: 'Telemetry failure is non-blocking to installed application; local audit log is persisted.',
    code: 'client/updater.py:report_update_telemetry()'
  }
];

let playerState = {
  currentStep: 1,
  isPlaying: false,
  speed: 1.0,
  intervalId: null
};

function initLifecyclePlayer() {
  renderLifecycleStep(1);
}

function renderLifecycleStep(stepNum) {
  playerState.currentStep = stepNum;
  const stepData = LIFECYCLE_STEPS[stepNum - 1];

  // Update track nodes
  for (let i = 1; i <= 11; i++) {
    const node = document.getElementById(`track-step-${i}`);
    if (!node) continue;
    node.className = 'lifecycle-step-node';
    if (i === stepNum) {
      node.classList.add('active');
    } else if (i < stepNum) {
      node.classList.add('completed');
    }
  }

  // Update details box
  document.getElementById('player-step-counter').textContent = `Step ${stepNum}`;
  document.getElementById('step-title').textContent = stepData.title;
  const phaseBadge = document.getElementById('step-phase-badge');
  phaseBadge.className = `badge ${stepData.phaseClass}`;
  phaseBadge.textContent = stepData.phase;

  document.getElementById('step-operation').textContent = stepData.operation;
  document.getElementById('step-security').textContent = stepData.security;
  document.getElementById('step-threat').textContent = stepData.threat;
  document.getElementById('step-failsecure').textContent = stepData.failsecure;
  document.getElementById('step-code').textContent = stepData.code;
}

function jumpToStep(stepNum) {
  pausePlayer();
  renderLifecycleStep(stepNum);
}

function stepNext() {
  if (playerState.currentStep < 11) {
    renderLifecycleStep(playerState.currentStep + 1);
  } else {
    pausePlayer();
  }
}

function stepPrev() {
  if (playerState.currentStep > 1) {
    renderLifecycleStep(playerState.currentStep - 1);
  }
}

function stepRestart() {
  pausePlayer();
  renderLifecycleStep(1);
}

function togglePlayPause() {
  if (playerState.isPlaying) {
    pausePlayer();
  } else {
    startPlayer();
  }
}

function startPlayer() {
  playerState.isPlaying = true;
  document.getElementById('play-icon').className = 'fas fa-pause';

  if (playerState.currentStep === 11) {
    renderLifecycleStep(1);
  }

  const intervalMs = Math.round(2500 / playerState.speed);
  clearInterval(playerState.intervalId);
  playerState.intervalId = setInterval(() => {
    if (playerState.currentStep < 11) {
      stepNext();
    } else {
      pausePlayer();
    }
  }, intervalMs);
}

function pausePlayer() {
  playerState.isPlaying = false;
  document.getElementById('play-icon').className = 'fas fa-play';
  clearInterval(playerState.intervalId);
}

function setSpeed(multiplier) {
  playerState.speed = multiplier;
  document.querySelectorAll('.speed-badge').forEach(b => b.classList.remove('active'));

  if (multiplier === 0.5) document.getElementById('speed-05').classList.add('active');
  if (multiplier === 1.0) document.getElementById('speed-10').classList.add('active');
  if (multiplier === 2.0) document.getElementById('speed-20').classList.add('active');

  if (playerState.isPlaying) {
    startPlayer(); // restart interval with new speed
  }
}

/* ====================================================================
   4. ATTACK SIMULATION RUNNER (CALLS BACKEND API)
   ==================================================================== */
async function runBackendScenario(scenarioId, termId, btnId) {
  const terminal = document.getElementById(termId);
  const btn = document.getElementById(btnId);

  terminal.style.display = 'block';
  terminal.textContent = `[*] Contacting backend simulation engine for Scenario ${scenarioId}...\n[*] Executing live client updater validation...`;
  btn.disabled = true;

  try {
    const res = await fetch(`/api/client/run-scenario/${scenarioId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });

    const data = await res.json();
    let termText = `=== SCENARIO ${scenarioId} EXECUTION OUTPUT ===\n`;
    termText += `Status: ${data.success ? 'PASSED (Genuine Release Installed)' : 'ATTACK PREVENTED (Fail-Secure)'}\n`;
    if (data.blocked_step) {
      termText += `Blocked At: Step ${data.error_stage} - ${data.blocked_step}\n`;
    }
    if (data.details) {
      termText += `Details: ${data.details}\n`;
    }
    if (data.output) {
      termText += `\n--- Standard Output Logs ---\n${data.output}`;
    }

    terminal.textContent = termText;
    terminal.scrollTop = terminal.scrollHeight;
  } catch (err) {
    terminal.textContent = `[!] Error communicating with backend server: ${err.message}`;
  } finally {
    btn.disabled = false;
  }
}

/* ====================================================================
   5. SUBNAV SCROLL SPY
   ==================================================================== */
function initSubnavScrollSpy() {
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.subnav-link');

  window.addEventListener('scroll', () => {
    let current = '';
    sections.forEach(section => {
      const sectionTop = section.offsetTop - 160;
      if (window.pageYOffset >= sectionTop) {
        current = section.getAttribute('id');
      }
    });

    navLinks.forEach(link => {
      link.classList.remove('active');
      if (link.getAttribute('href') === `#${current}`) {
        link.classList.add('active');
      }
    });
  });
}

