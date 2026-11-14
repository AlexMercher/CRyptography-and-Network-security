let latestCheckData = null;
let currentClientState = null;
let isUpdating = false;

async function loadClientState() {
  try {
    const res = await fetch("/api/client/status");
    if (!res.ok) return;
    const state = await res.json();
    currentClientState = state;
    document.getElementById("client-installed-version").innerText = `DemoApp v${state.installed_version}`;
    document.getElementById("client-installed-seq").innerText = `Seq: ${state.release_sequence}`;
    
    // Update active comparison card
    document.getElementById("comp-installed-title").innerText = `DemoApp v${state.installed_version}`;
    document.getElementById("comp-installed-seq").innerText = `Monotonic Sequence: ${state.release_sequence}`;
    document.getElementById("comp-installed-status").innerText = `Status: ${state.status} (Verified)`;

    logConsole(`Current local installed version: DemoApp v${state.installed_version} (Seq: ${state.release_sequence})`, "info");
    loadClientHistory();
    loadReleaseCatalog();
  } catch (err) {
    console.error("Client state load error:", err);
  }
}

async function resetClientBaseline() {
  if (isUpdating) {
    logConsole("Cannot reset baseline while an update is actively in progress.", "warn");
    return;
  }
  try {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const headers = { "Content-Type": "application/json" };
    if (csrfMeta && csrfMeta.content) {
      headers["X-CSRF-Token"] = csrfMeta.content;
    }
    const res = await fetch("/api/client/reset", { 
      method: "POST",
      headers: headers
    });
    const data = await res.json();
    if (res.ok) {
      logConsole(data.message, "success");
      hideFailureExplanation();
      resetPipelineUI();
      await loadClientState();
      await refreshUpdateAvailability();
    } else {
      logConsole(`Reset rejected: ${data.error || "Administrator authentication required."} (HTTP ${res.status})`, "error");
    }
  } catch (err) {
    logConsole("Reset error: " + err, "error");
  }
}

async function refreshUpdateAvailability() {
  try {
    const stateRes = await fetch("/api/client/status");
    const state = await stateRes.json();
    currentClientState = state;

    const res = await fetch(`/api/updates/check?software_id=demoapp&client_id=client-alpha&current_version=${state.installed_version}`);
    const data = await res.json();

    const badge = document.getElementById("update-badge");
    const details = document.getElementById("update-details");
    const btnInstall = document.getElementById("btn-install-pipeline");

    if (data.update_available) {
      latestCheckData = data;
      badge.className = "badge badge-success";
      badge.innerText = "New Update Available";

      document.getElementById("update-message").innerText = "A valid signed software update is ready for installation.";
      details.style.display = "block";
      document.getElementById("avail-version").innerText = `v${data.metadata.version}`;
      document.getElementById("avail-seq").innerText = data.metadata.release_sequence;
      document.getElementById("avail-hash").innerText = data.metadata.package_hash ? data.metadata.package_hash.substring(0, 16) + "..." : "N/A";
      document.getElementById("avail-exp").innerText = new Date(data.metadata.expiration_timestamp).toLocaleDateString();

      btnInstall.removeAttribute("disabled");
      updateVersionComparison(state, data.metadata);
      logConsole(`Update found: DemoApp v${data.metadata.version} (Seq ${data.metadata.release_sequence}). Signed digest: ${data.metadata.package_hash}`, "info");
    } else {
      latestCheckData = null;
      badge.className = "badge badge-info";
      badge.innerText = "Up to Date";
      document.getElementById("update-message").innerText = data.message || "No updates available.";
      details.style.display = "none";
      btnInstall.setAttribute("disabled", "true");
      updateVersionComparison(state, null);
      logConsole(data.message || "System is already running the latest version.", "warn");
    }
  } catch (err) {
    logConsole("Update availability check failed: " + err, "error");
  }
}

async function checkUpdates() {
  if (isUpdating) {
    logConsole("Update check postponed: an installation pipeline is currently active.", "warn");
    return;
  }
  hideFailureExplanation();
  logConsole("Querying update server for available releases...", "info");
  await refreshUpdateAvailability();
}

function updateVersionComparison(installedState, availMeta) {
  const compBadge = document.getElementById("comparison-badge");
  const availPill = document.getElementById("comp-avail-pill");
  const availTitle = document.getElementById("comp-avail-title");
  const availSeq = document.getElementById("comp-avail-seq");
  const availDesc = document.getElementById("comp-avail-desc");
  const availCrypto = document.getElementById("comp-avail-crypto");

  if (!availMeta) {
    compBadge.className = "badge badge-success";
    compBadge.innerText = "System Up-to-Date";
    availPill.className = "badge badge-success";
    availPill.innerText = "Up-to-Date";
    availTitle.innerText = `DemoApp v${installedState.installed_version}`;
    availSeq.innerText = `Monotonic Sequence: ${installedState.release_sequence}`;
    availDesc.innerText = "No higher release sequence found on the update server.";
    availCrypto.innerText = "Current installed package is at the highest authorized sequence.";
    return;
  }

  const isNewer = availMeta.release_sequence > installedState.release_sequence;
  if (isNewer) {
    compBadge.className = "badge badge-success";
    compBadge.innerText = `Upgrade Ready (+${availMeta.release_sequence - installedState.release_sequence} sequence)`;
    availPill.className = "badge badge-success";
    availPill.innerText = "Upgrade Candidate";
    availTitle.innerText = `DemoApp v${availMeta.version}`;
    availSeq.innerText = `Candidate Sequence: ${availMeta.release_sequence} (Higher)`;
    availDesc.innerText = availMeta.description || "Contains security updates and performance diagnostics.";
    availCrypto.innerHTML = `<strong>Package:</strong> ${availMeta.package_filename} (${availMeta.package_size} bytes)<br><strong>Signed SHA-256:</strong> <code>${availMeta.package_hash}</code>`;
  } else {
    compBadge.className = "badge badge-danger";
    compBadge.innerText = "Rollback / Stale Candidate";
    availPill.className = "badge badge-danger";
    availPill.innerText = "Incompatible";
    availTitle.innerText = `DemoApp v${availMeta.version}`;
    availSeq.innerText = `Candidate Sequence: ${availMeta.release_sequence} (Lower or Equal)`;
    availDesc.innerText = "Candidate is not strictly newer than current installed state. Installation will be blocked.";
    availCrypto.innerText = `Signed SHA-256: ${availMeta.package_hash}`;
  }
}

function resetPipelineUI() {
  for (let i = 1; i <= 11; i++) {
    const el = document.getElementById(`step-${i}`);
    if (el) {
      el.className = "step-card pending";
      const tag = el.querySelector(".status-tag");
      if (tag) {
        tag.className = "badge badge-info status-tag";
        tag.innerText = "Pending";
      }
      const tech = document.getElementById(`step-tech-${i}`);
      if (tech) {
        tech.style.display = "none";
        tech.innerText = "";
      }
    }
  }
  const mainBadge = document.getElementById("pipeline-status-badge");
  mainBadge.className = "badge badge-info";
  mainBadge.innerText = "Standby";
}

function updatePipelineStep(stepNum, statusOrSuccess, message) {
  const el = document.getElementById(`step-${stepNum}`);
  if (!el) return;

  const tag = el.querySelector(".status-tag");
  const tech = document.getElementById(`step-tech-${stepNum}`);

  let status = "PENDING";
  if (statusOrSuccess === true || statusOrSuccess === "PASSED") {
    status = "PASSED";
  } else if (statusOrSuccess === "RUNNING") {
    status = "RUNNING";
  } else if (statusOrSuccess === "SKIPPED") {
    status = "SKIPPED";
  } else if (statusOrSuccess === false || statusOrSuccess === "FAILED") {
    status = "FAILED";
  }

  if (status === "PASSED") {
    el.className = "step-card success";
    if (tag) {
      tag.className = "badge badge-success status-tag";
      tag.innerText = "PASSED";
    }
    if (tech) {
      tech.style.display = "block";
      tech.innerHTML = `<i class="fa-solid fa-circle-check" style="color: var(--success);"></i> ${message}`;
    }
    logConsole(`[Step ${stepNum}] PASSED: ${message}`, "success");
  } else if (status === "RUNNING") {
    el.className = "step-card running";
    if (tag) {
      tag.className = "badge badge-warning status-tag";
      tag.innerText = "RUNNING";
    }
    if (tech) {
      tech.style.display = "block";
      tech.innerHTML = `<i class="fa-solid fa-gear fa-spin" style="color: var(--warning);"></i> ${message || "Executing verification step..."}`;
    }
  } else if (status === "SKIPPED") {
    el.className = "step-card skipped";
    if (tag) {
      tag.className = "badge badge-secondary status-tag";
      tag.innerText = "SKIPPED";
    }
    if (tech) {
      tech.style.display = "block";
      tech.innerHTML = `<i class="fa-solid fa-forward-step" style="color: var(--text-muted);"></i> ${message}`;
    }
  } else if (status === "FAILED") {
    el.className = "step-card failure";
    if (tag) {
      tag.className = "badge badge-danger status-tag";
      tag.innerText = "BLOCKED";
    }
    if (tech) {
      tech.style.display = "block";
      tech.innerHTML = `<i class="fa-solid fa-triangle-exclamation" style="color: var(--danger);"></i> ${message}`;
    }
    logConsole(`[Step ${stepNum}] BLOCKED: ${message}`, "error");
  }
}

function showFailureExplanation(errorStage, message) {
  const card = document.getElementById("failure-explanation-card");
  const badge = document.getElementById("fail-stage-badge");
  const whatEl = document.getElementById("fail-what-happened");
  const whyEl = document.getElementById("fail-why-blocked");
  const principleEl = document.getElementById("fail-security-principle");

  badge.innerText = `Pipeline Halted at Step ${errorStage}`;
  whatEl.innerText = message;

  const explanations = {
    1: {
      why: "The client could not retrieve legitimate release metadata from the server or transport was interrupted.",
      principle: "Transport Integrity & Server Availability (SR03)"
    },
    2: {
      why: "The digital signature does not match the canonical metadata when verified against the provisioned publisher public key. The metadata was altered after signing or produced by an unauthorized rogue key.",
      principle: "Publisher Authenticity & Non-Repudiation (SR02 / Ed25519)"
    },
    3: {
      why: "The release expiration timestamp is in the past, or required metadata fields are missing/corrupted.",
      principle: "Metadata Freshness & Replay Attack Prevention (SR06)"
    },
    4: {
      why: "The candidate software version or sequence number is older than or equal to the currently installed version. An adversary attempted a rollback attack.",
      principle: "Rollback Attack Prevention & Monotonic Sequence Invariance (SR05)"
    },
    5: {
      why: "The package file download failed, was artificially interrupted, or did not match the expected byte size.",
      principle: "Fail-Secure Package Transmission (SR08)"
    },
    6: {
      why: "An error occurred while computing the SHA-256 digest over the downloaded archive.",
      principle: "Data Integrity Verification (SR01)"
    },
    7: {
      why: "The SHA-256 hash calculated over the downloaded package does not match the digest signed by the publisher. The archive was modified, corrupted, or tampered with.",
      principle: "End-to-End Package Integrity (SR01 / SHA-256)"
    },
    8: {
      why: "The archive contains malicious relative paths ('../') or absolute path traversals (Zip-Slip vulnerability).",
      principle: "Safe Archive Extraction & Directory Boundary Containment (SR09)"
    },
    9: {
      why: "Activation or post-installation verification failed. The installation engine immediately aborted and restored the previous working backup.",
      principle: "Atomic Staging & Safe Recovery (SR10)"
    }
  };

  const exp = explanations[errorStage] || {
    why: "A cryptographic or security verification requirement was violated.",
    principle: "Zero-Trust Fail-Secure Principle"
  };

  whyEl.innerText = exp.why;
  principleEl.innerText = exp.principle;
  card.style.display = "block";
}

function hideFailureExplanation() {
  const card = document.getElementById("failure-explanation-card");
  if (card) card.style.display = "none";
}

async function executeStandardUpdate() {
  if (isUpdating) {
    logConsole("An update pipeline execution is already in progress. Please wait...", "warn");
    return;
  }
  isUpdating = true;
  const btnInstall = document.getElementById("btn-install-pipeline");
  if (btnInstall) btnInstall.setAttribute("disabled", "true");

  hideFailureExplanation();
  resetPipelineUI();
  updatePipelineStep(1, "RUNNING", "Querying server and retrieving signed metadata...");
  logConsole("Starting mandatory 11-step update pipeline...", "info");
  const mainBadge = document.getElementById("pipeline-status-badge");
  mainBadge.className = "badge badge-warning";
  mainBadge.innerText = "Verifying Pipeline...";

  try {
    const res = await fetch("/api/client/run-update", { method: "POST" });
    const result = await res.json();
    await processPipelineResult(result);
  } catch (err) {
    logConsole("Pipeline execution error: " + err, "error");
  } finally {
    isUpdating = false;
  }
}

async function runAttackScenario(scenarioNum) {
  if (isUpdating) {
    logConsole("A pipeline execution is already in progress. Please wait...", "warn");
    return;
  }
  isUpdating = true;
  const btnInstall = document.getElementById("btn-install-pipeline");
  if (btnInstall) btnInstall.setAttribute("disabled", "true");

  resetPipelineUI();
  hideFailureExplanation();
  updatePipelineStep(1, "RUNNING", "Initializing simulation payload...");
  logConsole(`========== TRIGGERING DEMO SCENARIO ${scenarioNum} ==========`, "warn");
  const mainBadge = document.getElementById("pipeline-status-badge");
  mainBadge.className = "badge badge-warning";
  mainBadge.innerText = "Simulating Scenario...";

  try {
    const res = await fetch(`/api/client/run-scenario/${scenarioNum}`, { method: "POST" });
    const data = await res.json();

    logConsole(`Scenario: ${data.title}`, "info");
    logConsole(`Expected: ${data.expected}`, "info");
    await processPipelineResult(data.result);
  } catch (err) {
    logConsole("Scenario error: " + err, "error");
  } finally {
    isUpdating = false;
  }
}

async function processPipelineResult(result) {
  const mainBadge = document.getElementById("pipeline-status-badge");

  if (result.steps && result.steps.length > 0) {
    result.steps.forEach(s => {
      updatePipelineStep(s.step, s.status || (s.success ? "PASSED" : "FAILED"), s.message);
    });
  }

  if (result.success) {
    mainBadge.className = "badge badge-success";
    mainBadge.innerHTML = `<i class="fa-solid fa-circle-check"></i> Update Complete (11/11 Passed)`;
    logConsole(`SUCCESS: ${result.message}`, "success");
    hideFailureExplanation();
    await loadClientState();
    await refreshUpdateAvailability();
  } else {
    mainBadge.className = "badge badge-danger";
    mainBadge.innerHTML = `<i class="fa-solid fa-ban"></i> Blocked at Step ${result.error_stage}`;
    logConsole(`UPDATE ABORTED: Security verification failed at step ${result.error_stage}: ${result.message}`, "error");
    showFailureExplanation(result.error_stage, result.message);
    await loadClientHistory();
    await refreshUpdateAvailability();
  }
}

async function loadClientHistory() {
  try {
    const res = await fetch("/api/client/history?client_id=client-alpha&limit=15");
    if (!res.ok) return;
    const data = await res.json();
    const tbody = document.querySelector("#client-history-table tbody");
    tbody.innerHTML = "";

    if (!data.history || data.history.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No activity history recorded yet.</td></tr>`;
      return;
    }

    data.history.forEach(h => {
      const tr = document.createElement("tr");
      const timeStr = h.timestamp ? new Date(h.timestamp).toLocaleTimeString() : "--";
      const isOk = h.verification_result === "SUCCESS" || h.verification_result === "CHECKED" || h.installation_result === "SUCCESS";
      const badgeClass = isOk ? "badge-success" : (h.verification_result.includes("FAILED") || h.verification_result.includes("BLOCKED") || h.verification_result.includes("MISMATCH") || h.verification_result.includes("INVALID") ? "badge-danger" : "badge-info");

      tr.innerHTML = `
        <td><code style="font-size: 0.75rem;">${timeStr}</code></td>
        <td><strong>${h.action}</strong></td>
        <td><span class="badge ${badgeClass}">${h.verification_result}</span></td>
        <td><span class="badge ${h.installation_result === 'SUCCESS' ? 'badge-success' : 'badge-info'}">${h.installation_result}</span></td>
        <td style="font-size: 0.8rem; color: #cbd5e1;">${h.details || '-'}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("History load error:", err);
  }
}

async function exportDiagnosticReport(format) {
  try {
    const res = await fetch("/api/client/diagnostic-report");
    if (!res.ok) return;
    const data = await res.json();

    let content = "";
    let mime = "application/json";
    let filename = `client_diagnostic_report_${Date.now()}.json`;

    if (format === "json") {
      content = JSON.stringify(data, null, 2);
    } else {
      mime = "text/markdown";
      filename = `client_diagnostic_report_${Date.now()}.md`;
      content = `# Client Diagnostic Report\n\n**Generated:** ${data.report_generated_utc}\n**Client ID:** ${data.client_id}\n\n## Client State\n- Installed Version: ${data.client_state.installed_version}\n- Sequence: ${data.client_state.release_sequence}\n- Status: ${data.client_state.status}\n\n## Cryptographic Anchors\n- Publisher Public Key: ${data.cryptographic_anchors.publisher_public_key_present ? "PRESENT" : "MISSING"}\n- Root CA Cert: ${data.cryptographic_anchors.root_ca_certificate_present ? "PRESENT" : "MISSING"}\n`;
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    logConsole(`Exported diagnostic report: ${filename}`, "info");
  } catch (err) {
    alert("Export failed: " + err);
  }
}

function logConsole(msg, type = "info") {
  const con = document.getElementById("client-console");
  const line = document.createElement("div");
  line.className = `terminal-line ${type}`;
  const time = new Date().toLocaleTimeString();
  line.innerText = `[${time}] ${msg}`;
  con.appendChild(line);
  con.scrollTop = con.scrollHeight;
}

function clearConsole() {
  document.getElementById("client-console").innerHTML = `<div class="terminal-line info">[CLIENT] Console cleared.</div>`;
}

async function loadReleaseCatalog() {
  try {
    const res = await fetch("/api/updates/catalog?software_id=demoapp");
    if (!res.ok) return;
    const data = await res.json();
    const tbody = document.querySelector("#client-catalog-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!data.catalog || data.catalog.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No software releases published yet.</td></tr>`;
      return;
    }

    const installedSeq = currentClientState ? currentClientState.release_sequence : 1;
    const installedVer = currentClientState ? currentClientState.installed_version : "1.0.0";

    data.catalog.forEach(r => {
      const tr = document.createElement("tr");
      const shortHash = r.package_hash ? r.package_hash.substring(0, 12) + "..." : "N/A";
      const statusBadge = r.status === "published"
        ? `<span class="badge badge-success"><i class="fa-solid fa-check"></i> Published</span>`
        : `<span class="badge badge-danger"><i class="fa-solid fa-ban"></i> Revoked</span>`;

      let eligBadge = "";
      if (r.version === installedVer) {
        eligBadge = `<span class="badge badge-info"><i class="fa-solid fa-circle-check"></i> Currently Installed</span>`;
      } else if (r.status === "revoked") {
        eligBadge = `<span class="badge badge-danger"><i class="fa-solid fa-circle-xmark"></i> Ineligible (Revoked)</span>`;
      } else if (r.release_sequence > installedSeq) {
        eligBadge = `<span class="badge badge-success"><i class="fa-solid fa-arrow-up"></i> Eligible Upgrade</span>`;
      } else {
        eligBadge = `<span class="badge badge-warning"><i class="fa-solid fa-ban"></i> Ineligible (Rollback)</span>`;
      }

      tr.innerHTML = `
        <td><strong>${r.software_id}</strong></td>
        <td><code>v${r.version}</code></td>
        <td><span class="badge badge-info">Seq: ${r.release_sequence}</span></td>
        <td>${r.package_filename} (${r.package_size} B)</td>
        <td><code title="${r.package_hash}">${shortHash}</code></td>
        <td>${statusBadge}</td>
        <td>${eligBadge}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Catalog load error:", err);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadClientState();
  checkUpdates();
});
