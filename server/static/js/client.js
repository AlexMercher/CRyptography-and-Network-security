let latestCheckData = null;

async function loadClientState() {
  try {
    const res = await fetch("/api/client/status");
    if (!res.ok) return;
    const state = await res.json();
    document.getElementById("client-installed-version").innerText = `DemoApp v${state.installed_version}`;
    document.getElementById("client-installed-seq").innerText = `Seq: ${state.release_sequence}`;
    logConsole(`Current local installed version: DemoApp v${state.installed_version} (Seq: ${state.release_sequence})`, "info");
  } catch (err) {
    console.error("Client state load error:", err);
  }
}

async function resetClientBaseline() {
  try {
    const res = await fetch("/api/client/reset", { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      logConsole(data.message, "success");
      loadClientState();
      resetPipelineUI();
    }
  } catch (err) {
    logConsole("Reset error: " + err, "error");
  }
}

async function checkUpdates() {
  resetPipelineUI();
  logConsole("Querying update server for available releases...", "info");
  try {
    const stateRes = await fetch("/api/client/status");
    const state = await stateRes.json();

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
      logConsole(`Update found: DemoApp v${data.metadata.version} (Seq ${data.metadata.release_sequence}). Signed digest: ${data.metadata.package_hash}`, "info");
    } else {
      latestCheckData = null;
      badge.className = "badge badge-info";
      badge.innerText = "Up to Date";
      document.getElementById("update-message").innerText = data.message || "No updates available.";
      details.style.display = "none";
      btnInstall.setAttribute("disabled", "true");
      logConsole(data.message || "System is already running the latest version.", "warn");
    }
  } catch (err) {
    logConsole("Update check failed: " + err, "error");
  }
}

function resetPipelineUI() {
  for (let i = 1; i <= 10; i++) {
    const el = document.getElementById(`step-${i}`);
    if (el) {
      el.className = "step-card pending";
      const tag = el.querySelector(".status-tag");
      if (tag) {
        tag.className = "badge badge-info status-tag";
        tag.innerText = "Pending";
      }
    }
  }
  const mainBadge = document.getElementById("pipeline-status-badge");
  mainBadge.className = "badge badge-info";
  mainBadge.innerText = "Standby";
}

function updatePipelineStep(stepNum, success, message) {
  const el = document.getElementById(`step-${stepNum}`);
  if (!el) return;

  const tag = el.querySelector(".status-tag");
  if (success) {
    el.className = "step-card success";
    if (tag) {
      tag.className = "badge badge-success status-tag";
      tag.innerText = "PASSED";
    }
    logConsole(`[Step ${stepNum}] PASSED: ${message}`, "success");
  } else {
    el.className = "step-card failure";
    if (tag) {
      tag.className = "badge badge-danger status-tag";
      tag.innerText = "BLOCKED";
    }
    logConsole(`[Step ${stepNum}] BLOCKED: ${message}`, "error");
  }
}

async function executeStandardUpdate() {
  logConsole("Starting mandatory 11-step update pipeline...", "info");
  const mainBadge = document.getElementById("pipeline-status-badge");
  mainBadge.className = "badge badge-warning";
  mainBadge.innerText = "Verifying...";

  try {
    const res = await fetch("/api/client/run-update", { method: "POST" });
    const result = await res.json();
    processPipelineResult(result);
  } catch (err) {
    logConsole("Pipeline execution error: " + err, "error");
  }
}

async function runAttackScenario(scenarioNum) {
  resetPipelineUI();
  logConsole(`========== TRIGGERING DEMO SCENARIO ${scenarioNum} ==========`, "warn");
  const mainBadge = document.getElementById("pipeline-status-badge");
  mainBadge.className = "badge badge-warning";
  mainBadge.innerText = "Simulating Scenario...";

  try {
    const res = await fetch(`/api/client/run-scenario/${scenarioNum}`, { method: "POST" });
    const data = await res.json();

    logConsole(`Scenario: ${data.title}`, "info");
    logConsole(`Expected: ${data.expected}`, "info");
    processPipelineResult(data.result);
  } catch (err) {
    logConsole("Scenario error: " + err, "error");
  }
}

function processPipelineResult(result) {
  const mainBadge = document.getElementById("pipeline-status-badge");

  if (result.steps && result.steps.length > 0) {
    result.steps.forEach(s => {
      updatePipelineStep(s.step, s.success, s.message);
    });
  }

  if (result.success) {
    mainBadge.className = "badge badge-success";
    mainBadge.innerText = "Update Complete";
    logConsole(`SUCCESS: ${result.message}`, "success");
    loadClientState();
  } else {
    mainBadge.className = "badge badge-danger";
    mainBadge.innerText = `Rejected (Step ${result.error_stage})`;
    logConsole(`UPDATE ABORTED: Security verification failed at step ${result.error_stage}: ${result.message}`, "error");
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

document.addEventListener("DOMContentLoaded", () => {
  loadClientState();
  checkUpdates();
});

