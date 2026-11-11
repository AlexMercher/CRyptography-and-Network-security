let currentUser = null;

async function checkAuth() {
  try {
    const res = await fetch("/api/auth/me");
    const data = await res.json();
    const badge = document.getElementById("session-user-badge");
    const container = document.getElementById("auth-action-container");

    if (data.authenticated) {
      currentUser = data.user;
      badge.className = "badge badge-success";
      badge.innerText = `Active: ${data.user}`;
      container.innerHTML = `<button class="btn btn-secondary" onclick="handleLogout()"><i class="fa-solid fa-right-from-bracket"></i> Logout</button>`;
      loadStats();
      loadReleases();
      loadLogs();
    } else {
      currentUser = null;
      badge.className = "badge badge-warning";
      badge.innerText = "Not Authenticated";
      container.innerHTML = `<button class="btn btn-secondary" onclick="openLoginModal()"><i class="fa-solid fa-right-to-bracket"></i> Login as Admin</button>`;
    }
  } catch (err) {
    console.error("Auth check error:", err);
  }
}

function openLoginModal() {
  const modal = document.getElementById("login-modal");
  modal.style.display = "flex";
}

function closeLoginModal() {
  const modal = document.getElementById("login-modal");
  modal.style.display = "none";
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;
  const errBox = document.getElementById("login-error");

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (res.ok) {
      closeLoginModal();
      checkAuth();
    } else {
      errBox.style.display = "block";
      errBox.innerText = data.error || "Authentication failed";
    }
  } catch (err) {
    errBox.style.display = "block";
    errBox.innerText = "Network error during login";
  }
}

async function handleLogout() {
  await fetch("/api/auth/logout", { method: "POST" });
  checkAuth();
}

async function loadStats() {
  try {
    const res = await fetch("/api/admin/stats");
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById("stat-releases").innerText = data.published_releases;
    document.getElementById("stat-clients").innerText = data.active_clients;
    document.getElementById("stat-security").innerText = data.security_events;
    document.getElementById("stat-installs").innerText = data.successful_installs;
  } catch (err) {
    console.error("Stats load error:", err);
  }
}

async function handleUpload(e) {
  e.preventDefault();
  const fileInput = document.getElementById("package-file");
  if (!fileInput.files.length) return;

  const formData = new FormData();
  formData.append("package", fileInput.files[0]);

  try {
    const res = await fetch("/api/admin/upload", {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    if (res.ok) {
      document.getElementById("upload-result").style.display = "block";
      document.getElementById("res-filename").innerText = data.filename;
      document.getElementById("res-hash").innerText = data.sha256;
      document.getElementById("res-size").innerText = data.size;

      document.getElementById("pub-filename").value = data.filename;
      document.getElementById("pub-hash").value = data.sha256;
      document.getElementById("pub-size").value = data.size;

      // Extract version guess from filename e.g. demoapp-1.1.0.zip
      const match = data.filename.match(/(\d+\.\d+\.\d+)/);
      if (match) {
        document.getElementById("pub-version").value = match[1];
      }
    } else {
      alert("Upload failed: " + (data.error || "Unknown error"));
    }
  } catch (err) {
    alert("Upload error: " + err);
  }
}

async function handlePublish(e) {
  e.preventDefault();
  const payload = {
    software_id: document.getElementById("pub-software-id").value,
    version: document.getElementById("pub-version").value,
    release_sequence: parseInt(document.getElementById("pub-sequence").value),
    package_filename: document.getElementById("pub-filename").value,
    package_hash: document.getElementById("pub-hash").value,
    package_size: parseInt(document.getElementById("pub-size").value),
    description: document.getElementById("pub-desc").value,
    expiration_days: parseInt(document.getElementById("pub-exp-days").value)
  };

  if (!payload.package_filename || !payload.package_hash) {
    alert("Please upload a package first to compute SHA-256 hash.");
    return;
  }

  try {
    const res = await fetch("/api/admin/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.ok) {
      alert(data.message);
      loadReleases();
      loadStats();
      loadLogs();
    } else {
      alert("Publish failed: " + (data.error || "Unknown error"));
    }
  } catch (err) {
    alert("Publish network error: " + err);
  }
}

async function quickPublish(version, sequence, desc) {
  const pkgMap = {
    "1.1.0": { filename: "demoapp-1.1.0.zip", size: 1268 },
    "1.2.0": { filename: "demoapp-1.2.0.zip", size: 1440 }
  };
  const pkg = pkgMap[version];
  if (!pkg) return;

  // Compute or get hash
  const payload = {
    software_id: "demoapp",
    version: version,
    release_sequence: sequence,
    package_filename: pkg.filename,
    package_hash: "", // Server will auto compute or lookup
    package_size: pkg.size,
    description: desc,
    expiration_days: 365
  };

  // Upload or publish directly
  try {
    // If not hashed yet, upload / read
    const checkRes = await fetch(`/api/updates/download/${pkg.filename}`);
    if (checkRes.ok) {
      const blob = await checkRes.blob();
      const buf = await blob.arrayBuffer();
      // SHA-256 via Web Crypto
      const hashBuf = await crypto.subtle.digest("SHA-256", buf);
      const hashArray = Array.from(new Uint8Array(hashBuf));
      payload.package_hash = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
      payload.package_size = blob.size;

      const res = await fetch("/api/admin/publish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        alert(data.message);
        loadReleases();
        loadStats();
        loadLogs();
      } else {
        alert("Publish failed: " + (data.error || "Unknown error"));
      }
    }
  } catch (err) {
    alert("Quick publish error: " + err);
  }
}

async function loadReleases() {
  try {
    const res = await fetch("/api/admin/releases");
    if (!res.ok) return;
    const data = await res.json();
    const tbody = document.querySelector("#releases-table tbody");
    tbody.innerHTML = "";

    if (!data.releases || data.releases.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted);">No software releases published yet.</td></tr>`;
      return;
    }

    data.releases.forEach(r => {
      const tr = document.createElement("tr");
      const shortHash = r.package_hash ? r.package_hash.substring(0, 12) + "..." : "N/A";
      const shortSig = r.signature ? r.signature.substring(0, 16) + "..." : "N/A";
      const statusBadge = r.status === "published"
        ? `<span class="badge badge-success">Published</span>`
        : `<span class="badge badge-danger">Revoked</span>`;

      tr.innerHTML = `
        <td>${r.id}</td>
        <td><strong>${r.software_id}</strong></td>
        <td><code>v${r.version}</code></td>
        <td>${r.release_sequence}</td>
        <td><code title="${r.package_hash}">${shortHash}</code></td>
        <td><code title="${r.signature}">${shortSig}</code></td>
        <td>${new Date(r.published_at).toLocaleString()}</td>
        <td>${statusBadge}</td>
        <td>
          ${r.status === "published" ? `<button class="btn btn-danger" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="revokeRelease(${r.id})">Revoke</button>` : "-"}
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Releases load error:", err);
  }
}

async function revokeRelease(releaseId) {
  if (!confirm(`Are you sure you want to revoke Release ID ${releaseId}?`)) return;
  try {
    const res = await fetch(`/api/admin/revoke/${releaseId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "Revoked from admin dashboard" })
    });
    if (res.ok) {
      loadReleases();
      loadStats();
      loadLogs();
    }
  } catch (err) {
    alert("Revoke failed: " + err);
  }
}

async function loadLogs() {
  try {
    const res = await fetch("/api/admin/logs?limit=50");
    if (!res.ok) return;
    const data = await res.json();

    const secTerm = document.getElementById("security-log-terminal");
    secTerm.innerHTML = "";
    if (data.security_events.length === 0) {
      secTerm.innerHTML = `<div class="terminal-line info">[SYS] No security incidents recorded yet.</div>`;
    } else {
      data.security_events.forEach(e => {
        const line = document.createElement("div");
        line.className = `terminal-line ${e.result === "BLOCKED" ? "error" : "success"}`;
        line.innerText = `[${e.timestamp.substring(11, 19)}] [${e.event_type}] [${e.result}] ${e.description}`;
        secTerm.appendChild(line);
      });
    }

    const actTerm = document.getElementById("activity-log-terminal");
    actTerm.innerHTML = "";
    if (data.update_activity.length === 0) {
      actTerm.innerHTML = `<div class="terminal-line info">[SYS] No client update activity recorded yet.</div>`;
    } else {
      data.update_activity.forEach(a => {
        const line = document.createElement("div");
        line.className = `terminal-line ${a.verification_result === "SUCCESS" || a.installation_result === "SUCCESS" ? "success" : "info"}`;
        line.innerText = `[${a.timestamp.substring(11, 19)}] [${a.client_id}] [${a.action}] Verif: ${a.verification_result} | Install: ${a.installation_result} (${a.details})`;
        actTerm.appendChild(line);
      });
    }
  } catch (err) {
    console.error("Logs load error:", err);
  }
}

// Polling and init
document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
  setInterval(() => {
    if (currentUser) {
      loadStats();
      loadLogs();
    }
  }, 4000);
});

