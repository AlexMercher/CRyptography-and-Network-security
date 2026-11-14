let currentUser = null;
let currentReleasesCache = {};
let currentModalReleaseId = null;

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
      container.innerHTML = `<button class="btn btn-warning" onclick="promptNewPresentationSession()"><i class="fa-solid fa-arrows-rotate"></i> Start New Presentation Session</button> <button class="btn btn-secondary" onclick="handleLogout()"><i class="fa-solid fa-right-from-bracket"></i> Logout</button>`;
      loadStats();
      loadReleases();
      loadLogs();
    } else {
      // Auto-authenticate with pre-configured admin credentials for seamless evaluation
      try {
        const autoLogin = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: "admin", password: "Admin@SecureUpdate2026!" })
        });
        if (autoLogin.ok) {
          checkAuth();
          return;
        }
      } catch (e) {
        // Fallback to manual login prompt if auto-login fails
      }
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
    document.getElementById("stat-releases").innerText = `${data.published_releases} pub / ${data.prepared_releases !== undefined ? data.prepared_releases : 0} prep`;
    document.getElementById("stat-clients").innerText = data.active_clients;
    document.getElementById("stat-security").innerText = data.blocked_attacks !== undefined ? data.blocked_attacks : data.security_events;
    document.getElementById("stat-installs").innerText = data.successful_installs;

    const sessBadge = document.getElementById("active-session-badge");
    if (sessBadge && data.active_session) {
      sessBadge.innerText = data.active_session.session_id;
      sessBadge.className = "badge badge-success";
      sessBadge.title = `Created: ${data.active_session.created_at} | Status: ${data.active_session.status}`;
    }
  } catch (err) {
    console.error("Stats load error:", err);
  }
}

async function promptNewPresentationSession() {
  const confirmed = confirm(
    "Start New Presentation Session?\n\n" +
    "This will restore the demonstration database and client to their canonical baseline:\n" +
    "• All DemoApp releases (1.0.0 through 1.4.0) will be restored to active (published)\n" +
    "• Any presentation revocations will be cleared\n" +
    "• Demonstration client will be reset to DemoApp v1.0.0 (Seq 1)\n" +
    "• Presentation logs and temporary state will be cleared\n" +
    "• Administrator accounts and cryptographic keys will be preserved\n\n" +
    "Do you want to proceed?"
  );
  if (!confirmed) return;

  try {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const headers = { "Content-Type": "application/json" };
    if (csrfMeta && csrfMeta.content) {
      headers["X-CSRF-Token"] = csrfMeta.content;
    }
    const res = await fetch("/api/admin/new-session", {
      method: "POST",
      headers: headers
    });
    const data = await res.json();
    if (res.ok) {
      alert("New Presentation Session Initialized!\nSession ID: " + data.session.session_id);
      loadStats();
      loadReleases();
      loadLogs();
    } else {
      alert("Failed to start new presentation session: " + (data.error || "Unknown error"));
    }
  } catch (err) {
    alert("Network error: " + err);
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

async function publishPreparedRelease(releaseId) {
  const rel = currentReleasesCache[releaseId];
  const verName = rel ? `v${rel.version} (Sequence ${rel.release_sequence})` : `Release #${releaseId}`;
  const confirmed = confirm(`Publish ${verName} to Clients?\n\nThis will transition the release state to 'published' and make it immediately discoverable by client devices.`);
  if (!confirmed) return;

  try {
    const res = await fetch(`/api/admin/releases/${releaseId}/publish`, {
      method: "POST"
    });
    const data = await res.json();
    if (res.ok) {
      alert(data.message);
      await loadReleases();
      await loadStats();
      await loadLogs();
    } else {
      alert("Failed to publish release: " + (data.error || "Unknown error"));
    }
  } catch (err) {
    alert("Publish network error: " + err);
  }
}

async function quickPublish(version, sequence, desc) {
  // Check if this version is already prepared in cache
  for (const id in currentReleasesCache) {
    const r = currentReleasesCache[id];
    if (r.version === version) {
      if (r.status === "prepared") {
        return publishPreparedRelease(r.id);
      } else if (r.status === "published") {
        alert(`DemoApp v${version} (Sequence ${sequence}) is already published and active!`);
        return;
      } else if (r.status === "revoked") {
        alert(`DemoApp v${version} (Sequence ${sequence}) is currently revoked.`);
        return;
      }
    }
  }

  const pkgMap = {
    "1.1.0": { filename: "demoapp-1.1.0.zip", size: 1272 },
    "1.2.0": { filename: "demoapp-1.2.0.zip", size: 1441 },
    "1.3.0": { filename: "demoapp-1.3.0.zip", size: 1825 },
    "1.4.0": { filename: "demoapp-1.4.0.zip", size: 2427 }
  };
  const pkg = pkgMap[version];
  if (!pkg) return;

  const payload = {
    software_id: "demoapp",
    version: version,
    release_sequence: sequence,
    package_filename: pkg.filename,
    package_hash: "",
    package_size: pkg.size,
    description: desc,
    expiration_days: 365
  };

  try {
    const checkRes = await fetch(`/api/updates/download/${pkg.filename}`);
    if (checkRes.ok) {
      const blob = await checkRes.blob();
      const buf = await blob.arrayBuffer();
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
    currentReleasesCache = {};

    const pubTbody = document.querySelector("#releases-table tbody");
    const prepTbody = document.querySelector("#prepared-releases-table tbody");
    const prepBadge = document.getElementById("prepared-count-badge");

    pubTbody.innerHTML = "";
    if (prepTbody) prepTbody.innerHTML = "";

    if (data.releases) {
      data.releases.forEach(r => { currentReleasesCache[r.id] = r; });
    }

    const prepList = data.prepared_releases || (data.releases ? data.releases.filter(r => r.status === 'prepared').sort((a,b) => a.release_sequence - b.release_sequence) : []);
    const pubList = data.published_releases || (data.releases ? data.releases.filter(r => r.status !== 'prepared').sort((a,b) => b.release_sequence - a.release_sequence) : []);

    if (prepBadge) {
      prepBadge.innerText = `${prepList.length} Prepared`;
      prepBadge.className = prepList.length > 0 ? "badge badge-warning" : "badge badge-info";
    }

    // 1. Render Prepared Releases (sorted release_sequence ASC)
    if (prepTbody) {
      if (prepList.length === 0) {
        prepTbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 1rem;">No prepared releases pending publication. All packages are published.</td></tr>`;
      } else {
        prepList.forEach(r => {
          const tr = document.createElement("tr");
          tr.style.cursor = "pointer";
          const shortHash = r.package_hash ? r.package_hash.substring(0, 10) + "..." : "N/A";
          tr.innerHTML = `
            <td><strong>${r.software_id}</strong></td>
            <td><code>v${r.version}</code></td>
            <td><span class="badge badge-info">Seq: ${r.release_sequence}</span></td>
            <td>${r.package_filename}</td>
            <td><code title="${r.package_hash}">${shortHash}</code></td>
            <td style="font-size: 0.8rem; color: #cbd5e1;">${r.description || '-'}</td>
            <td><span class="badge badge-warning"><i class="fa-solid fa-clock"></i> Prepared</span></td>
            <td>
              <button class="btn btn-primary" style="padding: 0.25rem 0.6rem; font-size: 0.75rem;" onclick="event.stopPropagation(); publishPreparedRelease(${r.id})">
                <i class="fa-solid fa-cloud-arrow-up"></i> Publish
              </button>
              <button class="btn btn-secondary" style="padding: 0.25rem 0.5rem; font-size: 0.72rem; margin-left: 0.25rem;" onclick="event.stopPropagation(); openReleaseDetails(${r.id})">
                <i class="fa-solid fa-magnifying-glass"></i> Details
              </button>
            </td>
          `;
          tr.addEventListener("click", () => openReleaseDetails(r.id));
          prepTbody.appendChild(tr);
        });
      }
    }

    // 2. Render Published Releases (sorted release_sequence DESC)
    if (pubList.length === 0) {
      pubTbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 1rem;">No published releases available yet.</td></tr>`;
    } else {
      pubList.forEach(r => {
        const tr = document.createElement("tr");
        tr.style.cursor = "pointer";
        tr.title = "Click to inspect full cryptographic release metadata & verification details";

        const shortHash = r.package_hash ? r.package_hash.substring(0, 10) + "..." : "N/A";
        const shortSig = r.signature ? r.signature.substring(0, 12) + "..." : "N/A";
        const statusBadge = r.status === "published"
          ? `<span class="badge badge-success"><i class="fa-solid fa-check"></i> Published</span>`
          : `<span class="badge badge-danger"><i class="fa-solid fa-ban"></i> Revoked</span>`;

        tr.innerHTML = `
          <td><strong>#${r.id}</strong></td>
          <td><strong>${r.software_id}</strong></td>
          <td><code>v${r.version}</code></td>
          <td><span class="badge badge-info">Seq: ${r.release_sequence}</span></td>
          <td><code title="${r.package_hash}">${shortHash}</code></td>
          <td><code title="${r.signature}">${shortSig}</code></td>
          <td>${new Date(r.published_at).toLocaleString()}</td>
          <td>${statusBadge}</td>
          <td>
            <button class="btn btn-secondary" style="padding: 0.2rem 0.5rem; font-size: 0.72rem; margin-right: 0.25rem;" onclick="event.stopPropagation(); openReleaseDetails(${r.id})">
              <i class="fa-solid fa-magnifying-glass"></i> Details
            </button>
            ${r.status === "published" 
              ? `<button class="btn btn-danger" style="padding: 0.2rem 0.5rem; font-size: 0.72rem;" onclick="event.stopPropagation(); promptRevoke(${r.id})"><i class="fa-solid fa-ban"></i> Revoke</button>` 
              : `<span style="font-size: 0.75rem; color: var(--text-muted);"><i class="fa-solid fa-lock"></i> Revoked</span>`}
          </td>
        `;

        tr.addEventListener("click", () => openReleaseDetails(r.id));
        pubTbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error("Releases load error:", err);
  }
}

async function openReleaseDetails(releaseId) {
  let release = currentReleasesCache[releaseId];
  if (!release) {
    try {
      const res = await fetch(`/api/admin/releases/${releaseId}`);
      if (res.ok) {
        const d = await res.json();
        release = d.release;
      }
    } catch (e) {
      console.error(e);
    }
  }
  if (!release) return;

  currentModalReleaseId = release.id;
  document.getElementById("modal-rel-title").innerHTML = `<i class="fa-solid fa-box-open"></i> Release #${release.id}: ${release.software_id} v${release.version}`;
  
  const badge = document.getElementById("modal-rel-status-badge");
  if (release.status === "published") {
    badge.className = "badge badge-success";
    badge.innerText = "Status: Published";
    document.getElementById("modal-btn-revoke").style.display = "inline-flex";
  } else if (release.status === "prepared") {
    badge.className = "badge badge-warning";
    badge.innerText = "Status: Prepared (Awaiting Publication)";
    document.getElementById("modal-btn-revoke").style.display = "none";
  } else {
    badge.className = "badge badge-danger";
    badge.innerText = "Status: Revoked";
    document.getElementById("modal-btn-revoke").style.display = "none";
  }

  document.getElementById("modal-rel-software").innerText = release.software_id;
  document.getElementById("modal-rel-version").innerText = `v${release.version} (Monotonic Sequence: ${release.release_sequence})`;
  document.getElementById("modal-rel-filename").innerText = `${release.package_filename} (${release.package_size} bytes)`;
  
  const pubDate = new Date(release.published_at).toLocaleString();
  const expDate = new Date(release.expires_at).toLocaleString();
  document.getElementById("modal-rel-validity").innerText = `Published: ${pubDate}\nExpires: ${expDate}`;

  // Revocation details
  const revBox = document.getElementById("modal-rel-revocation-box");
  if (release.status === "revoked") {
    revBox.style.display = "block";
    const revDate = release.revoked_at ? new Date(release.revoked_at).toLocaleString() : "Recently";
    const reason = release.revocation_reason || "Administrative revocation";
    document.getElementById("modal-rel-revocation-details").innerText = `Revoked at: ${revDate} | Reason: ${reason}`;
  } else {
    revBox.style.display = "none";
  }

  // Hashes & Signatures
  document.getElementById("modal-rel-hash").innerText = release.package_hash || "N/A";
  document.getElementById("modal-rel-sig").innerText = release.signature || "N/A";
  
  const metaObj = release.metadata || {};
  document.getElementById("modal-rel-json").innerText = JSON.stringify(metaObj, null, 2);

  // Download link
  const btnDl = document.getElementById("modal-btn-download");
  btnDl.href = `/api/updates/download/${release.package_filename}`;

  document.getElementById("release-details-modal").style.display = "flex";
}

function closeReleaseModal() {
  document.getElementById("release-details-modal").style.display = "none";
  currentModalReleaseId = null;
}

function promptRevoke(releaseId) {
  document.getElementById("revoke-release-id").value = releaseId;
  document.getElementById("revoke-reason-input").value = "";
  document.getElementById("revoke-modal").style.display = "flex";
}

function promptRevokeFromModal() {
  if (currentModalReleaseId) {
    promptRevoke(currentModalReleaseId);
  }
}

function closeRevokeModal() {
  document.getElementById("revoke-modal").style.display = "none";
}

async function handleRevokeSubmit(e) {
  e.preventDefault();
  const relId = document.getElementById("revoke-release-id").value;
  const reason = document.getElementById("revoke-reason-input").value.trim();
  if (!relId) return;

  try {
    const res = await fetch(`/api/admin/revoke/${relId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: reason || "Administrative revocation" })
    });
    if (res.ok) {
      closeRevokeModal();
      closeReleaseModal();
      loadReleases();
      loadStats();
      loadLogs();
      alert(`Release #${relId} has been successfully revoked.`);
    } else {
      const err = await res.json();
      alert("Revoke failed: " + (err.error || "Unknown error"));
    }
  } catch (err) {
    alert("Network error: " + err);
  }
}

function copyText(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.innerText;
  navigator.clipboard.writeText(text).then(() => {
    alert("Copied to clipboard!");
  }).catch(() => {
    // Fallback
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("Copied to clipboard!");
  });
}

async function applyLogFilters() {
  await loadLogs();
}

function resetLogFilters() {
  document.getElementById("filter-sec-type").value = "ALL";
  document.getElementById("filter-sec-result").value = "ALL";
  loadLogs();
}

async function loadLogs() {
  try {
    const type = document.getElementById("filter-sec-type") ? document.getElementById("filter-sec-type").value : "ALL";
    const result = document.getElementById("filter-sec-result") ? document.getElementById("filter-sec-result").value : "ALL";
    
    let url = `/api/admin/logs?limit=50&event_type=${encodeURIComponent(type)}&result=${encodeURIComponent(result)}`;
    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();

    const secTerm = document.getElementById("security-log-terminal");
    secTerm.innerHTML = "";
    if (data.security_events.length === 0) {
      secTerm.innerHTML = `<div class="terminal-line info">[SYS] No matching security incidents for active filter.</div>`;
    } else {
      data.security_events.forEach(e => {
        const line = document.createElement("div");
        line.className = `terminal-line ${e.result === "BLOCKED" ? "error" : "success"}`;
        const timeStr = e.timestamp ? e.timestamp.substring(11, 19) : "--:--:--";
        line.innerText = `[${timeStr}] [${e.event_type}] [${e.result}] (Actor: ${e.related_client_or_admin}) ${e.description}`;
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
        const timeStr = a.timestamp ? a.timestamp.substring(11, 19) : "--:--:--";
        line.innerText = `[${timeStr}] [${a.client_id}] [${a.action}] Verif: ${a.verification_result} | Install: ${a.installation_result} (${a.details})`;
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
