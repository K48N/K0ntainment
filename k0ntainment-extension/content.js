(() => {
  const BUTTON_ID = "k0ntainment-button";
  const BUTTON_HOST_ID = "k0ntainment-button-host";
  const PANEL_ID = "k0ntainment-panel";

  let lastUrl = "";
  let activeScanId = null;
  let activeScanStart = 0;
  let activeLastProgressAt = 0;
  let activeButton = null;
  let activeContext = null;
  let lastScanData = null;
  let lastScanContext = null;

  let DEBUG = window.localStorage.getItem("k0ntainmentDebug") === "1";
  chrome.storage.local.get(["k0ntainmentDebug"], (result) => {
    if (typeof result.k0ntainmentDebug === "boolean") {
      DEBUG = result.k0ntainmentDebug;
    }
  });

  function getPlatform() {
    if (location.hostname === "github.com") return "github";
    if (location.hostname === "gitlab.com") return "gitlab";
    return null;
  }

  function isBlacklistedGitHubOwner(owner) {
    const blacklist = new Set([
      "about", "account", "codespaces", "collections", "contact", "customer-stories", "enterprise", "features",
      "issues", "login", "marketplace", "new", "notifications", "orgs", "pricing", "pulls", "search",
      "security", "settings", "signup", "site", "sponsors", "team", "topics", "trending"
    ]);
    return blacklist.has(owner);
  }

  function parseGitHubRepo() {
    const parts = location.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;

    const owner = parts[0];
    const repo = parts[1];
    if (isBlacklistedGitHubOwner(owner)) return null;

    return { platform: "github", owner, repo, displayName: `${owner}/${repo}`, url: location.href };
  }

  function parseGitLabRepo() {
    const path = location.pathname;
    const marker = path.indexOf("/-/");

    let projectPath = "";
    if (marker >= 0) {
      projectPath = path.slice(0, marker);
    } else {
      const parts = path.split("/").filter(Boolean);
      if (parts.length < 2) return null;
      projectPath = `/${parts[0]}/${parts[1]}`;
    }

    const trimmed = projectPath.replace(/^\/+|\/+$/g, "");
    if (!trimmed) return null;

    const segments = trimmed.split("/");
    if (segments.length < 2) return null;

    return { platform: "gitlab", projectPath: trimmed, displayName: trimmed, url: location.href };
  }

  function getRepoContext() {
    const platform = getPlatform();
    if (platform === "github") return parseGitHubRepo();
    if (platform === "gitlab") return parseGitLabRepo();
    return null;
  }

  function detectTheme(platform) {
    const root = document.documentElement;
    if (platform === "github") {
      const mode = root.getAttribute("data-color-mode");
      return mode === "dark" ? "dark" : "light";
    }

    const htmlClass = root.className || "";
    if (/dark/i.test(htmlClass)) return "dark";
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) return "dark";
    return "light";
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function buildList(items, fallback) {
    if (!Array.isArray(items) || items.length === 0) {
      return `<li>${escapeHtml(fallback)}</li>`;
    }
    return items.map((line) => `<li>${escapeHtml(line)}</li>`).join("");
  }

  function removeUi() {
    document.getElementById(BUTTON_ID)?.remove();
    document.getElementById(PANEL_ID)?.remove();
    document.getElementById(BUTTON_HOST_ID)?.remove();

    activeScanId = null;
    activeButton = null;
    activeContext = null;
    activeScanStart = 0;
  }

  function colorForScore(score) {
    if (score >= 80) return "var(--k0-score-good)";
    if (score >= 60) return "var(--k0-score-medium)";
    return "var(--k0-score-bad)";
  }

  function formatEta(seconds) {
    if (!Number.isFinite(seconds) || seconds < 0) return "--";
    if (seconds < 60) return `${Math.ceil(seconds)}s`;
    const mins = Math.floor(seconds / 60);
    const rem = Math.ceil(seconds % 60);
    return `${mins}m ${rem}s`;
  }

  function shortenPath(path) {
    const value = String(path || "");
    if (!value) return "";
    if (value.length <= 46) return value;
    return `...${value.slice(value.length - 43)}`;
  }

  function fileNameFromPath(path) {
    const value = String(path || "");
    if (!value) return "";
    const parts = value.split("/");
    return parts[parts.length - 1] || value;
  }

  function logDebug(message, data) {
    if (!DEBUG) return;
    if (typeof data === "undefined") {
      console.log("[K0ntmination]", message);
      return;
    }
    console.log("[K0ntmination]", message, data);
  }

  function fitButtonLabel(labelEl, text) {
    if (!labelEl) return;
    const normalized = String(text || "");
    labelEl.textContent = normalized;

    const maxWidth = 210;
    const maxFont = 12;
    const minFont = 8.2;
    const estimate = normalized.length * 0.58 * maxFont;
    const size = estimate > maxWidth ? Math.max(minFont, maxWidth / Math.max(1, normalized.length * 0.58)) : maxFont;

    labelEl.style.fontSize = `${size.toFixed(2)}px`;
    labelEl.style.letterSpacing = size < 10 ? "-0.1px" : "0";
  }

  function ensureButtonMarkup(button) {
    if (button.querySelector(".k0-btn-label")) return;

    button.innerHTML = `
      <span class="k0-btn-stack">
        <span class="k0-btn-label">K0ntmination Scan</span>
        <span class="k0-btn-meta" aria-live="polite"></span>
        <span class="k0-btn-path" aria-live="polite"></span>
      </span>
      <span class="k0-btn-progress" aria-hidden="true"><span class="k0-btn-progress-fill"></span></span>
    `;
  }

  function setButtonIdle(button) {
    ensureButtonMarkup(button);
    button.classList.remove("k0-scanning", "k0-canceling");
    button.disabled = false;
    button.removeAttribute("aria-busy");

    const label = button.querySelector(".k0-btn-label");
    const meta = button.querySelector(".k0-btn-meta");
    const path = button.querySelector(".k0-btn-path");
    const fill = button.querySelector(".k0-btn-progress-fill");

    fitButtonLabel(label, "K0ntmination Scan");
    if (meta) meta.textContent = "";
    if (path) path.textContent = "";
    if (fill) fill.style.width = "0%";
  }

  function setButtonCanceling(button) {
    ensureButtonMarkup(button);
    button.classList.add("k0-canceling");
    const label = button.querySelector(".k0-btn-label");
    const meta = button.querySelector(".k0-btn-meta");
    fitButtonLabel(label, "Canceling scan...");
    if (meta) meta.textContent = "Stopping active requests";
  }

  function setButtonProgress(button, update) {
    ensureButtonMarkup(button);
    button.classList.add("k0-scanning");
    button.classList.remove("k0-canceling");
    button.disabled = false;
    button.setAttribute("aria-busy", "true");

    const label = button.querySelector(".k0-btn-label");
    const meta = button.querySelector(".k0-btn-meta");
    const path = button.querySelector(".k0-btn-path");
    const fill = button.querySelector(".k0-btn-progress-fill");

    const percent = Math.max(1, Math.min(99, Number(update.percent || 0)));
    const stageLabel = update.label || "Scanning";
    if (fill) fill.style.width = `${percent}%`;

    const processed = Number(update.processed || 0);
    const total = Number(update.total || 0);
    const elapsed = Math.max(0, (Date.now() - activeScanStart) / 1000);

    let etaText = "ETA --";
    if (processed > 0 && total > 0 && processed <= total) {
      const avg = elapsed / processed;
      etaText = `ETA ${formatEta(avg * (total - processed))}`;
    }

    const countText = total > 0 ? `${processed}/${total} files` : "Preparing file list";
    if (meta) meta.textContent = `${countText} • ${etaText}`;
    if (path) path.textContent = update.currentPath ? shortenPath(update.currentPath) : "";

    const currentFileName = fileNameFromPath(update.currentPath);
    let compact = stageLabel;
    if (total > 0) compact = `Scanning ${processed}/${total}`;
    if (currentFileName) compact = `${compact} • ${currentFileName}`;
    else if (etaText !== "ETA --") compact = `${compact} • ${etaText}`;

    fitButtonLabel(label, compact);
  }

  function formatAge(ms) {
    const secs = Math.floor(ms / 1000);
    if (secs < 60) return "just now";
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins} min ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  }

  function severityTag(severity) {
    const s = String(severity || "Info");
    return `<span class="k0-sev k0-sev-${s.toLowerCase()}">${escapeHtml(s)}</span>`;
  }

  function buildTaggedFindings(findings) {
    if (!Array.isArray(findings) || findings.length === 0) {
      return `<li>No obvious high-risk indicators found.</li>`;
    }
    return findings.map((f) => {
      if (typeof f === "string") return `<li>${escapeHtml(f)}</li>`;
      return `<li>${severityTag(f.severity)} ${escapeHtml(f.message)}</li>`;
    }).join("");
  }

  function buildConfidenceBar(confidence) {
    const pct = Math.max(0, Math.min(100, Number(confidence || 0)));
    const label = pct >= 75 ? "High" : pct >= 45 ? "Medium" : "Low";
    return `
      <div class="k0-conf-row" title="Confidence: ${pct}/100">
        <span class="k0-conf-label">Confidence</span>
        <div class="k0-conf-bar"><div class="k0-conf-fill" style="width:${pct}%"></div></div>
        <span class="k0-conf-value">${label} (${pct}/100)</span>
      </div>`;
  }

  async function openOptionsPage() {
    await sendMessage({ type: "k0ntainment.openOptions" });
  }

  function findPanelInsertionPoint(platform) {
    if (platform === "github") {
      // Insert before the repo content area — this sits just below the nav tabs
      return (
        document.querySelector("#repo-content-turbo-frame") ||
        document.querySelector("turbo-frame#repo-content-turbo-frame") ||
        document.querySelector(".repository-content") ||
        document.querySelector("[data-turbo-frame='repo-content-turbo-frame']") ||
        null
      );
    }
    if (platform === "gitlab") {
      return (
        document.querySelector(".project-repo-buttons + div") ||
        document.querySelector(".tree-holder") ||
        document.querySelector(".blob-viewer") ||
        null
      );
    }
    return null;
  }

  function insertPanel(panel, context) {
    const anchor = findPanelInsertionPoint(context.platform);
    if (anchor) {
      anchor.insertAdjacentElement("beforebegin", panel);
    } else {
      // Fallback: insert after the repository header
      const fallback =
        document.querySelector("#repository-container-header") ||
        document.querySelector(".detail-page-header");
      if (fallback) {
        fallback.insertAdjacentElement("afterend", panel);
      } else {
        document.body.appendChild(panel);
        panel.dataset.floating = "true";
      }
    }
  }

  function renderPanel(data, context) {
    document.getElementById(PANEL_ID)?.remove();

    const theme = detectTheme(context.platform);
    const panel = document.createElement("aside");
    panel.id = PANEL_ID;
    panel.setAttribute("role", "region");
    panel.setAttribute("aria-label", "K0ntmination scan results");
    panel.dataset.theme = theme;

    if (data.error) {
      panel.innerHTML = `
        <div class="k0-panel-inner">
          <div class="k0-panel-row k0-panel-top">
            <span class="k0-panel-title">K0ntmination Scanner</span>
            <button class="k0-close" aria-label="Dismiss">&#x2715;</button>
          </div>
          <p class="k0-meta k0-error">${escapeHtml(data.error)}</p>
        </div>
      `;
    } else {
      const score = typeof data.k0ntaminationScore === "number" ? data.k0ntaminationScore : data.score;
      const confidence = typeof data.confidence === "number" ? data.confidence : 0;
      const breakdown = data.breakdown || {};
      const riskLevel = escapeHtml(data.riskLevel || "Unknown");
      const ageText = data.scannedAt ? formatAge(Date.now() - data.scannedAt) : "";

      const breakdownItems = [
        `Code risk (${breakdown.codeWeight || 0}%): ${breakdown.codeScore ?? "n/a"}/100`,
        `Trust signals (${breakdown.trustWeight || 0}%): ${breakdown.trustScore ?? "n/a"}/100`,
        `Hygiene (${breakdown.hygieneWeight || 0}%): ${breakdown.hygieneScore ?? "n/a"}/100`,
      ];

      const findings = (data.findings || []).filter((f) => {
        const msg = typeof f === "string" ? f : f?.message || "";
        return !/manually review/i.test(msg);
      }).slice(0, 10);

      panel.innerHTML = `
        <div class="k0-panel-inner">
          <div class="k0-panel-row k0-panel-top">
            <div class="k0-panel-score-row">
              <span class="k0-score" style="color:${colorForScore(score)}">${score}<span class="k0-score-denom">/100</span></span>
              <div class="k0-panel-labels">
                <span class="k0-risk-badge k0-risk-${riskLevel.toLowerCase()}">${riskLevel} risk</span>
                <span class="k0-panel-title">K0ntmination Score${ageText ? ` • <span class="k0-age">${escapeHtml(ageText)}</span>` : ""}</span>
              </div>
            </div>
            <div class="k0-panel-actions">
              <button type="button" class="k0-rescan">Re-scan</button>
              <button type="button" class="k0-settings">Token Settings</button>
              <button class="k0-close" aria-label="Dismiss">&#x2715;</button>
            </div>
          </div>

          <p class="k0-explanation">${escapeHtml(data.explanation || "No explanation available.")}</p>

          <details class="k0-details" open>
            <summary class="k0-section-title">Weighted Breakdown</summary>
            <ul>${buildList(breakdownItems, "No weighted breakdown available.")}</ul>
            ${buildConfidenceBar(confidence)}
          </details>

          <details class="k0-details">
            <summary class="k0-section-title">Key Findings</summary>
            <ul>${buildTaggedFindings(findings)}</ul>
          </details>

          <details class="k0-details">
            <summary class="k0-section-title">File and Signal Evidence</summary>
            <ul>${buildList((data.evidence || []).slice(0, 14), "No detailed evidence available.")}</ul>
          </details>

          <p class="k0-disclaimer">${escapeHtml(data.disclaimer || "Indicator only. Always manually review a project before trusting it.")}</p>
        </div>
      `;
    }

    panel.querySelector(".k0-close")?.addEventListener("click", () => panel.remove());
    panel.querySelector(".k0-settings")?.addEventListener("click", () => openOptionsPage());
    panel.querySelector(".k0-rescan")?.addEventListener("click", () => {
      panel.remove();
      lastScanData = null;
      lastScanContext = null;
      if (activeButton && activeContext) {
        runScan(activeButton, activeContext);
      } else {
        const btn = document.getElementById(BUTTON_ID);
        const ctx = getRepoContext();
        if (btn && ctx) runScan(btn, ctx);
      }
    });

    insertPanel(panel, context);
  }

  function sendMessage(payload) {
    return new Promise((resolve) => {
      logDebug("Message -> background", payload);

      let done = false;
      let timeoutId = null;
      let watchdogId = null;

      const finish = (value) => {
        if (done) return;
        done = true;
        if (timeoutId) clearTimeout(timeoutId);
        if (watchdogId) clearInterval(watchdogId);
        resolve(value);
      };

      if (payload?.type === "k0ntainment.scan") {
        timeoutId = setTimeout(() => {
          logDebug("Message timeout", "max scan timeout");
          finish({ error: "Scan exceeded the maximum runtime. Try reducing blockers on api.github.com/raw.githubusercontent.com or add PAT tokens." });
        }, 8 * 60 * 1000);

        watchdogId = setInterval(() => {
          const idleMs = Date.now() - (activeLastProgressAt || activeScanStart || Date.now());
          if (idleMs > 45000) {
            logDebug("Message timeout", `idle ${idleMs}ms`);
            finish({ error: "Scan stalled while waiting for API responses. This is often caused by network/privacy blockers on GitHub/GitLab API domains." });
          }
        }, 5000);
      } else {
        timeoutId = setTimeout(() => {
          logDebug("Message timeout", payload.type);
          finish({ error: "Scan timed out. This may be caused by a network issue or a blocker extension." });
        }, 90000);
      }

      chrome.runtime.sendMessage(payload, (response) => {
        if (done) return;
        if (chrome.runtime.lastError) {
          logDebug("Runtime message error", chrome.runtime.lastError.message);
          finish({ error: chrome.runtime.lastError.message || "Message failed" });
          return;
        }
        logDebug("Message <- background", { type: payload.type, response });
        finish(response || { error: "No response received from scanner." });
      });
    });
  }

  function randomScanId() {
    return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (!message || message.type !== "k0ntainment.scanProgress") return;
    if (!activeScanId || message.scanId !== activeScanId) return;
    if (!activeButton) return;

    activeLastProgressAt = Date.now();

    if (DEBUG && message.processed % 10 === 0) {
      logDebug("Progress", {
        label: message.label,
        processed: message.processed,
        total: message.total,
        currentPath: message.currentPath
      });
    }

    setButtonProgress(activeButton, {
      label: message.label || "Scanning",
      percent: message.percent,
      processed: message.processed,
      total: message.total,
      currentPath: message.currentPath || ""
    });
  });

  async function cancelActiveScan() {
    if (!activeScanId) return;
    logDebug("Cancel requested", { scanId: activeScanId });
    if (activeButton) setButtonCanceling(activeButton);
    await sendMessage({ type: "k0ntainment.cancelScan", scanId: activeScanId });
  }

  async function runScan(button, context) {
    if (activeScanId && activeButton === button) {
      await cancelActiveScan();
      return;
    }

    // Toggle: if panel already open for this repo, close it
    const existingPanel = document.getElementById(PANEL_ID);
    if (!activeScanId && existingPanel) {
      existingPanel.remove();
      return;
    }

    // Re-show cached result without re-scanning
    if (!activeScanId && lastScanData && lastScanContext?.displayName === context.displayName) {
      renderPanel(lastScanData, lastScanContext);
      return;
    }

    activeScanId = randomScanId();
    activeButton = button;
    activeContext = context;
    activeScanStart = Date.now();
    activeLastProgressAt = activeScanStart;
    logDebug("Scan started", { scanId: activeScanId, context });

    setButtonProgress(button, { label: "Initializing scan", percent: 2, processed: 0, total: 0, currentPath: "" });

    try {
      const result = await sendMessage({ type: "k0ntainment.scan", context, scanId: activeScanId });
      if (activeButton) setButtonIdle(activeButton);
      lastScanData = result;
      lastScanContext = context;
      renderPanel(result, context);
      logDebug("Scan finished", { scanId: activeScanId, result });
    } catch (error) {
      if (activeButton) setButtonIdle(activeButton);
      renderPanel({ error: error?.message || "Scan failed unexpectedly." }, context);
      logDebug("Scan failed", { scanId: activeScanId, error: String(error?.message || error) });
    } finally {
      activeScanId = null;
      activeScanStart = 0;
      activeLastProgressAt = 0;
      activeButton = null;
      activeContext = null;
    }
  }

  function findGitHubAnchor() {
    const selectors = ["#repository-container-header div[data-testid='repository-actions']", ".pagehead-actions", ".file-navigation"];
    for (const selector of selectors) {
      const el = document.querySelector(selector);
      if (el) return el;
    }
    return null;
  }

  function findGitLabAnchor() {
    const selectors = [".project-action-buttons", ".tree-controls", ".gl-display-flex.gl-gap-3"];
    for (const selector of selectors) {
      const el = document.querySelector(selector);
      if (el) return el;
    }
    return null;
  }

  function attachButton(button, context) {
    button.className = "";
    button.classList.add("k0-button-base");

    if (context.platform === "github") {
      button.classList.add("btn", "btn-sm", "k0-host-github");
      const anchor = findGitHubAnchor();
      if (anchor) {
        let host = document.getElementById(BUTTON_HOST_ID);
        if (!host) {
          host = document.createElement("span");
          host.id = BUTTON_HOST_ID;
          host.className = "k0-inline-host";
          anchor.appendChild(host);
        }
        if (!host.contains(button)) host.appendChild(button);
        return;
      }
    }

    if (context.platform === "gitlab") {
      button.classList.add("gl-button", "btn", "btn-default", "btn-sm", "k0-host-gitlab");
      const anchor = findGitLabAnchor();
      if (anchor) {
        let host = document.getElementById(BUTTON_HOST_ID);
        if (!host) {
          host = document.createElement("span");
          host.id = BUTTON_HOST_ID;
          host.className = "k0-inline-host";
          anchor.appendChild(host);
        }
        if (!host.contains(button)) host.appendChild(button);
        return;
      }
    }

    button.classList.add("k0-floating-fallback");
    if (!document.body.contains(button)) document.body.appendChild(button);
  }

  function ensureUi() {
    const context = getRepoContext();
    if (!context) {
      removeUi();
      lastUrl = location.href;
      return;
    }

    const navigationChanged = location.href !== lastUrl;
    lastUrl = location.href;

    let button = document.getElementById(BUTTON_ID);
    if (!button) {
      button = document.createElement("button");
      button.id = BUTTON_ID;
      button.type = "button";
      button.setAttribute("aria-label", "Run K0ntmination Scan");
      setButtonIdle(button);
    }

    attachButton(button, context);
    button.onclick = () => runScan(button, context);

    if (navigationChanged) {
      document.getElementById(PANEL_ID)?.remove();
      lastScanData = null;
      lastScanContext = null;

      if (activeScanId && activeContext && activeContext.url !== location.href) {
        activeScanId = null;
        activeScanStart = 0;
        activeButton = null;
        activeContext = null;
        setButtonIdle(button);
      }
    }
  }

  ensureUi();
  setInterval(ensureUi, 1200);
})();
