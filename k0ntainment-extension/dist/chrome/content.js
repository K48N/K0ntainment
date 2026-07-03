(() => {
  const BUTTON_ID = "k0ntainment-button";
  const BUTTON_HOST_ID = "k0ntainment-button-host";
  const PANEL_ID = "k0ntainment-panel";
  let lastUrl = "";

  function getPlatform() {
    if (location.hostname === "github.com") {
      return "github";
    }
    if (location.hostname === "gitlab.com") {
      return "gitlab";
    }
    return null;
  }

  function isBlacklistedGitHubOwner(owner) {
    const blacklist = new Set([
      "about",
      "account",
      "codespaces",
      "collections",
      "contact",
      "customer-stories",
      "enterprise",
      "features",
      "issues",
      "login",
      "marketplace",
      "new",
      "notifications",
      "orgs",
      "pricing",
      "pulls",
      "search",
      "security",
      "settings",
      "signup",
      "site",
      "sponsors",
      "team",
      "topics",
      "trending"
    ]);
    return blacklist.has(owner);
  }

  function parseGitHubRepo() {
    const parts = location.pathname.split("/").filter(Boolean);
    if (parts.length < 2) {
      return null;
    }

    const owner = parts[0];
    const repo = parts[1];
    if (isBlacklistedGitHubOwner(owner)) {
      return null;
    }

    return {
      platform: "github",
      owner,
      repo,
      displayName: `${owner}/${repo}`,
      url: location.href
    };
  }

  function parseGitLabRepo() {
    const path = location.pathname;
    const marker = path.indexOf("/-/");

    let projectPath = "";
    if (marker >= 0) {
      projectPath = path.slice(0, marker);
    } else {
      const parts = path.split("/").filter(Boolean);
      if (parts.length < 2) {
        return null;
      }
      projectPath = `/${parts[0]}/${parts[1]}`;
    }

    const trimmed = projectPath.replace(/^\/+|\/+$/g, "");
    if (!trimmed) {
      return null;
    }

    const segments = trimmed.split("/");
    if (segments.length < 2) {
      return null;
    }

    return {
      platform: "gitlab",
      projectPath: trimmed,
      displayName: trimmed,
      url: location.href
    };
  }

  function getRepoContext() {
    const platform = getPlatform();
    if (platform === "github") {
      return parseGitHubRepo();
    }
    if (platform === "gitlab") {
      return parseGitLabRepo();
    }
    return null;
  }

  function detectTheme(platform) {
    const root = document.documentElement;
    if (platform === "github") {
      const mode = root.getAttribute("data-color-mode");
      return mode === "dark" ? "dark" : "light";
    }

    const htmlClass = root.className || "";
    if (/dark/i.test(htmlClass)) {
      return "dark";
    }

    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      return "dark";
    }

    return "light";
  }

  function removeUi() {
    const button = document.getElementById(BUTTON_ID);
    const panel = document.getElementById(PANEL_ID);
    const host = document.getElementById(BUTTON_HOST_ID);

    if (button) {
      button.remove();
    }
    if (panel) {
      panel.remove();
    }
    if (host) {
      host.remove();
    }
  }

  function colorForScore(score) {
    if (score >= 80) {
      return "var(--k0-score-good)";
    }
    if (score >= 60) {
      return "var(--k0-score-medium)";
    }
    return "var(--k0-score-bad)";
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

  async function openOptionsPage() {
    await sendMessage({ type: "k0ntainment.openOptions" });
  }

  function renderPanel(data, context) {
    const existing = document.getElementById(PANEL_ID);
    if (existing) {
      existing.remove();
    }

    const panel = document.createElement("aside");
    panel.id = PANEL_ID;
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-live", "polite");
    panel.dataset.theme = detectTheme(context.platform);

    if (data.error) {
      panel.innerHTML = `
        <div class="k0-head">
          <h3>K0ntmination Scanner</h3>
          <button class="k0-close" aria-label="Close">x</button>
        </div>
        <p class="k0-meta">${escapeHtml(data.error)}</p>
      `;
    } else {
      const score = typeof data.k0ntaminationScore === "number" ? data.k0ntaminationScore : data.score;
      const confidence = typeof data.confidence === "number" ? data.confidence : 0;
      const breakdown = data.breakdown || {};

      const breakdownItems = [
        `Code risk (${breakdown.codeWeight || 0}%): ${breakdown.codeScore ?? "n/a"}/100`,
        `Trust signals (${breakdown.trustWeight || 0}%): ${breakdown.trustScore ?? "n/a"}/100`,
        `Hygiene (${breakdown.hygieneWeight || 0}%): ${breakdown.hygieneScore ?? "n/a"}/100`,
        `Confidence: ${confidence}/100`
      ];

      panel.innerHTML = `
        <div class="k0-head">
          <h3>K0ntmination Scanner</h3>
          <button class="k0-close" aria-label="Close">x</button>
        </div>
        <div class="k0-score" style="color:${colorForScore(score)}">K0ntamination Score: ${score}/100</div>
        <div class="k0-meta">${escapeHtml(data.riskLevel || "Unknown")} risk • ${escapeHtml(data.repoName || context.displayName)}</div>
        <p class="k0-explanation">${escapeHtml(data.explanation || "No explanation available.")}</p>

        <div class="k0-section-title">Weighted Breakdown</div>
        <ul>${buildList(breakdownItems, "No weighted breakdown available.")}</ul>

        <div class="k0-section-title">Key Findings</div>
        <ul>${buildList((data.findings || []).slice(0, 8), "No obvious high-risk indicators found by current heuristics.")}</ul>

        <div class="k0-section-title">File and Signal Evidence</div>
        <ul>${buildList((data.evidence || []).slice(0, 12), "No detailed evidence lines were available from this scan.")}</ul>

        <p class="k0-disclaimer">${escapeHtml(data.disclaimer || "Indicator only. Always manually review a project before trusting it.")}</p>
        <div class="k0-actions">
          <button type="button" class="k0-settings">Token Settings</button>
        </div>
      `;
    }

    panel.querySelector(".k0-close")?.addEventListener("click", () => panel.remove());
    panel.querySelector(".k0-settings")?.addEventListener("click", () => {
      openOptionsPage();
    });

    document.body.appendChild(panel);
  }

  function sendMessage(payload) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(payload, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ error: chrome.runtime.lastError.message || "Message failed" });
          return;
        }
        resolve(response || { error: "No response received from scanner." });
      });
    });
  }

  async function runScan(button, context) {
    button.disabled = true;
    const previous = button.textContent;
    button.textContent = "Scanning...";

    try {
      const result = await sendMessage({
        type: "k0ntainment.scan",
        context
      });
      renderPanel(result, context);
    } catch (error) {
      renderPanel({ error: error?.message || "Scan failed unexpectedly." }, context);
    } finally {
      button.disabled = false;
      button.textContent = previous;
    }
  }

  function findGitHubAnchor() {
    const selectors = [
      "#repository-container-header div[data-testid='repository-actions']",
      ".pagehead-actions",
      ".file-navigation"
    ];

    for (const selector of selectors) {
      const el = document.querySelector(selector);
      if (el) {
        return el;
      }
    }
    return null;
  }

  function findGitLabAnchor() {
    const selectors = [
      ".project-action-buttons",
      ".tree-controls",
      ".gl-display-flex.gl-gap-3"
    ];

    for (const selector of selectors) {
      const el = document.querySelector(selector);
      if (el) {
        return el;
      }
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
        if (!host.contains(button)) {
          host.appendChild(button);
        }
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
        if (!host.contains(button)) {
          host.appendChild(button);
        }
        return;
      }
    }

    button.classList.add("k0-floating-fallback");
    if (!document.body.contains(button)) {
      document.body.appendChild(button);
    }
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
      button.textContent = "K0ntmination Scan";
      button.setAttribute("aria-label", "Run K0ntmination Scan");
    }

    attachButton(button, context);
    button.onclick = () => runScan(button, context);

    if (navigationChanged) {
      const panel = document.getElementById(PANEL_ID);
      if (panel) {
        panel.remove();
      }
    }
  }

  ensureUi();
  setInterval(ensureUi, 1200);
})();
