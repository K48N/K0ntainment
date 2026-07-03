const MAX_SCRIPT_SAMPLES = 24;
const MAX_FILE_COUNT_ANALYZED = 10000;
const MAX_FILE_EVIDENCE = 14;
const MAX_GITHUB_AUTHOR_LOOKUPS = 6;
const REQUEST_TIMEOUT_MS = 15000;

const activeScans = new Map();
let DEBUG_ENABLED = false;

chrome.storage.local.get(["k0ntainmentDebug"], (result) => {
  DEBUG_ENABLED = result.k0ntainmentDebug === true;
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.k0ntainmentDebug) {
    DEBUG_ENABLED = changes.k0ntainmentDebug.newValue === true;
  }
});

const WEIGHTS = {
  code: 0.55,
  trust: 0.30,
  hygiene: 0.15
};

const SUSPICIOUS_EXTENSIONS = new Set([
  "exe", "dll", "bat", "cmd", "ps1", "scr", "jar", "apk", "dmg", "iso"
]);

const SCRIPT_EXTENSIONS = new Set([
  "js", "mjs", "cjs", "ts", "sh", "bash", "zsh", "ps1", "py", "rb", "php"
]);

// High-priority filenames — always sampled before other script candidates
const PRIORITY_FILENAMES = new Set([
  "index.js", "index.ts", "index.mjs", "main.js", "main.ts",
  "setup.py", "setup.cfg", "install.sh", "install.bash",
  "Makefile", "GNUmakefile", "makefile",
  "build.sh", "build.bash", "configure", "bootstrap.sh"
]);

const DANGEROUS_PATTERNS = [
  { name: "dynamic eval", regex: /\beval\s*\(/i, severity: 12 },
  { name: "runtime Function constructor", regex: /\bFunction\s*\(/i, severity: 8 },
  { name: "base64 decode usage", regex: /\batob\s*\(|base64\.b64decode\s*\(/i, severity: 6 },
  { name: "shell pipe execution", regex: /curl\s+[^\n|]*\|\s*(bash|sh)\b/i, severity: 20 },
  { name: "powershell encoded command", regex: /powershell(?:\.exe)?\s+-enc/i, severity: 20 },
  { name: "scripted web download", regex: /Invoke-WebRequest|wget\s+http|iwr\s+/i, severity: 12 }
];

function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function maxStringEntropy(text) {
  // Extract quoted string literals, check highest entropy
  const matches = text.match(/["'`][A-Za-z0-9+/=]{20,}["'`]/g) || [];
  let max = 0;
  for (const m of matches) {
    const inner = m.slice(1, -1);
    const e = shannonEntropy(inner);
    if (e > max) max = e;
  }
  return max;
}

function addFinding(findings, severity, message) {
  findings.push({ severity, message });
}

function debugLog(message, data) {
  if (!DEBUG_ENABLED) return;
  if (typeof data === "undefined") {
    console.log("[K0ntmination/bg]", message);
    return;
  }
  console.log("[K0ntmination/bg]", message, data);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== "string") return;

  if (message.type === "k0ntainment.openOptions") {
    chrome.runtime.openOptionsPage(() => {
      sendResponse({ ok: !chrome.runtime.lastError });
    });
    return true;
  }

  if (message.type === "k0ntainment.cancelScan") {
    const scanId = String(message.scanId || "");
    const controller = activeScans.get(scanId);

    if (controller) {
      debugLog("Cancel request accepted", { scanId });
      controller.abort();
      activeScans.delete(scanId);
      sendResponse({ ok: true, canceled: true });
      return true;
    }

    sendResponse({ ok: false, canceled: false });
    return true;
  }

  if (message.type !== "k0ntainment.scan") return;

  const tabId = sender?.tab?.id;
  const scanId = String(message.scanId || `scan-${Date.now()}`);
  debugLog("Scan request received", { scanId, tabId, context: message.context });

  const controller = new AbortController();
  activeScans.set(scanId, controller);

  const progress = createProgressReporter(tabId, scanId);

  scanRepository(message.context, progress, controller.signal)
    .then((result) => {
      debugLog("Scan completed", { scanId, score: result?.k0ntaminationScore, error: result?.error });
      sendResponse(result);
    })
    .catch((error) => {
      debugLog("Scan failed", { scanId, error: String(error?.message || error) });
      if (isAbortLikeError(error)) {
        sendResponse({ error: "Scan canceled by user." });
        return;
      }
      sendResponse({ error: `Scan failed: ${String(error?.message || "unknown error")}` });
    })
    .finally(() => {
      debugLog("Scan cleanup", { scanId });
      activeScans.delete(scanId);
    });

  return true;
});

function createProgressReporter(tabId, scanId) {
  let lastLog = 0;

  return (update) => {
    if (!Number.isInteger(tabId) || !scanId) return;

    const now = Date.now();
    if (DEBUG_ENABLED && now - lastLog >= 1200) {
      debugLog("Progress", {
        scanId,
        label: update.label,
        processed: update.processed,
        total: update.total,
        currentPath: update.currentPath
      });
      lastLog = now;
    }

    chrome.tabs.sendMessage(
      tabId,
      {
        type: "k0ntainment.scanProgress",
        scanId,
        label: update.label || "Scanning",
        percent: clamp(Number(update.percent || 0), 0, 100),
        processed: Math.max(0, Number(update.processed || 0)),
        total: Math.max(0, Number(update.total || 0)),
        currentPath: String(update.currentPath || "")
      },
      () => {
        void chrome.runtime.lastError;
      }
    );
  };
}

function throwIfAborted(signal) {
  if (signal?.aborted) {
    throw new DOMException("Scan aborted", "AbortError");
  }
}

function isAbortLikeError(error) {
  const msg = String(error?.message || "").toLowerCase();
  return error?.name === "AbortError" || msg.includes("aborted") || msg.includes("canceled");
}

async function scanRepository(context, progress, signal) {
  throwIfAborted(signal);

  if (!context || !context.platform) {
    return { error: "No repository context was provided." };
  }

  progress({ label: "Preparing scan", percent: 1, processed: 0, total: 0, currentPath: "" });

  if (context.platform === "github") {
    return scanGitHub(context, progress, signal);
  }

  if (context.platform === "gitlab") {
    return scanGitLab(context, progress, signal);
  }

  return { error: `Unsupported platform: ${context.platform}` };
}

async function scanGitHub(context, progress, signal) {
  throwIfAborted(signal);

  const token = await getStoredToken("githubToken");
  const headers = makeHeaders(token);

  progress({ label: "Loading repository", percent: 5, processed: 0, total: 0, currentPath: "" });
  const repoUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}`;
  const repo = await fetchJson(repoUrl, headers, signal);
  const branch = repo.default_branch || "main";

  progress({ label: "Indexing files", percent: 12, processed: 0, total: 0, currentPath: "" });
  const treeUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`;
  const treeResponse = await fetchJson(treeUrl, headers, signal);

  const files = (treeResponse.tree || [])
    .filter((item) => item.type === "blob")
    .slice(0, MAX_FILE_COUNT_ANALYZED)
    .map((item) => ({ path: item.path, size: item.size || 0 }));

  const sampleLoader = async (filePath) => {
    return fetchGitHubFileTextWithFallback({
      owner: context.owner,
      repo: context.repo,
      branch,
      filePath,
      headers,
      signal
    });
  };

  progress({ label: "Analyzing maintainers", percent: 22, processed: 0, total: 0, currentPath: "" });
  const trustSignals = [];
  trustSignals.push(...(await analyzeGitHubAuthorHistory(context, repo, headers, signal)));

  progress({ label: "Analyzing issues", percent: 30, processed: 0, total: 0, currentPath: "" });
  trustSignals.push(...(await analyzeGitHubIssues(context, headers, signal)));

  return runWeightedHeuristics({ repoName: `${context.owner}/${context.repo}`, files, sampleLoader, trustSignals, progress, signal, repoMeta: repo });
}

async function fetchGitHubFileTextWithFallback({ owner, repo, branch, filePath, headers, signal }) {
  const rawUrl = `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(branch)}/${filePath}`;
  try {
    return await fetchText(rawUrl, headers, signal);
  } catch (rawError) {
    if (isAbortLikeError(rawError)) throw rawError;

    debugLog("raw.githubusercontent.com blocked, falling back to contents API", { filePath, error: String(rawError?.message || rawError) });
    const contentsUrl = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodeURIComponent(filePath)}?ref=${encodeURIComponent(branch)}`;
    const json = await fetchJson(contentsUrl, headers, signal);

    const encoded = String(json?.content || "").replace(/\n/g, "");
    if (!encoded) return "";
    return base64ToUtf8(encoded);
  }
}

function base64ToUtf8(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

async function scanGitLab(context, progress, signal) {
  throwIfAborted(signal);

  const token = await getStoredToken("gitlabToken");
  const headers = makeHeaders(token);
  const encodedProject = encodeURIComponent(context.projectPath);

  progress({ label: "Loading repository", percent: 5, processed: 0, total: 0, currentPath: "" });
  const projectUrl = `https://gitlab.com/api/v4/projects/${encodedProject}`;
  const project = await fetchJson(projectUrl, headers, signal);
  const branch = project.default_branch || "main";

  const files = [];
  let page = 1;

  progress({ label: "Indexing files", percent: 12, processed: 0, total: 0, currentPath: "" });
  while (page <= 5 && files.length < MAX_FILE_COUNT_ANALYZED) {
    throwIfAborted(signal);

    const treeUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/repository/tree?recursive=true&per_page=100&page=${page}&ref=${encodeURIComponent(branch)}`;
    const pageItems = await fetchJson(treeUrl, headers, signal);
    if (!Array.isArray(pageItems) || pageItems.length === 0) break;

    for (const item of pageItems) {
      if (item.type === "blob") files.push({ path: item.path, size: 0 });
      if (files.length >= MAX_FILE_COUNT_ANALYZED) break;
    }

    if (pageItems.length < 100) break;
    page += 1;
  }

  const sampleLoader = async (filePath) => {
    const fileUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/repository/files/${encodeURIComponent(filePath)}/raw?ref=${encodeURIComponent(branch)}`;
    return fetchText(fileUrl, headers, signal);
  };

  const trustSignals = [];
  progress({ label: "Analyzing contributors", percent: 22, processed: 0, total: 0, currentPath: "" });
  trustSignals.push(...(await analyzeGitLabContributors(encodedProject, headers, signal)));

  progress({ label: "Analyzing issues", percent: 30, processed: 0, total: 0, currentPath: "" });
  trustSignals.push(...(await analyzeGitLabIssues(encodedProject, headers, signal)));

  return runWeightedHeuristics({ repoName: context.projectPath, files, sampleLoader, trustSignals, progress, signal });
}

async function analyzeGitHubAuthorHistory(context, repoMeta, headers, signal) {
  const signals = [];

  try {
    throwIfAborted(signal);
    const commitsUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}/commits?per_page=20`;
    const commits = await fetchJson(commitsUrl, headers, signal);
    if (!Array.isArray(commits) || commits.length === 0) {
      signals.push({ impact: -18, message: "No recent commit history could be evaluated." });
      return signals;
    }

    const uniqueAuthors = new Set();
    const accounts = [];

    for (const commit of commits) {
      const login = commit?.author?.login;
      if (login && !uniqueAuthors.has(login)) {
        uniqueAuthors.add(login);
        accounts.push(login);
      }
      if (accounts.length >= MAX_GITHUB_AUTHOR_LOOKUPS) break;
    }

    if (uniqueAuthors.size <= 1) {
      signals.push({ impact: -10, message: "Low maintainer diversity in recent commits (single visible author)." });
    } else if (uniqueAuthors.size >= 4) {
      signals.push({ impact: 8, message: "Healthy maintainer diversity in recent commits." });
    }

    let veryNewAccounts = 0;
    for (const login of accounts) {
      throwIfAborted(signal);
      try {
        const user = await fetchJson(`https://api.github.com/users/${encodeURIComponent(login)}`, headers, signal);
        const created = Date.parse(user.created_at || "");
        if (!Number.isNaN(created)) {
          const ageDays = (Date.now() - created) / (1000 * 60 * 60 * 24);
          if (ageDays < 60) veryNewAccounts += 1;
        }
      } catch {
        // Continue.
      }
    }

    if (veryNewAccounts > 0) {
      signals.push({ impact: -Math.min(18, veryNewAccounts * 5), message: `${veryNewAccounts} recent contributor account(s) appear very new.` });
    }
  } catch (error) {
    if (isAbortLikeError(error)) throw error;
    signals.push({ impact: -8, message: "Could not fully evaluate author history (API or rate-limit issue)." });
  }

  // Repo metadata signals from /repos response
  try {
    if (repoMeta) {
      const created = Date.parse(repoMeta.created_at || "");
      if (!Number.isNaN(created)) {
        const ageDays = (Date.now() - created) / (1000 * 60 * 60 * 24);
        if (ageDays < 30) {
          signals.push({ impact: -18, message: "Repository was created less than 30 days ago." });
        } else if (ageDays < 90) {
          signals.push({ impact: -8, message: "Repository is less than 90 days old." });
        }
      }
      if (typeof repoMeta.stargazers_count === "number" && repoMeta.stargazers_count === 0
        && typeof repoMeta.forks_count === "number" && repoMeta.forks_count === 0) {
        signals.push({ impact: -6, message: "Repository has zero stars and zero forks." });
      }
      if (repoMeta.fork === true) {
        signals.push({ impact: -4, message: "Repository is a fork — verify origin and intent." });
      }
    }
  } catch {
    // Non-critical.
  }

  return signals;
}

async function analyzeGitHubIssues(context, headers, signal) {
  const signals = [];

  try {
    throwIfAborted(signal);
    const issuesUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}/issues?state=open&per_page=50`;
    const openIssues = await fetchJson(issuesUrl, headers, signal);
    if (!Array.isArray(openIssues)) return signals;

    const onlyIssues = openIssues.filter((item) => !item.pull_request);
    const securityTagged = onlyIssues.filter((item) => {
      const labels = item.labels || [];
      return labels.some((label) => {
        const name = typeof label === "string" ? label : label?.name || "";
        return /security|malware|supply.?chain|vulnerability/i.test(name);
      });
    });

    if (onlyIssues.length > 40) {
      signals.push({ impact: -12, message: `High open issue volume (${onlyIssues.length}) may indicate maintenance risk.` });
    } else if (onlyIssues.length < 8) {
      signals.push({ impact: 6, message: "Low open issue volume indicates likely active maintenance." });
    }

    if (securityTagged.length > 0) {
      signals.push({ impact: -Math.min(22, securityTagged.length * 5), message: `Security-related open issues found (${securityTagged.length}).` });
    }
  } catch (error) {
    if (isAbortLikeError(error)) throw error;
    signals.push({ impact: -5, message: "Could not evaluate open issues (API or rate-limit issue)." });
  }

  return signals;
}

async function analyzeGitLabContributors(encodedProject, headers, signal) {
  const signals = [];

  try {
    throwIfAborted(signal);
    const contributorsUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/repository/contributors`;
    const contributors = await fetchJson(contributorsUrl, headers, signal);
    if (!Array.isArray(contributors) || contributors.length === 0) {
      signals.push({ impact: -14, message: "No contributor history data was available from GitLab." });
      return signals;
    }

    if (contributors.length <= 1) {
      signals.push({ impact: -8, message: "Low maintainer diversity in visible contributor history." });
    } else if (contributors.length >= 4) {
      signals.push({ impact: 6, message: "Multiple maintainers observed in contributor history." });
    }

    const top = contributors[0];
    if (top && top.commits > 1000 && contributors.length <= 2) {
      signals.push({ impact: -6, message: "One contributor dominates commit history; manually verify trust chain." });
    }
  } catch (error) {
    if (isAbortLikeError(error)) throw error;
    signals.push({ impact: -5, message: "Could not evaluate contributor history on GitLab." });
  }

  return signals;
}

async function analyzeGitLabIssues(encodedProject, headers, signal) {
  const signals = [];

  try {
    throwIfAborted(signal);
    const issuesUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/issues?state=opened&per_page=50`;
    const issues = await fetchJson(issuesUrl, headers, signal);
    if (!Array.isArray(issues)) return signals;

    if (issues.length > 40) {
      signals.push({ impact: -12, message: `High open issue volume (${issues.length}) may indicate maintenance risk.` });
    } else if (issues.length < 8) {
      signals.push({ impact: 6, message: "Low open issue volume indicates likely active maintenance." });
    }

    const securityIssues = issues.filter((issue) => {
      const labels = issue.labels || [];
      return labels.some((name) => /security|malware|supply.?chain|vulnerability/i.test(String(name)));
    });

    if (securityIssues.length > 0) {
      signals.push({ impact: -Math.min(22, securityIssues.length * 5), message: `Security-related open issues found (${securityIssues.length}).` });
    }
  } catch (error) {
    if (isAbortLikeError(error)) throw error;
    signals.push({ impact: -5, message: "Could not evaluate GitLab issues." });
  }

  return signals;
}

function getExtension(filePath) {
  const idx = filePath.lastIndexOf(".");
  if (idx < 0 || idx === filePath.length - 1) return "";
  return filePath.slice(idx + 1).toLowerCase();
}

function includesAny(filePath, tokens) {
  const lower = filePath.toLowerCase();
  return tokens.some((token) => lower.includes(token));
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function toInt(value) {
  return Math.round(value);
}

function addEvidence(evidence, change, reason, filePath) {
  const sign = change >= 0 ? "+" : "";
  const suffix = filePath ? ` File: ${filePath}` : "";
  evidence.push(`${sign}${change} ${reason}.${suffix}`);
}

function buildConclusion(score, confidence, evidenceCount) {
  if (score >= 85) {
    return `K0ntamination Score is high because few risky indicators were detected. Confidence ${confidence}/100 from ${evidenceCount} weighted signals.`;
  }
  if (score >= 65) {
    return `K0ntamination Score is moderate because cautionary indicators were detected. Confidence ${confidence}/100 from ${evidenceCount} weighted signals.`;
  }
  return `K0ntamination Score is low because multiple high-risk indicators were detected. Confidence ${confidence}/100 from ${evidenceCount} weighted signals.`;
}

function riskLevelFromScore(score) {
  if (score < 60) return "High";
  if (score < 80) return "Medium";
  return "Low";
}

async function runWeightedHeuristics({ repoName, files, sampleLoader, trustSignals, progress, signal, repoMeta }) {
  const findings = [];
  const evidence = [];

  let codeScore = 100;
  let trustScore = 100;
  let hygieneScore = 100;

  const suspiciousBinaries = files.filter((file) => SUSPICIOUS_EXTENSIONS.has(getExtension(file.path)));
  const hasReadme = files.some((f) => /^readme(\.|$)/i.test(f.path.split("/").pop() || ""));
  const hasLicense = files.some((f) => /^license(\.|$)/i.test(f.path.split("/").pop() || ""));
  const hasLockfile = files.some((f) => includesAny(f.path, ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "requirements.txt", "cargo.lock", "go.sum"]));

  if (suspiciousBinaries.length > 0) {
    const penalty = Math.min(60, suspiciousBinaries.length * 10);
    codeScore -= penalty;
    findings.push(`Contains ${suspiciousBinaries.length} executable/binary-like file(s).`);

    for (const item of suspiciousBinaries.slice(0, MAX_FILE_EVIDENCE)) {
      addEvidence(evidence, -10, "Executable or binary-like artifact detected", item.path);
    }
  }

  // Prioritize root-level high-signal files so quota is spent wisely
  const allScriptFiles = files
    .filter((f) => SCRIPT_EXTENSIONS.has(getExtension(f.path)))
    .filter((f) => (f.size || 0) < 180000);

  const priorityFiles = allScriptFiles.filter((f) => {
    const name = f.path.split("/").pop() || "";
    return PRIORITY_FILENAMES.has(name) || f.path.split("/").length === 1;
  });
  const otherFiles = allScriptFiles.filter((f) => {
    const name = f.path.split("/").pop() || "";
    return !PRIORITY_FILENAMES.has(name) && f.path.split("/").length > 1;
  });

  const scriptCandidates = [...priorityFiles, ...otherFiles].slice(0, MAX_SCRIPT_SAMPLES);

  let patternHits = 0;
  let minifiedHits = 0;
  let processedScripts = 0;
  const totalScripts = scriptCandidates.length;

  progress({ label: "Scanning files", percent: totalScripts > 0 ? 35 : 70, processed: 0, total: totalScripts, currentPath: "" });

  for (const candidate of scriptCandidates) {
    throwIfAborted(signal);

    let text = "";
    try {
      text = await sampleLoader(candidate.path);
    } catch (error) {
      if (isAbortLikeError(error)) throw error;
      processedScripts += 1;
      const failedPercent = 35 + Math.round((processedScripts / Math.max(1, totalScripts)) * 35);
      progress({ label: "Scanning files", percent: failedPercent, processed: processedScripts, total: totalScripts, currentPath: candidate.path });
      continue;
    }

    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.regex.test(text)) {
        codeScore -= pattern.severity;
        patternHits += 1;
        addEvidence(evidence, -pattern.severity, `Suspicious pattern (${pattern.name})`, candidate.path);
      }
    }

    const newLineCount = (text.match(/\n/g) || []).length;
    if (text.length > 5000 && newLineCount < 20) {
      minifiedHits += 1;
      codeScore -= 4;
      addEvidence(evidence, -4, "Heavily minified script reduces readability", candidate.path);
    }

    // Entropy check — high-entropy string literals suggest encoded/obfuscated payloads
    const topEntropy = maxStringEntropy(text);
    if (topEntropy > 5.5) {
      codeScore -= 8;
      addEvidence(evidence, -8, `High-entropy string literal detected (entropy ${topEntropy.toFixed(2)})`, candidate.path);
    }

    processedScripts += 1;
    const percent = 35 + Math.round((processedScripts / Math.max(1, totalScripts)) * 35);
    progress({ label: "Scanning files", percent, processed: processedScripts, total: totalScripts, currentPath: candidate.path });
  }

  // package.json install hook scan
  const pkgJsonFile = files.find((f) => f.path === "package.json" || f.path.endsWith("/package.json"));
  if (pkgJsonFile) {
    try {
      const pkgText = await sampleLoader(pkgJsonFile.path);
      throwIfAborted(signal);
      const pkg = JSON.parse(pkgText);
      const dangerousHooks = ["preinstall", "postinstall", "prepare", "prepack"];
      const foundHooks = dangerousHooks.filter((h) => typeof pkg?.scripts?.[h] === "string");
      if (foundHooks.length > 0) {
        codeScore -= Math.min(35, foundHooks.length * 18);
        addFinding(findings, "Critical", `package.json defines install hook(s): ${foundHooks.join(", ")}`);
        for (const h of foundHooks) {
          addEvidence(evidence, -18, `npm install hook '${h}' executes code on install`, pkgJsonFile.path);
        }
      }
    } catch (error) {
      if (isAbortLikeError(error)) throw error;
    }
  }

  // .npmrc custom registry scan
  const npmrcFile = files.find((f) => f.path === ".npmrc" || f.path.endsWith("/.npmrc"));
  if (npmrcFile) {
    try {
      const npmrcText = await sampleLoader(npmrcFile.path);
      throwIfAborted(signal);
      const hasCustomRegistry = /registry\s*=/.test(npmrcText) &&
        !/registry\.npmjs\.org/.test(npmrcText);
      if (hasCustomRegistry) {
        codeScore -= 22;
        addFinding(findings, "High", ".npmrc redirects installs to a non-default registry.");
        addEvidence(evidence, -22, "Custom npm registry in .npmrc may redirect installs to an untrusted host", npmrcFile.path);
      }
    } catch (error) {
      if (isAbortLikeError(error)) throw error;
    }
  }

  // GitHub Actions workflow scan
  const workflowFiles = files.filter((f) =>
    f.path.startsWith(".github/workflows/") && /\.ya?ml$/.test(f.path)
  ).slice(0, 6);
  for (const wf of workflowFiles) {
    throwIfAborted(signal);
    try {
      const wfText = await sampleLoader(wf.path);
      throwIfAborted(signal);
      const curlPipe = /curl[^\n]*\|\s*(ba)?sh/i.test(wfText);
      const unpinnedAction = /uses:\s+[\w-]+\/[\w-]+@(?!\b[0-9a-f]{40}\b)[^\s]+/i.test(wfText);
      const secretsToEnv = /env:\s*[\s\S]{0,40}secrets\./i.test(wfText);
      if (curlPipe) {
        codeScore -= 20;
        addFinding(findings, "Critical", `GitHub Actions workflow uses curl pipe-to-shell.`);
        addEvidence(evidence, -20, "GitHub Actions workflow pipes curl output to shell", wf.path);
      }
      if (unpinnedAction) {
        codeScore -= 8;
        addFinding(findings, "Medium", `GitHub Actions workflow uses unpinned third-party action.`);
        addEvidence(evidence, -8, "Unpinned third-party action reference (use full SHA instead of tag)", wf.path);
      }
      if (secretsToEnv) {
        codeScore -= 6;
        addFinding(findings, "Medium", `GitHub Actions workflow exposes secrets in environment.`);
        addEvidence(evidence, -6, "Secrets forwarded to environment in workflow", wf.path);
      }
    } catch (error) {
      if (isAbortLikeError(error)) throw error;
    }
  }

  if (patternHits > 0) addFinding(findings, "High", `Found ${patternHits} potentially dangerous code pattern match(es).`);
  if (minifiedHits > 0) addFinding(findings, "Info", `Detected ${minifiedHits} heavily minified script file(s).`);

  if (!hasReadme) {
    hygieneScore -= 24;
    addFinding(findings, "Medium", "No README file found.");
    addEvidence(evidence, -24, "Project metadata weakness (README missing)");
  }

  if (!hasLicense) {
    hygieneScore -= 18;
    addFinding(findings, "Medium", "No LICENSE file found.");
    addEvidence(evidence, -18, "Project metadata weakness (LICENSE missing)");
  }

  if (hasLockfile) {
    hygieneScore += 8;
    addFinding(findings, "Info", "Dependency lockfile detected.");
    addEvidence(evidence, 8, "Dependency lockfile improves supply-chain repeatability");
  }

  if (files.length > 6000) {
    codeScore -= 6;
    addFinding(findings, "Info", "Very large repository size may reduce scan confidence.");
    addEvidence(evidence, -6, "Very large repository can hide risky files");
  }

  if (files.length === 0) {
    codeScore = 0;
    trustScore = 0;
    hygieneScore = 0;
    addFinding(findings, "High", "Could not enumerate repository files.");
    addEvidence(evidence, -100, "Repository tree could not be read");
  }

  for (const signalEntry of trustSignals || []) {
    if (!signalEntry || typeof signalEntry.impact !== "number" || !signalEntry.message) continue;
    trustScore += signalEntry.impact;
    addEvidence(evidence, signalEntry.impact, signalEntry.message);
  }

  progress({ label: "Finalizing score", percent: 95, processed: processedScripts, total: totalScripts, currentPath: "" });

  codeScore = clamp(codeScore, 0, 100);
  trustScore = clamp(trustScore, 0, 100);
  hygieneScore = clamp(hygieneScore, 0, 100);

  const weightedScore = codeScore * WEIGHTS.code + trustScore * WEIGHTS.trust + hygieneScore * WEIGHTS.hygiene;

  const sampleCoverage = clamp(scriptCandidates.length / MAX_SCRIPT_SAMPLES, 0, 1);
  const fileCoverage = files.length > 0 ? 1 : 0;
  const trustCoverage = Array.isArray(trustSignals) && trustSignals.length > 0 ? 1 : 0.4;

  const confidence = toInt(clamp(40 + sampleCoverage * 30 + fileCoverage * 20 + trustCoverage * 10, 20, 100));
  const score = toInt(clamp(weightedScore, 0, 100));
  const riskLevel = riskLevelFromScore(score);

  const visibleEvidence = evidence.slice(0, 20);

  progress({ label: "Complete", percent: 100, processed: totalScripts, total: totalScripts, currentPath: "" });

  return {
    repoName,
    k0ntaminationScore: score,
    score,
    confidence,
    riskLevel,
    findings,
    scannedAt: Date.now(),
    explanation: buildConclusion(score, confidence, visibleEvidence.length),
    evidence: visibleEvidence,
    breakdown: {
      codeScore: toInt(codeScore),
      trustScore: toInt(trustScore),
      hygieneScore: toInt(hygieneScore),
      codeWeight: toInt(WEIGHTS.code * 100),
      trustWeight: toInt(WEIGHTS.trust * 100),
      hygieneWeight: toInt(WEIGHTS.hygiene * 100)
    },
    disclaimer: "Indicator only. This is not a guaranteed malware verdict. Always perform manual review before trusting code."
  };
}

function makeHeaders(token) {
  const headers = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function getStoredToken(key) {
  return new Promise((resolve) => {
    chrome.storage.local.get([key], (result) => resolve(result[key] || ""));
  });
}

function normalizeFetchError(error, url) {
  const message = String(error?.message || error || "Unknown network error");

  if (message.includes("The operation was aborted") || message.includes("aborted")) {
    return "Scan canceled by user.";
  }

  if (message.includes("Failed to fetch") || message.includes("NetworkError")) {
    return `Network request blocked or failed for ${url}. Check blocker/privacy extensions and API token settings.`;
  }

  return `${message} (${url})`;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS, signal) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let abortHandler = null;
  if (signal) {
    abortHandler = () => controller.abort();
    signal.addEventListener("abort", abortHandler, { once: true });
  }

  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    throw new Error(normalizeFetchError(error, url));
  } finally {
    clearTimeout(timeoutId);
    if (signal && abortHandler) signal.removeEventListener("abort", abortHandler);
  }
}

async function fetchJson(url, headers, signal) {
  const response = await fetchWithTimeout(url, { headers }, REQUEST_TIMEOUT_MS, signal);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText} from ${url}`);
  return response.json();
}

async function fetchText(url, headers, signal) {
  const response = await fetchWithTimeout(url, { headers }, REQUEST_TIMEOUT_MS, signal);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText} from ${url}`);
  return response.text();
}
