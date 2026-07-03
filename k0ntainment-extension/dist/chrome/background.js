const MAX_SCRIPT_SAMPLES = 24;
const MAX_FILE_COUNT_ANALYZED = 10000;
const MAX_FILE_EVIDENCE = 14;
const MAX_GITHUB_AUTHOR_LOOKUPS = 6;

const WEIGHTS = {
  code: 0.55,
  trust: 0.30,
  hygiene: 0.15
};

const SUSPICIOUS_EXTENSIONS = new Set([
  "exe",
  "dll",
  "bat",
  "cmd",
  "ps1",
  "scr",
  "jar",
  "apk",
  "dmg",
  "iso"
]);

const SCRIPT_EXTENSIONS = new Set([
  "js",
  "mjs",
  "cjs",
  "ts",
  "sh",
  "bash",
  "zsh",
  "ps1",
  "py",
  "rb",
  "php"
]);

const DANGEROUS_PATTERNS = [
  { name: "dynamic eval", regex: /\beval\s*\(/i, severity: 12 },
  { name: "runtime Function constructor", regex: /\bFunction\s*\(/i, severity: 8 },
  { name: "base64 decode usage", regex: /\batob\s*\(|base64\.b64decode\s*\(/i, severity: 6 },
  { name: "shell pipe execution", regex: /curl\s+[^\n|]*\|\s*(bash|sh)\b/i, severity: 20 },
  { name: "powershell encoded command", regex: /powershell(?:\.exe)?\s+-enc/i, severity: 20 },
  { name: "scripted web download", regex: /Invoke-WebRequest|wget\s+http|iwr\s+/i, severity: 12 }
];

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || typeof message.type !== "string") {
    return;
  }

  if (message.type === "k0ntainment.openOptions") {
    chrome.runtime.openOptionsPage(() => {
      sendResponse({ ok: !chrome.runtime.lastError });
    });
    return true;
  }

  if (message.type !== "k0ntainment.scan") {
    return;
  }

  scanRepository(message.context)
    .then(sendResponse)
    .catch((error) => {
      sendResponse({
        error: `Scan failed: ${error?.message || "unknown error"}`
      });
    });

  return true;
});

async function scanRepository(context) {
  if (!context || !context.platform) {
    return { error: "No repository context was provided." };
  }

  if (context.platform === "github") {
    return scanGitHub(context);
  }

  if (context.platform === "gitlab") {
    return scanGitLab(context);
  }

  return { error: `Unsupported platform: ${context.platform}` };
}

async function scanGitHub(context) {
  const token = await getStoredToken("githubToken");
  const headers = makeHeaders(token);
  const repoUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}`;

  const repo = await fetchJson(repoUrl, headers);
  const branch = repo.default_branch || "main";

  const treeUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`;
  const treeResponse = await fetchJson(treeUrl, headers);

  const files = (treeResponse.tree || [])
    .filter((item) => item.type === "blob")
    .slice(0, MAX_FILE_COUNT_ANALYZED)
    .map((item) => ({ path: item.path, size: item.size || 0 }));

  const sampleLoader = async (filePath) => {
    const rawUrl = `https://raw.githubusercontent.com/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}/${encodeURIComponent(branch)}/${filePath}`;
    return fetchText(rawUrl, headers);
  };

  const trustSignals = [];
  trustSignals.push(...(await analyzeGitHubAuthorHistory(context, headers)));
  trustSignals.push(...(await analyzeGitHubIssues(context, headers)));

  return runWeightedHeuristics({
    repoName: `${context.owner}/${context.repo}`,
    files,
    sampleLoader,
    trustSignals
  });
}

async function scanGitLab(context) {
  const token = await getStoredToken("gitlabToken");
  const headers = makeHeaders(token);
  const encodedProject = encodeURIComponent(context.projectPath);
  const projectUrl = `https://gitlab.com/api/v4/projects/${encodedProject}`;

  const project = await fetchJson(projectUrl, headers);
  const branch = project.default_branch || "main";

  const files = [];
  let page = 1;

  while (page <= 5 && files.length < MAX_FILE_COUNT_ANALYZED) {
    const treeUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/repository/tree?recursive=true&per_page=100&page=${page}&ref=${encodeURIComponent(branch)}`;
    const pageItems = await fetchJson(treeUrl, headers);
    if (!Array.isArray(pageItems) || pageItems.length === 0) {
      break;
    }

    for (const item of pageItems) {
      if (item.type === "blob") {
        files.push({ path: item.path, size: 0 });
      }
      if (files.length >= MAX_FILE_COUNT_ANALYZED) {
        break;
      }
    }

    if (pageItems.length < 100) {
      break;
    }

    page += 1;
  }

  const sampleLoader = async (filePath) => {
    const fileUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/repository/files/${encodeURIComponent(filePath)}/raw?ref=${encodeURIComponent(branch)}`;
    return fetchText(fileUrl, headers);
  };

  const trustSignals = [];
  trustSignals.push(...(await analyzeGitLabContributors(encodedProject, headers)));
  trustSignals.push(...(await analyzeGitLabIssues(encodedProject, headers)));

  return runWeightedHeuristics({
    repoName: context.projectPath,
    files,
    sampleLoader,
    trustSignals
  });
}

async function analyzeGitHubAuthorHistory(context, headers) {
  const signals = [];

  try {
    const commitsUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}/commits?per_page=20`;
    const commits = await fetchJson(commitsUrl, headers);
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
      if (accounts.length >= MAX_GITHUB_AUTHOR_LOOKUPS) {
        break;
      }
    }

    if (uniqueAuthors.size <= 1) {
      signals.push({ impact: -10, message: "Low maintainer diversity in recent commits (single visible author)." });
    } else if (uniqueAuthors.size >= 4) {
      signals.push({ impact: 8, message: "Healthy maintainer diversity in recent commits." });
    }

    let veryNewAccounts = 0;
    for (const login of accounts) {
      try {
        const user = await fetchJson(`https://api.github.com/users/${encodeURIComponent(login)}`, headers);
        const created = Date.parse(user.created_at || "");
        if (!Number.isNaN(created)) {
          const ageDays = (Date.now() - created) / (1000 * 60 * 60 * 24);
          if (ageDays < 60) {
            veryNewAccounts += 1;
          }
        }
      } catch {
        // Ignore failed user lookups.
      }
    }

    if (veryNewAccounts > 0) {
      signals.push({ impact: -Math.min(18, veryNewAccounts * 5), message: `${veryNewAccounts} recent contributor account(s) appear very new.` });
    }
  } catch {
    signals.push({ impact: -8, message: "Could not fully evaluate author history (API or rate-limit issue)." });
  }

  return signals;
}

async function analyzeGitHubIssues(context, headers) {
  const signals = [];

  try {
    const issuesUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}/issues?state=open&per_page=50`;
    const openIssues = await fetchJson(issuesUrl, headers);
    if (!Array.isArray(openIssues)) {
      return signals;
    }

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
  } catch {
    signals.push({ impact: -5, message: "Could not evaluate open issues (API or rate-limit issue)." });
  }

  return signals;
}

async function analyzeGitLabContributors(encodedProject, headers) {
  const signals = [];

  try {
    const contributorsUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/repository/contributors`;
    const contributors = await fetchJson(contributorsUrl, headers);
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
  } catch {
    signals.push({ impact: -5, message: "Could not evaluate contributor history on GitLab." });
  }

  return signals;
}

async function analyzeGitLabIssues(encodedProject, headers) {
  const signals = [];

  try {
    const issuesUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/issues?state=opened&per_page=50`;
    const issues = await fetchJson(issuesUrl, headers);
    if (!Array.isArray(issues)) {
      return signals;
    }

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
  } catch {
    signals.push({ impact: -5, message: "Could not evaluate GitLab issues." });
  }

  return signals;
}

function getExtension(filePath) {
  const idx = filePath.lastIndexOf(".");
  if (idx < 0 || idx === filePath.length - 1) {
    return "";
  }
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
  if (score < 60) {
    return "High";
  }
  if (score < 80) {
    return "Medium";
  }
  return "Low";
}

async function runWeightedHeuristics({ repoName, files, sampleLoader, trustSignals }) {
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

  const scriptCandidates = files
    .filter((f) => SCRIPT_EXTENSIONS.has(getExtension(f.path)))
    .filter((f) => (f.size || 0) < 180000)
    .slice(0, MAX_SCRIPT_SAMPLES);

  let patternHits = 0;
  let minifiedHits = 0;

  for (const candidate of scriptCandidates) {
    let text = "";
    try {
      text = await sampleLoader(candidate.path);
    } catch {
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
  }

  if (patternHits > 0) {
    findings.push(`Found ${patternHits} potentially dangerous code pattern match(es).`);
  }

  if (minifiedHits > 0) {
    findings.push(`Detected ${minifiedHits} heavily minified script file(s).`);
  }

  if (!hasReadme) {
    hygieneScore -= 24;
    findings.push("No README file found.");
    addEvidence(evidence, -24, "Project metadata weakness (README missing)");
  }

  if (!hasLicense) {
    hygieneScore -= 18;
    findings.push("No LICENSE file found.");
    addEvidence(evidence, -18, "Project metadata weakness (LICENSE missing)");
  }

  if (hasLockfile) {
    hygieneScore += 8;
    findings.push("Dependency lockfile detected.");
    addEvidence(evidence, 8, "Dependency lockfile improves supply-chain repeatability");
  }

  if (files.length > 6000) {
    codeScore -= 6;
    findings.push("Very large repository size may reduce scan confidence.");
    addEvidence(evidence, -6, "Very large repository can hide risky files");
  }

  if (files.length === 0) {
    codeScore = 0;
    trustScore = 0;
    hygieneScore = 0;
    findings.push("Could not enumerate repository files.");
    addEvidence(evidence, -100, "Repository tree could not be read");
  }

  for (const signal of trustSignals || []) {
    if (!signal || typeof signal.impact !== "number" || !signal.message) {
      continue;
    }
    trustScore += signal.impact;
    addEvidence(evidence, signal.impact, signal.message);
  }

  codeScore = clamp(codeScore, 0, 100);
  trustScore = clamp(trustScore, 0, 100);
  hygieneScore = clamp(hygieneScore, 0, 100);

  const weightedScore = (
    codeScore * WEIGHTS.code +
    trustScore * WEIGHTS.trust +
    hygieneScore * WEIGHTS.hygiene
  );

  const sampleCoverage = clamp(scriptCandidates.length / MAX_SCRIPT_SAMPLES, 0, 1);
  const fileCoverage = files.length > 0 ? 1 : 0;
  const trustCoverage = Array.isArray(trustSignals) && trustSignals.length > 0 ? 1 : 0.4;

  const confidence = toInt(
    clamp(
      40 + sampleCoverage * 30 + fileCoverage * 20 + trustCoverage * 10,
      20,
      100
    )
  );

  const score = toInt(clamp(weightedScore, 0, 100));
  const riskLevel = riskLevelFromScore(score);

  const visibleEvidence = evidence.slice(0, 20);
  findings.push("K0ntmination Scanner is an indicator only and every project should be manually reviewed.");

  return {
    repoName,
    k0ntaminationScore: score,
    score,
    confidence,
    riskLevel,
    findings,
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
  const headers = {
    Accept: "application/json"
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  return headers;
}

async function getStoredToken(key) {
  return new Promise((resolve) => {
    chrome.storage.local.get([key], (result) => {
      resolve(result[key] || "");
    });
  });
}

async function fetchJson(url, headers) {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} from ${url}`);
  }
  return response.json();
}

async function fetchText(url, headers) {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} from ${url}`);
  }
  return response.text();
}
const MAX_SCRIPT_SAMPLES = 20;
const MAX_FILE_COUNT_ANALYZED = 10000;
const MAX_FILE_EVIDENCE = 14;
const MAX_GITHUB_AUTHOR_LOOKUPS = 5;

const WEIGHTS = {
  code: 60,
  trust: 25,
  hygiene: 15
};

const SUSPICIOUS_EXTENSIONS = new Set([
  "exe",
  "dll",
  "bat",
  "cmd",
  "ps1",
  "scr",
  "jar",
  "apk",
  "dmg",
  "iso"
]);

const SCRIPT_EXTENSIONS = new Set([
  "js",
  "mjs",
  "cjs",
  "ts",
  "sh",
  "bash",
  "zsh",
  "ps1",
  "py",
  "rb",
  "php"
]);

const DANGEROUS_PATTERNS = [
  { name: "dynamic eval", regex: /\beval\s*\(/i, weight: 8 },
  { name: "runtime Function constructor", regex: /\bFunction\s*\(/i, weight: 5 },
  { name: "base64 decode usage", regex: /\batob\s*\(|base64\.b64decode\s*\(/i, weight: 4 },
  { name: "shell pipe execution", regex: /curl\s+[^\n|]*\|\s*(bash|sh)\b/i, weight: 14 },
  { name: "powershell encoded command", regex: /powershell(?:\.exe)?\s+-enc/i, weight: 14 },
  { name: "scripted web download", regex: /Invoke-WebRequest|wget\s+http|iwr\s+/i, weight: 8 }
];

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || !message.type) {
    return false;
  }

  if (message.type === "k0ntainment.openOptions") {
    chrome.runtime.openOptionsPage(() => {
      if (chrome.runtime.lastError) {
        sendResponse({ ok: false, error: chrome.runtime.lastError.message || "Failed to open settings page." });
        return;
      }
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message.type === "k0ntainment.scan") {
    scanRepository(message.context)
      .then(sendResponse)
      .catch((error) => {
        sendResponse({
          error: `Scan failed: ${error?.message || "unknown error"}`
        });
      });
    return true;
  }

  return false;
});

async function scanRepository(context) {
  if (!context || !context.platform) {
    return { error: "No repository context was provided." };
  }

  if (context.platform === "github") {
    return scanGitHub(context);
  }

  if (context.platform === "gitlab") {
    return scanGitLab(context);
  }

  return { error: `Unsupported platform: ${context.platform}` };
}

async function scanGitHub(context) {
  const token = await getStoredToken("githubToken");
  const headers = makeHeaders(token);
  const repoUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}`;

  const repo = await fetchJson(repoUrl, headers);
  const branch = repo.default_branch || "main";

  const treeUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`;
  const treeResponse = await fetchJson(treeUrl, headers);

  const files = (treeResponse.tree || [])
    .filter((item) => item.type === "blob")
    .slice(0, MAX_FILE_COUNT_ANALYZED)
    .map((item) => ({ path: item.path, size: item.size || 0 }));

  const sampleLoader = async (filePath) => {
    const rawUrl = `https://raw.githubusercontent.com/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}/${encodeURIComponent(branch)}/${filePath}`;
    return fetchText(rawUrl, headers);
  };

  const trustSignals = [];
  const trustDiagnostics = { attempts: 0, failures: 0, lookedUp: 0 };

  const authorData = await analyzeGitHubAuthorHistory(context, headers);
  trustSignals.push(...authorData.signals);
  mergeDiagnostics(trustDiagnostics, authorData.diagnostics);

  const issueData = await analyzeGitHubIssues(context, headers);
  trustSignals.push(...issueData.signals);
  mergeDiagnostics(trustDiagnostics, issueData.diagnostics);

  return runHeuristics({
    repoName: `${context.owner}/${context.repo}`,
    files,
    sampleLoader,
    trustSignals,
    trustDiagnostics
  });
}

async function scanGitLab(context) {
  const token = await getStoredToken("gitlabToken");
  const headers = makeHeaders(token);
  const encodedProject = encodeURIComponent(context.projectPath);
  const projectUrl = `https://gitlab.com/api/v4/projects/${encodedProject}`;

  const project = await fetchJson(projectUrl, headers);
  const branch = project.default_branch || "main";

  const files = [];
  let page = 1;

  while (page <= 5 && files.length < MAX_FILE_COUNT_ANALYZED) {
    const treeUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/repository/tree?recursive=true&per_page=100&page=${page}&ref=${encodeURIComponent(branch)}`;
    const pageItems = await fetchJson(treeUrl, headers);
    if (!Array.isArray(pageItems) || pageItems.length === 0) {
      break;
    }

    for (const item of pageItems) {
      if (item.type === "blob") {
        files.push({ path: item.path, size: 0 });
      }
      if (files.length >= MAX_FILE_COUNT_ANALYZED) {
        break;
      }
    }

    if (pageItems.length < 100) {
      break;
    }

    page += 1;
  }

  const sampleLoader = async (filePath) => {
    const fileUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/repository/files/${encodeURIComponent(filePath)}/raw?ref=${encodeURIComponent(branch)}`;
    return fetchText(fileUrl, headers);
  };

  const trustSignals = [];
  const trustDiagnostics = { attempts: 0, failures: 0, lookedUp: 0 };

  const contributorData = await analyzeGitLabContributors(encodedProject, headers);
  trustSignals.push(...contributorData.signals);
  mergeDiagnostics(trustDiagnostics, contributorData.diagnostics);

  const issueData = await analyzeGitLabIssues(encodedProject, headers);
  trustSignals.push(...issueData.signals);
  mergeDiagnostics(trustDiagnostics, issueData.diagnostics);

  return runHeuristics({
    repoName: context.projectPath,
    files,
    sampleLoader,
    trustSignals,
    trustDiagnostics
  });
}

function mergeDiagnostics(target, incoming) {
  target.attempts += incoming?.attempts || 0;
  target.failures += incoming?.failures || 0;
  target.lookedUp += incoming?.lookedUp || 0;
}

function successResult(signals, diagnostics) {
  return { signals, diagnostics };
}

function safeRisk(points, message) {
  return { points, message };
}

async function analyzeGitHubAuthorHistory(context, headers) {
  const diagnostics = { attempts: 1, failures: 0, lookedUp: 0 };
  const signals = [];

  try {
    const commitsUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}/commits?per_page=20`;
    const commits = await fetchJson(commitsUrl, headers);
    if (!Array.isArray(commits) || commits.length === 0) {
      signals.push(safeRisk(10, "No recent commit history could be evaluated."));
      return successResult(signals, diagnostics);
    }

    const uniqueAuthors = new Set();
    const accounts = [];

    for (const commit of commits) {
      const login = commit?.author?.login;
      if (login && !uniqueAuthors.has(login)) {
        uniqueAuthors.add(login);
        accounts.push(login);
      }
      if (accounts.length >= MAX_GITHUB_AUTHOR_LOOKUPS) {
        break;
      }
    }

    diagnostics.lookedUp += uniqueAuthors.size;

    if (uniqueAuthors.size <= 1) {
      signals.push(safeRisk(6, "Low maintainer diversity in recent commits (single visible author)."));
    }

    let veryNewAccounts = 0;
    for (const login of accounts) {
      diagnostics.attempts += 1;
      try {
        const user = await fetchJson(`https://api.github.com/users/${encodeURIComponent(login)}`, headers);
        const created = Date.parse(user.created_at || "");
        if (!Number.isNaN(created)) {
          const ageDays = (Date.now() - created) / (1000 * 60 * 60 * 24);
          if (ageDays < 60) {
            veryNewAccounts += 1;
          }
        }
      } catch {
        diagnostics.failures += 1;
      }
    }

    if (veryNewAccounts > 0) {
      signals.push(safeRisk(Math.min(12, veryNewAccounts * 4), `${veryNewAccounts} recent contributor account(s) appear very new.`));
    }
  } catch {
    diagnostics.failures += 1;
    signals.push(safeRisk(5, "Could not fully evaluate author history (API or rate-limit issue)."));
  }

  return successResult(signals, diagnostics);
}

async function analyzeGitHubIssues(context, headers) {
  const diagnostics = { attempts: 1, failures: 0, lookedUp: 0 };
  const signals = [];

  try {
    const issuesUrl = `https://api.github.com/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}/issues?state=open&per_page=50`;
    const openIssues = await fetchJson(issuesUrl, headers);
    if (!Array.isArray(openIssues)) {
      return successResult(signals, diagnostics);
    }

    const onlyIssues = openIssues.filter((item) => !item.pull_request);
    diagnostics.lookedUp += onlyIssues.length;

    const securityTagged = onlyIssues.filter((item) => {
      const labels = item.labels || [];
      return labels.some((label) => {
        const name = typeof label === "string" ? label : label?.name || "";
        return /security|malware|supply.?chain|vulnerability/i.test(name);
      });
    });

    if (onlyIssues.length > 25) {
      signals.push(safeRisk(7, `Large open issue count (${onlyIssues.length}) may indicate maintenance risk.`));
    }

    if (securityTagged.length > 0) {
      signals.push(safeRisk(Math.min(16, securityTagged.length * 4), `Security-related open issues found (${securityTagged.length}).`));
    }
  } catch {
    diagnostics.failures += 1;
    signals.push(safeRisk(4, "Could not evaluate open issues (API or rate-limit issue)."));
  }

  return successResult(signals, diagnostics);
}

async function analyzeGitLabContributors(encodedProject, headers) {
  const diagnostics = { attempts: 1, failures: 0, lookedUp: 0 };
  const signals = [];

  try {
    const contributorsUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/repository/contributors`;
    const contributors = await fetchJson(contributorsUrl, headers);

    if (!Array.isArray(contributors) || contributors.length === 0) {
      signals.push(safeRisk(8, "No contributor history data was available from GitLab."));
      return successResult(signals, diagnostics);
    }

    diagnostics.lookedUp += contributors.length;

    if (contributors.length <= 1) {
      signals.push(safeRisk(6, "Low maintainer diversity in visible contributor history."));
    }

    const top = contributors[0];
    if (top && top.commits > 1000 && contributors.length <= 2) {
      signals.push(safeRisk(4, "One contributor dominates commit history; manually verify trust chain."));
    }
  } catch {
    diagnostics.failures += 1;
    signals.push(safeRisk(4, "Could not evaluate contributor history on GitLab."));
  }

  return successResult(signals, diagnostics);
}

async function analyzeGitLabIssues(encodedProject, headers) {
  const diagnostics = { attempts: 1, failures: 0, lookedUp: 0 };
  const signals = [];

  try {
    const issuesUrl = `https://gitlab.com/api/v4/projects/${encodedProject}/issues?state=opened&per_page=50`;
    const issues = await fetchJson(issuesUrl, headers);
    if (!Array.isArray(issues)) {
      return successResult(signals, diagnostics);
    }

    diagnostics.lookedUp += issues.length;

    if (issues.length > 25) {
      signals.push(safeRisk(7, `Large open issue count (${issues.length}) may indicate maintenance risk.`));
    }

    const securityIssues = issues.filter((issue) => {
      const labels = issue.labels || [];
      return labels.some((name) => /security|malware|supply.?chain|vulnerability/i.test(String(name)));
    });

    if (securityIssues.length > 0) {
      signals.push(safeRisk(Math.min(16, securityIssues.length * 4), `Security-related open issues found (${securityIssues.length}).`));
    }
  } catch {
    diagnostics.failures += 1;
    signals.push(safeRisk(4, "Could not evaluate GitLab issues."));
  }

  return successResult(signals, diagnostics);
}

function getExtension(filePath) {
  const idx = filePath.lastIndexOf(".");
  if (idx < 0 || idx === filePath.length - 1) {
    return "";
  }
  return filePath.slice(idx + 1).toLowerCase();
}

function includesAny(filePath, tokens) {
  const lower = filePath.toLowerCase();
  return tokens.some((token) => lower.includes(token));
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function addEvidence(evidence, points, reason, filePath) {
  const suffix = filePath ? ` File: ${filePath}` : "";
  evidence.push(`-${points} ${reason}.${suffix}`);
}

function toRiskLabel(score) {
  if (score < 60) {
    return "High";
  }
  if (score < 80) {
    return "Medium";
  }
  return "Low";
}

function buildConclusion(score, confidence, evidenceCount) {
  if (score >= 85) {
    return `K0ntamination Score is high because weighted risk signals are limited (${evidenceCount} total signals). Confidence is ${confidence}/100 based on scan coverage and API availability.`;
  }
  if (score >= 65) {
    return `K0ntamination Score is moderate because multiple cautionary weighted signals were detected (${evidenceCount} total signals). Confidence is ${confidence}/100.`;
  }
  return `K0ntamination Score is low because several high-impact weighted signals were detected (${evidenceCount} total signals). Confidence is ${confidence}/100.`;
}

async function runHeuristics({ repoName, files, sampleLoader, trustSignals, trustDiagnostics }) {
  const findings = [];
  const evidence = [];

  let codeRiskPoints = 0;
  let trustRiskPoints = 0;
  let hygieneScore = 70;

  const suspiciousBinaries = files.filter((file) => SUSPICIOUS_EXTENSIONS.has(getExtension(file.path)));
  const hasReadme = files.some((f) => /^readme(\.|$)/i.test(f.path.split("/").pop() || ""));
  const hasLicense = files.some((f) => /^license(\.|$)/i.test(f.path.split("/").pop() || ""));
  const hasLockfile = files.some((f) =>
    includesAny(f.path, ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "requirements.txt", "cargo.lock", "go.sum"])
  );

  if (suspiciousBinaries.length > 0) {
    const penalty = Math.min(45, suspiciousBinaries.length * 8);
    codeRiskPoints += penalty;
    findings.push(`Contains ${suspiciousBinaries.length} executable/binary-like file(s).`);

    for (const item of suspiciousBinaries.slice(0, MAX_FILE_EVIDENCE)) {
      addEvidence(evidence, 8, "Executable or binary-like artifact detected", item.path);
    }
  }

  if (!hasReadme) {
    hygieneScore -= 12;
    findings.push("No README file found.");
    addEvidence(evidence, 12, "Project metadata weakness (README missing)");
  }

  if (!hasLicense) {
    hygieneScore -= 10;
    findings.push("No LICENSE file found.");
    addEvidence(evidence, 10, "Project metadata weakness (LICENSE missing)");
  }

  if (hasLockfile) {
    hygieneScore += 10;
    findings.push("Dependency lockfile detected.");
  }

  const scriptCandidates = files
    .filter((f) => SCRIPT_EXTENSIONS.has(getExtension(f.path)))
    .filter((f) => (f.size || 0) < 150000)
    .slice(0, MAX_SCRIPT_SAMPLES);

  let patternHits = 0;
  let minifiedHits = 0;
  let sampledScripts = 0;

  for (const candidate of scriptCandidates) {
    let text = "";
    try {
      text = await sampleLoader(candidate.path);
      sampledScripts += 1;
    } catch {
      continue;
    }

    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.regex.test(text)) {
        codeRiskPoints += pattern.weight;
        patternHits += 1;
        addEvidence(evidence, pattern.weight, `Suspicious pattern (${pattern.name})`, candidate.path);
      }
    }

    const newLineCount = (text.match(/\n/g) || []).length;
    if (text.length > 5000 && newLineCount < 20) {
      minifiedHits += 1;
      codeRiskPoints += 3;
      addEvidence(evidence, 3, "Heavily minified script reduces readability", candidate.path);
    }
  }

  if (patternHits > 0) {
    findings.push(`Found ${patternHits} potentially dangerous code pattern match(es).`);
  }

  if (minifiedHits > 0) {
    findings.push(`Detected ${minifiedHits} heavily minified script file(s).`);
  }

  for (const signal of trustSignals || []) {
    if (!signal || typeof signal.points !== "number" || !signal.message) {
      continue;
    }
    trustRiskPoints += signal.points;
    addEvidence(evidence, signal.points, signal.message);
  }

  if (files.length === 0) {
    codeRiskPoints = 100;
    trustRiskPoints = Math.max(trustRiskPoints, 20);
    hygieneScore = 0;
    findings.push("Could not enumerate repository files.");
    addEvidence(evidence, 100, "Repository tree could not be read");
  }

  if (files.length > 6000) {
    trustRiskPoints += 5;
    findings.push("Very large repository size may reduce scan confidence.");
    addEvidence(evidence, 5, "Very large repository can hide risky files");
  }

  const codeScore = clamp(100 - codeRiskPoints, 0, 100);
  const trustScore = clamp(100 - trustRiskPoints, 0, 100);
  hygieneScore = clamp(hygieneScore, 0, 100);

  const weighted =
    (codeScore * WEIGHTS.code + trustScore * WEIGHTS.trust + hygieneScore * WEIGHTS.hygiene) /
    (WEIGHTS.code + WEIGHTS.trust + WEIGHTS.hygiene);

  const totalScriptCandidates = Math.max(1, scriptCandidates.length);
  const sampleCoverage = sampledScripts / totalScriptCandidates;

  const apiAttempts = Math.max(1, trustDiagnostics?.attempts || 1);
  const apiQuality = 1 - (trustDiagnostics?.failures || 0) / apiAttempts;

  const treeCoverage = files.length > 0 ? 1 : 0;

  const confidence = Math.round(
    clamp(
      100 * (sampleCoverage * 0.45 + clamp(apiQuality, 0, 1) * 0.35 + treeCoverage * 0.2),
      0,
      100
    )
  );

  const score = Math.round(clamp(weighted, 0, 100));
  const riskLevel = toRiskLabel(score);

  const visibleEvidence = evidence.slice(0, 18);
  findings.push("K0ntmination Scanner is an indicator only and every project should be manually reviewed.");

  return {
    repoName,
    k0ntaminationScore: score,
    score,
    riskLevel,
    confidence,
    findings,
    explanation: buildConclusion(score, confidence, visibleEvidence.length),
    evidence: visibleEvidence,
    breakdown: {
      codeWeight: WEIGHTS.code,
      trustWeight: WEIGHTS.trust,
      hygieneWeight: WEIGHTS.hygiene,
      codeScore,
      trustScore,
      hygieneScore
    },
    disclaimer: "Indicator only. This is not a guaranteed malware verdict. Always perform manual review before trusting code."
  };
}

function makeHeaders(token) {
  const headers = {
    Accept: "application/json"
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  return headers;
}

async function getStoredToken(key) {
  return new Promise((resolve) => {
    chrome.storage.local.get([key], (result) => {
      resolve(result[key] || "");
    });
  });
}

async function fetchJson(url, headers) {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} from ${url}`);
  }
  return response.json();
}

async function fetchText(url, headers) {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} from ${url}`);
  }
  return response.text();
}
