function statusText(text) {
  const el = document.getElementById("status");
  if (el) {
    el.textContent = text;
  }
}

function obfuscateToken(token) {
  if (!token) return "";
  if (token.length <= 8) return "*".repeat(token.length);
  return `${token.slice(0, 4)}${"*".repeat(Math.max(0, token.length - 8))}${token.slice(-4)}`;
}

function readStorage(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, (result) => resolve(result || {}));
  });
}

function writeStorage(values) {
  return new Promise((resolve) => {
    chrome.storage.local.set(values, () => resolve());
  });
}

async function loadValues() {
  const values = await readStorage(["githubToken", "gitlabToken"]);
  const githubEl = document.getElementById("githubToken");
  const gitlabEl = document.getElementById("gitlabToken");

  if (githubEl && values.githubToken) {
    githubEl.value = values.githubToken;
  }

  if (gitlabEl && values.gitlabToken) {
    gitlabEl.value = values.gitlabToken;
  }

  const ghMask = obfuscateToken(values.githubToken || "");
  const glMask = obfuscateToken(values.gitlabToken || "");
  statusText(`Loaded token values. GitHub: ${ghMask || "none"} | GitLab: ${glMask || "none"}`);
}

async function saveValues() {
  const githubToken = (document.getElementById("githubToken")?.value || "").trim();
  const gitlabToken = (document.getElementById("gitlabToken")?.value || "").trim();

  await writeStorage({ githubToken, gitlabToken });
  statusText("Tokens saved locally in extension storage.");
}

async function clearValues() {
  await writeStorage({ githubToken: "", gitlabToken: "" });

  const githubEl = document.getElementById("githubToken");
  const gitlabEl = document.getElementById("gitlabToken");

  if (githubEl) githubEl.value = "";
  if (gitlabEl) gitlabEl.value = "";

  statusText("Tokens cleared.");
}

function init() {
  document.getElementById("saveBtn")?.addEventListener("click", saveValues);
  document.getElementById("clearBtn")?.addEventListener("click", clearValues);
  loadValues();
}

init();
