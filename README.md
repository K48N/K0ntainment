# K0ntainment

A privacy-first browser extension that evaluates GitHub and GitLab repositories with a transparent, heuristic-based supply-chain risk score.

## What it is

A Manifest V3 browser extension that injects a scan panel directly into GitHub and GitLab repository pages. It samples entry-point files, checks dependency install hooks, inspects CI/CD configuration, and runs entropy analysis on scripts to catch obfuscated payloads, all executed locally in the browser. Results combine into a single K0ntamination Score with severity-tagged findings.

Supply-chain scanning already exists as a paid service in plenty of places, usually running server-side against a repo you have granted it access to. K0ntainment does the opposite on purpose: everything runs in the browser, nothing is sent anywhere, and the scoring logic is visible in the extension's own source instead of hidden behind an API. The tradeoff is that it is a heuristic score, not a guarantee, and it cannot see anything a client-side scan cannot reach.

## How it works

- A content script injects a scan panel into GitHub and GitLab repo pages and adapts to the host page's light or dark theme
- Entry-point files, dependency manifests, and CI/CD configuration are pulled through each platform's API, falling back from `raw.githubusercontent.com` to the Contents API when ad blockers interfere
- Scripts are run through Shannon entropy analysis to flag likely obfuscated or packed payloads
- `package.json` install hooks, custom npm registry redirects, and CI patterns like unpinned Actions or curl-pipe-to-shell are flagged individually
- Contributor history, issue activity, and repository age feed into a separate trust signal
- CodeScore, TrustScore, and HygieneScore combine into one weighted K0ntamination Score, clamped to 0 through 100

## Why it's built this way

- Everything runs client-side because a security scanner asking for elevated repo access is itself a supply-chain risk; there is nothing to exfiltrate if nothing leaves the browser
- The score is a weighted sum with visible deductions rather than an opaque model, so a flagged repo can show exactly which finding caused the drop
- Manifest V3 with a content-script-only design keeps the extension inspectable; there is no background scanning or telemetry to hide
- API tokens are optional and stored locally, used only to raise GitHub and GitLab rate limits and never sent anywhere else

## Shortcomings

- Heuristic only; it is not a substitute for manual code review, and both false positives and false negatives happen with static analysis
- Without an API token, GitHub's 60 requests per hour anonymous limit can leave large repositories partially scanned
- Strict ad blockers can block `api.github.com` outright and need to be allowlisted
- GitHub and GitLab frontend changes can break the panel's injection point until the extension is updated

## Usage

Chrome or Edge:

```
1. Clone or download the repository
2. Open chrome://extensions (or edge://extensions)
3. Enable Developer mode
4. Click "Load unpacked" and select k0ntainment-extension/
```

Firefox:

```
1. Open about:debugging -> This Firefox
2. Click "Load Temporary Add-on"
3. Select k0ntainment-extension/manifest.json
```

Add `githubToken` and/or `gitlabToken` from the extension's options page to raise API rate limits.

## License

MIT
