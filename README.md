# Local Vulnerability Scanner (school-project MVP)

A local web app for uploading source files or folders and checking a small, editable catalog of common risky coding patterns. Findings include a file path, line number, severity, CWE category, explanation, and suggested mitigation.

See [TODO.md](TODO.md) for the project backlog.
See [examples/README.md](examples/README.md) for educational fixtures and website test steps,
and [examples/TEST_RESULTS.md](examples/TEST_RESULTS.md) for observed endpoint results.

## What this version does

- Runs locally with a FastAPI backend and a browser UI.
- Accepts source files and folders; scans supported text files in memory.
- Uses local heuristic rules for examples such as dynamic code execution, unsafe Python deserialization, shell command construction, risky HTML insertion, and hard-coded credentials.
- Does not save uploaded source files or send them to an external service.
- Optionally looks up CVE IDs mentioned in uploaded source using CVE.org and NVD; displays exact CVE-linked Exploit-DB metadata from a local CSV index.
- Includes a manual CVE lookup, persistent SQLite cache, provider throttling, and graceful partial results.

This includes CVE/exploit reference lookups, but is **not yet an AI model or a complete vulnerability scanner**. The rule catalog detects patterns associated with vulnerability classes; it cannot tell whether an application is exploitable, and it can miss issues or report false positives. Suggested fixes are examples, not automatic patches. Do not treat a clean scan as proof of security.

## Run locally

Requires Python 3.10 or newer.

```bash
cd VULN_AI_SCANNER
python3 -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. Stop the development server with `Ctrl+C`.

The upload endpoint limits a scan to 50 files, 512 KB per file, and 5 MB total. Only supported source extensions are scanned. The server is intended for local development; do not expose it to the public internet.

## Free vulnerability intelligence setup

No key is required to start. CVE.org uses `POST https://search.cve.org/search` with a JSON `cveIds` filter. NVD uses `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`. An optional NVD key is sent only in the `apiKey` header.

```bash
cp .env.example .env
# Edit .env locally and set NVD_API_KEY to your key (optional).
python -m app.sync_exploitdb
python -m uvicorn app.main:app --reload --env-file .env
```

`.env` is loaded by the uvicorn command above, not automatically by Python. For the sync command, defaults use `data/files_exploits.csv`; set the `EXPLOITDB_CSV` environment variable if you need another path. Both `.env` and downloaded data/cache directories are ignored by Git. Do not put keys in frontend code, source files, or commits.

The sync command downloads only `files_exploits.csv` from the [official Exploit-DB repository](https://gitlab.com/exploit-database/exploitdb). No API key or account is required. Existing indexes are replaced atomically only after validation. Sync attempts are limited to once per 24 hours, including failures; rerun the command daily to refresh. Lookups read the local index, match its `codes` column by exact CVE ID, and return at most 50 metadata references. Exploit code is neither downloaded nor executed. The index modification time is shown so you can assess freshness. Without a readable index, other sources still work.

Use the **Vulnerability database** form to look up a CVE, or enable the upload checkbox to enrich CVE mentions. The API also supports `GET /api/intelligence/CVE-2021-44228` and the optional multipart field `online_lookup=true` on `POST /api/scan` (default false).

Responses preserve provider provenance, retrieval time, record state (including rejected records), CVSS metrics, CNA affected-version data, and NVD CPE configurations. Applicability always remains `unverified`: neither a CVE mention, a keyword match, nor an exploit reference proves the uploaded application is vulnerable. Dependency manifests/version discovery and automatic applicability evaluation are future work. No AI provider key is needed for this integration.

### Rate limiting and failures

- Each online provider allows at most one outgoing request per 6.1 seconds, even when an NVD key is configured. This deliberately conservative rate does not increase with a key.
- SQLite reservations coordinate processes using the same cache file and survive restarts. Separate machines/cache paths do not share a quota; run a single local instance and avoid other clients using the same public IP/key while scanning.
- Requests during a provider's interval or cooldown return partial results immediately instead of queuing workers. For multiple uncached CVE mentions, later IDs may need a manual lookup after the interval. There is no background queue or automatic retry loop.
- Successful lookups, including empty responses, are cached for 24 hours. On refresh failure, stale data is explicitly labeled; cache entries older than 30 days are removed during successful writes.
- HTTP 403, 429, and 5xx responses cause a cooldown of at least 60 seconds and respect a longer `Retry-After` value (seconds or HTTP date). Network failures/invalid JSON also cause a 60-second cooldown.
- Each provider request has a 12-second socket timeout and a 4 MB response limit. Network calls run outside the async event loop. A missing provider or inaccessible cache does not prevent heuristic results from being returned. Remote services may still enforce stricter policies; rate limiting cannot guarantee against an IP ban.

Reference documentation: [CVE Search API](https://github.com/CVEProject/CVE-Search-API), [NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities), [NVD API guidance](https://nvd.nist.gov/developers/start-here), [SearchSploit manual](https://www.exploit-db.com/searchsploit).

## Test

```bash
python -m unittest discover -s tests -v
```

## How it works

1. The browser uploads selected files (or files from a selected folder) to the local FastAPI server.
2. The server reads supported files into memory and checks each line against the rules in `app/scanner.py`.
3. The UI displays matching lines and rule-based remediation examples.
4. If online lookup is selected, up to three unique CVE IDs mentioned in source are sent to CVE.org and NVD. These references appear separately from heuristic findings. Without CVE mentions, no online request is made.

The UI escapes all returned text before displaying it. The scanner does not execute submitted code.

## Research inspiration

- [VulnLLM-R](https://github.com/ucsb-mlsec/VulnLLM-R) studies reasoning-based detection and project-level analysis. This MVP starts with transparent, inspectable rules instead of claiming the accuracy of a trained model.
- [PatchLM](https://github.com/SmartSecLab/PatchLM) studies model-generated security fixes. This MVP offers rule-based mitigation guidance; it does not automatically rewrite code.
- [CyberGym](https://www.cybergym.io/cybergym/) and [CyberGym-E2E](https://rdi.berkeley.edu/blog/cybergym-e2e/) emphasize evaluation and validating candidate fixes. A future version should add a labeled test set and run checks against patched code.
- The linked [Vulnerability-AI-Scanner repository](https://github.com/Hussein-Sbeiti/Vulnerability-AI-Scanner) currently has no files, so this implementation provides the initial project structure.

## Suggested next steps

1. Add tests for each rule and measure false positives/negatives on safe, intentionally vulnerable sample code.
2. Add dependency-file parsing and affected-version matching. Current CVE lookups provide reference evidence only; they do not discover vulnerable dependencies or infer a CVE from a CWE rule.
3. Add an optional local model (for example, through Ollama) to explain verified rule matches. Keep deterministic findings separate from model-generated suggestions and label model output as unverified.
4. Evaluate proposed fixes with tests and human review; do not automatically apply model-generated patches.

## Git setup and commit commands

The supplied GitHub repository is empty. Once the project folder is initialized as its own repository and connected to your GitHub repo, use:

```bash
cd VULN_AI_SCANNER
git init
git add .gitignore README.md requirements.txt app tests
git commit -m "Build local vulnerability scanner MVP"
git branch -M main
git remote add origin https://github.com/Hussein-Sbeiti/Vulnerability-AI-Scanner.git
git push -u origin main
```

If Git already reports this folder as part of a parent repository, initialize/clone the project into a separate directory first; avoid `git add .` from the home directory.
