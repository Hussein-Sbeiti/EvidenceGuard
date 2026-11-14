# Local Vulnerability Scanner (school-project MVP)

A local web app for uploading source files or folders and checking a small, editable catalog of common risky coding patterns. Findings include a file path, line number, severity, CWE category, explanation, and suggested mitigation.

See [TODO.md](TODO.md) for the project backlog.
See [examples/README.md](examples/README.md) for educational fixtures and website test steps,
and [examples/TEST_RESULTS.md](examples/TEST_RESULTS.md) for observed endpoint results.

## What this version does

- Runs locally with a FastAPI backend and a browser UI.
- Uses a slate sidebar with separate source scan, results, and CVE database views; navigation moves above the content on smaller screens.
- Accepts source files and folders; scans supported text files in memory.
- Shows upload limits and reasons for skipped files, supports severity filtering, and downloads the latest completed scan as JSON or a readable text report.
- Uses local heuristic rules for examples such as dynamic code execution, unsafe Python deserialization, shell command construction, risky HTML insertion, hard-coded credentials, and dynamically constructed SQL queries.
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

The upload endpoint limits a scan to 50 files, 512 KB per file, and 5 MB total file data (including skipped files). Streaming multipart limits reject oversized data before file buffers can roll to disk, and a separate raw-body cap allows 256 KB for multipart overhead. Only supported UTF-8 text source files are scanned. The server requires loopback connections and local Host headers; API requests from other origins are rejected. Keep the server bound to `127.0.0.1`. See [upload review](docs/UPLOAD_REVIEW.md) for tested boundaries and limitations.

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

Optional frontend checks require Node.js (the application itself does not need Node):

```bash
node tests/frontend/ui-utils.test.mjs
node --check app/static/app.js
```

These checks cover file selection limits and readable report content. Visual layout, keyboard interactions, and browser download behavior still need a manual browser walkthrough.

## Rule evaluation

Run the reviewed synthetic corpus without executing its code or calling any services:

```bash
python -m app.evaluate --output-dir evaluation/results
```

[Evaluation notes](evaluation/README.md) describe 65 agent-reviewed synthetic cases across ten rules.
The [current report](evaluation/results/report.md) records every expected/actual rule set, module
hashes, and parser versions. The original [regex baseline](evaluation/baseline/report.md) and
[pre-SQL report](evaluation/pre-sql/report.md) are preserved. SQL detection expands the catalog;
the SQL diagnostic now expects the new rule instead of treating that weakness as unsupported.
All 65 labels are explicitly awaiting [independent review](evaluation/INDEPENDENT_REVIEW.md).
Passing these cases does not estimate real-world accuracy. AI work remains deferred.

## How it works

1. The browser uploads selected files (or files from a selected folder) to the local FastAPI server.
2. The server reads supported files into memory. Python rules inspect the syntax tree; JavaScript-family rules inspect Tree-sitter syntax trees for JS, JSX, TS, and TSX. Other supported languages retain the credential regex heuristic.
3. The UI displays matching lines and rule-based remediation examples.
4. If online lookup is selected, up to three unique CVE IDs mentioned in source are sent to CVE.org and NVD. These references appear separately from heuristic findings. Without CVE mentions, no online request is made.

The UI escapes all returned text before displaying it. The scanner does not execute submitted code.

Python analysis uses the standard-library AST to identify actual calls, literal credential assignments, direct import aliases, and explicit YAML loader arguments across lines. It accounts for common lexical name shadowing, with sequential top-level assignment/import handling and match-pattern bindings. It does not fully resolve arbitrary reassignment aliases, conditional imports, wrappers, or dynamic imports. Conventional names such as `yaml`, `pickle`, and `eval` are assumed when snippets omit imports. Ambiguous/rebound names can be missed. Syntax that cannot be fully parsed uses a best-effort token-based fallback; a per-file warning appears in the UI and both report formats so partial analysis is visible. Python syntax support follows the Python version running the scanner.

JavaScript, JSX, TypeScript, and TSX now use [Tree-sitter](https://github.com/tree-sitter/py-tree-sitter) with the official [JavaScript](https://github.com/tree-sitter/tree-sitter-javascript) and [TypeScript/TSX](https://github.com/tree-sitter/tree-sitter-typescript) grammars. Syntax nodes distinguish calls from JSX text, strings, and regex literals, including statement-position regex ambiguity. The rules handle common lexical shadowing, constant computed DOM properties, template expressions, and type assertions. Parsing a complete syntax tree does not provide complete semantic or taint analysis: dynamic properties, assignment aliases, cross-file bindings, and unusual TypeScript constructs can still be missed. Syntax errors yield a visible parser-recovery warning. Other languages retain the line-based credential heuristic. Evidence snippets may span multiple lines, up to 300 characters.

The Python **PY-SQL-INJECTION / CWE-89** rule follows local query variables through direct assignments, aliases, simple branches/loops, and overwrites into `.execute()`, `.executemany()`, and `.executescript()` calls. It flags known SQL fragments combined with unknown values using f-strings, concatenation, `%`, or `.format()`. Static queries with separately bound values are not flagged; passing parameters alongside an already-interpolated query does not suppress the finding. This is a candidate construction heuristic, not proof that a value is attacker-controlled. It does not follow query values across function calls, ORM/custom builder APIs, heap attributes, or arbitrary dynamic SQL without a recognizable SQL fragment. Placeholder syntax depends on the database driver; the example fix uses sqlite3 `?` placeholders. See the [Python sqlite3 parameter binding documentation](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries).

Use the sidebar to move between **Scan source**, **Scan results**, and **CVE database**. A completed scan opens its results automatically. Results include a file list with skip reasons, severity filtering, named CWE categories, and separate unverified CVE references. **Download JSON** exports the full result; **Download report** exports a readable `.txt` file, including provenance and provider warnings. Exports include flagged source snippets and remain local until you choose to share them. Selecting new files clears the previous report; results are kept only in the page's memory and are lost when it reloads.

The browser reads limits and supported extensions from `GET /api/config`, and the server independently enforces limits. Unsupported files and files above the per-file limit are listed as skipped before upload. Too many supported files or an oversized batch blocks scanning until you select fewer files. Binary or invalid UTF-8 content detected on the server is listed with skip reasons. An entirely unsupported/binary/invalid-encoding upload returns a readable error with per-file reasons. UTF-8 BOMs are accepted. Browser-based responsive and keyboard checks remain pending in [BROWSER_QA.md](docs/BROWSER_QA.md).

## Research inspiration

- [VulnLLM-R](https://github.com/ucsb-mlsec/VulnLLM-R) studies reasoning-based detection and project-level analysis. This MVP starts with transparent, inspectable rules instead of claiming the accuracy of a trained model.
- [PatchLM](https://github.com/SmartSecLab/PatchLM) studies model-generated security fixes. This MVP offers rule-based mitigation guidance; it does not automatically rewrite code.
- [CyberGym](https://www.cybergym.io/cybergym/) and [CyberGym-E2E](https://rdi.berkeley.edu/blog/cybergym-e2e/) emphasize evaluation and validating candidate fixes. A future version should add a labeled test set and run checks against patched code.
- Project repository: [Vulnerability-AI-Scanner](https://github.com/Hussein-Sbeiti/Vulnerability-AI-Scanner).

## Suggested next steps

1. Obtain independent review of the expanded corpus and complete browser responsive/keyboard checks.
2. Add dependency-file parsing and affected-version matching. Current CVE lookups provide reference evidence only; they do not discover vulnerable dependencies or infer a CVE from a CWE rule.
3. Add an optional local model (for example, through Ollama) to explain verified rule matches. Keep deterministic findings separate from model-generated suggestions and label model output as unverified.
4. Evaluate proposed fixes with tests and human review; do not automatically apply model-generated patches.

## Git setup and commit commands

Review and push project changes from this repository:

```bash
git status
git diff
git add .gitignore .env.example README.md TODO.md requirements.txt app tests examples evaluation docs
git commit -m "Improve scanner analysis and upload boundaries"
git push origin main
```

The real `.env`, downloaded database, cache, and virtual environment are ignored by Git.
