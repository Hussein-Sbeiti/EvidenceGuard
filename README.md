# Local Vulnerability Scanner (school-project MVP)

A local web app for uploading source files or folders and checking a small, editable catalog of common risky coding patterns. Findings include a file path, line number, severity, CWE category, explanation, and suggested mitigation.

See [TODO.md](TODO.md) for the project backlog.

## What this version does

- Runs locally with a FastAPI backend and a browser UI.
- Accepts source files and folders; scans supported text files in memory.
- Uses local heuristic rules for examples such as dynamic code execution, unsafe Python deserialization, shell command construction, risky HTML insertion, and hard-coded credentials.
- Does not save uploaded source files or send them to an external service.

This is **not yet an AI model, a CVE/exploit database, or a complete vulnerability scanner**. The rule catalog detects patterns associated with vulnerability classes; it cannot tell whether an application is exploitable, and it can miss issues or report false positives. Suggested fixes are examples, not automatic patches. Do not treat a clean scan as proof of security.

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

## Test

```bash
python -m unittest discover -s tests -v
```

## How it works

1. The browser uploads selected files (or files from a selected folder) to the local FastAPI server.
2. The server reads supported files into memory and checks each line against the rules in `app/scanner.py`.
3. The UI displays matching lines and rule-based remediation examples.

The UI escapes all returned text before displaying it. The scanner does not execute submitted code.

## Research inspiration

- [VulnLLM-R](https://github.com/ucsb-mlsec/VulnLLM-R) studies reasoning-based detection and project-level analysis. This MVP starts with transparent, inspectable rules instead of claiming the accuracy of a trained model.
- [PatchLM](https://github.com/SmartSecLab/PatchLM) studies model-generated security fixes. This MVP offers rule-based mitigation guidance; it does not automatically rewrite code.
- [CyberGym](https://www.cybergym.io/cybergym/) and [CyberGym-E2E](https://rdi.berkeley.edu/blog/cybergym-e2e/) emphasize evaluation and validating candidate fixes. A future version should add a labeled test set and run checks against patched code.
- The linked [Vulnerability-AI-Scanner repository](https://github.com/Hussein-Sbeiti/Vulnerability-AI-Scanner) currently has no files, so this implementation provides the initial project structure.

## Suggested next steps

1. Add tests for each rule and measure false positives/negatives on safe, intentionally vulnerable sample code.
2. Add dependency-file scanning against a maintained advisory source such as OSV. Send package names/versions only, never source code, and make the network request explicit to the user.
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
