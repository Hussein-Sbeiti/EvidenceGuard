# Downloadable local scanner

The desktop preview packages the scanner and Python together. A user extracts the
download and opens the app; the launcher starts a web server on `127.0.0.1` and
opens its browser UI. No Python, pip, terminal setup, or API key is required on the
end user's machine. First-time AI setup downloads its runtime and model into a
per-user folder. Rule scanning is available while that download runs.

The implemented release selects **base Qwen 2.5 Coder 3B**. No fine-tuned model has
been produced. A trained release will need a tested, published Ollama model with
its exact digest before this release configuration can select it.

## User experience

1. Download the package for your operating system and processor, then extract it.
2. Open `VulnAI-Scanner.exe` on Windows, `VulnAI-Scanner.app` on macOS, or
   `VulnAI-Scanner` on Linux. Keep the whole extracted folder together on Windows
   and Linux; it contains the bundled Python libraries.
3. The browser shows first-time setup, including download progress and retry.
   Existing matching models are reused. If no Ollama service is available, the
   app downloads a pinned official runtime, verifies its SHA-256, and starts it
   locally without installing a system service or drivers.
4. When AI setup finishes, the page opens the scanner automatically. Subsequent
   launches reuse the installed runtime/model and can work offline. AI explanations
   remain an explicit choice when scanning; no source is sent during setup.
5. Use **App setup and quit** in the scanner's sidebar to stop the app. Closing a
   browser tab alone does not stop the local server. A second app launch reopens
   the running instance. Only an Ollama process started by this app is stopped.

The Linux preview archive is about 30 MB. On a clean machine, the pinned Linux
or Windows runtime download is about 1.5–1.6 GB and base Qwen is about 1.9 GB;
the macOS runtime archive is about 188 MB. Extraction and model storage need
additional disk space; plan for at least 10 GB free. Downloads need internet on
first setup. Optional CVE/OSV lookups also need internet; local rule scanning and
local model inference do not require those lookups.

## Packages and current verification

| Target | Package | Verification |
| --- | --- | --- |
| Linux x86-64 | `.tar.gz` containing executable and libraries | Built locally; frozen imports/resources and live server/scan/quit checks passed |
| Windows x86-64 | `.zip` containing `.exe` and libraries | Native build workflow configured; execution and first-run walkthrough pending |
| macOS Apple Silicon | `.zip` containing `.app` | Native build workflow configured; execution and first-run walkthrough pending |
| macOS Intel | Separate `.zip` containing `.app` | Native build workflow configured; execution and first-run walkthrough pending |

Linux ARM and Windows ARM are not included in this preview. The local Linux
artifact was built on glibc 2.43/Python 3.14.4 and is a development-host preview,
not a compatibility claim for older distributions. The workflow uses Ubuntu 22.04
for the Linux release candidate and Python 3.12 on each target runner.

On November 23, 2026, **170 backend tests and 13 frontend tests passed**. The frozen
Linux executable also passed a live test from a temporary working/data directory:
loopback startup, setup page, website assets, a source scan, and graceful quit.
The real pinned Linux runtime archive was downloaded, checksum-verified, and
extracted in `.cache/desktop-runtime-qa/`. Existing Ollama was left running.
Fresh model installation through the setup page and the complete browser click
flow still need a clean-machine walkthrough. Unit tests cover streamed pulls,
incomplete downloads, digest mismatch, archive traversal, retries, and process
ownership. Visual/browser QA and offline cold-start tests remain pending.

These are preview bundles, not signed public installers. Windows code signing,
Apple Developer ID signing/notarization, native first-run QA, and public release
downloads remain release work. The macOS preview build performs ad-hoc signing
for its native smoke check; that does not establish public distribution trust.
No GitHub workflow has been triggered or public release published by this change.

## Files stored on the user's machine

The default app data locations are:

| Operating system | Location |
| --- | --- |
| Windows | `%LOCALAPPDATA%\VulnAIScanner` |
| macOS | `~/Library/Application Support/VulnAIScanner` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/vuln-ai-scanner` |

The folder contains the downloaded runtime, managed model files, setup logs,
instance lock, and advisory cache. An existing Ollama service keeps using its own
model storage. Uploaded source stays in memory; reports are saved only through
the user's export action. The package does not include the developer's `.env`,
keys, training records, evaluation history, or model caches. An absolute
`VULN_SCANNER_DATA_DIR` can override the app data location for development or a
different storage drive.

Managed Ollama binds to loopback and starts with `OLLAMA_NO_CLOUD=1`. Existing
Ollama settings are not rewritten. Model identity is checked against the release
digest before sending a flagged excerpt; an incorrect model is reported rather
than silently substituted. This is a pre-generation observation, not protection
against another local process replacing a model tag during generation.
The server retains its loopback and same-origin API boundaries.

## Build native previews

Development builds need Python 3.12 or newer; end users do not. In a separate
build virtual environment, install:

```bash
python -m pip install -r requirements.txt -r desktop/requirements.txt
python desktop/build.py
python desktop/smoke.py
```

The local build environment used here is `.venv-desktop`. Build output goes to
`.cache/desktop-artifacts/`, with a SHA-256 file alongside the archive. Each app
contains `build-info.json` recording the actual platform, architecture, bundled
package versions, and release configuration. The smoke test uses a temporary data
folder and does not open a browser, download models, train, or alter the user's
Ollama service.

Build each platform on that platform: [PyInstaller does not cross-compile](https://www.pyinstaller.org/en/stable/).
The manual **Build desktop previews** workflow in
[desktop-preview.yml](../.github/workflows/desktop-preview.yml) builds native
Linux, Windows, Apple Silicon, and Intel Mac artifacts using the
[documented GitHub runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
After the code is pushed, run it from GitHub's Actions tab, inspect all checks,
and download the artifacts. It does not automatically publish them as a release.

## Select the eventual trained model

`desktop/release.json` is the release contract. It pins the runtime version,
official archive size/checksum for each target, model name, model digest, and
whether the model is fine-tuned. The current archive checksums came from
[Ollama's official release metadata](https://api.github.com/repos/ollama/ollama/releases/tags/v0.40.17).
Downloads are verified before extracted programs execute. Archive extraction
rejects paths outside the target directory and bounds unpacked size.

For a trained release:

1. Finish data review, training, held-out evaluation, and human remediation review.
2. Export/quantize and test the served artifact, then publish it under a versioned
   Ollama model tag with the appropriate model/source permission records.
3. Update the release model name and exact served digest, mark `trained: true`,
   and rebuild each native package. Keep previous artifacts for rollback.
4. Verify model acquisition, disconnected operation, upgrades, and uninstall on
   clean machines before publishing signed end-user downloads.

Users download the finished inference model; they do not install PyTorch or train
on their machines. Training remains a separate development workflow.
