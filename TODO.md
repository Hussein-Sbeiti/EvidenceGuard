# Project To-do List

Latest recorded verification: **179 backend tests and 13 frontend tests pass** (November 23, 2026; backend tests outside the sandbox). The frozen Linux desktop preview passed live server, resource, scan, and quit checks. Mac upload validation has nine local tests; native Mac execution is pending. The expanded evaluation matches all **65 agent-reviewed labels**; independent sign-off is still pending. Fixture results do not establish real-world accuracy.

Dependency manifest inventory and opt-in OSV checks are implemented. Remaining work includes additional manifest formats and independent applicability/upgrade review. Browser verification and independent label review can proceed separately. Optional Ollama explanations are now integrated at user request; remaining non-AI review work is still open.

## Scanner quality

- [x] Add positive and negative test cases for every detection rule, including line numbers and language boundaries.
- [x] Review the original 39 synthetic examples and preserve the historical results in evaluation/baseline/ and evaluation/pre-sql/; current expanded results are in evaluation/results/report.md.
- [x] Add clear CWE names and explanations for every rule.
- [x] Fix the original five false positives and four missed matches involving comments, strings, direct import aliases, and multiline code; preserve the baseline for comparison.
- [x] Add per-file partial-analysis warnings for Python syntax fallback, including UI and exported reports.
- [x] Expand evaluation to 65 agent-reviewed cases with Python flow/binding edges and full Tree-sitter JavaScript/TypeScript/JSX/TSX parsing (including regex ambiguity).
- [ ] Have a separate reviewer check the 65 labels, record corrections and reviewer identifiers, and regenerate evaluation reports after sign-off; checklist in evaluation/INDEPENDENT_REVIEW.md.
- [x] Add Python SQL injection construction detection, including local value flow; the login example now matches PY-SQL-INJECTION at line 18.

## Useful capabilities

- [x] Integrate CVE.org and NVD for exact CVE metadata lookups.
- [x] Parse exact package versions from requirements.txt and npm package-lock.json (v1/v2/v3); report unresolved ranges, missing versions, links, provenance assumptions, and conflicts.
- [x] Add separate opt-in OSV package/version checks with shared persistent caching, pacing, Retry-After cooldowns, pagination, bounded request budgets, and partial/stale failure states.
- [x] Show dependency inventory and advisories with manifest locations, exact versions, affected evidence, source status, and reported fixed boundaries; preserve conditional/unverified applicability in UI and exports.
- [ ] Extend supported manifests/lockfiles and independently validate package provenance, applicability, and upgrade compatibility.
- [x] Integrate the official Exploit-DB CSV index; retain references and metadata only.
- [x] Make online lookups opt-in, explain what is sent, and send package names/versions or identifiers only—not uploaded source code.
- [x] Cache advisory responses with source, retrieval date, and record identifier so results can be refreshed and traced.
- [x] Add persistent provider throttling, Retry-After cooldowns, bounded responses, and stale-cache fallback.
- [x] Keep fix suggestions as recommendations; regression test verifies uploaded bytes remain unchanged and the scanner does not write to the upload buffer.

## App experience and safety

- [x] Show AI explanations first when enabled, collapse rule findings into a dropdown, and request fuller explanations, defensive steps, and review guidance.

- [x] Make the GUI cleaner and easier to use, with a navigation sidebar and slightly darker colors.
- [x] Show skipped files and upload limits clearly in the selection and results.
- [x] Add a way to export findings as JSON or a readable text report.
- [x] Add severity filtering and separate code findings from unverified database references.
- [x] Review and enforce streaming upload limits, cleanup, readable errors, and loopback/same-origin API access; regression tests and docs/UPLOAD_REVIEW.md record the boundaries.
- [ ] Complete docs/BROWSER_QA.md in a real browser: desktop/mobile layouts, zoom, keyboard navigation, uploads, CVE lookups, filters, warnings, and report downloads. Record browser/version and outcomes. Agent browser access is unavailable; HTTP/unit checks do not count as visual verification.

## Project delivery

- [x] Add a native desktop launcher with per-user storage, single-instance behavior, browser startup, setup progress/retry, and app shutdown.
- [x] Add automatic checksum-verified Ollama runtime acquisition, local model pulling, release model digest checks, and offline reuse.
- [x] Build a Linux preview and verify frozen resources and live startup/scan/quit; verify real Linux runtime archive download and extraction.
- [x] Configure manual native package builds for Linux, Windows, Apple Silicon, and Intel Macs; do not publish automatically.
- [x] Add a Mac-only build workflow with optional upload to an explicitly selected existing release after both native jobs pass; validate architecture, checksums, release version, and clean source provenance without overwriting Linux assets.
- [x] Set Mac bundle version/minimum OS metadata, place build information in Resources, and add strict ad-hoc signature verification; native CI execution remains pending.
- [ ] Run Windows/macOS native builds, browser walkthroughs, and clean-machine first-run/offline/upgrade tests; Linux distribution compatibility also needs release-candidate checks.
- [ ] Add Windows code signing and Apple Developer ID signing/notarization, then publish tested desktop downloads.
- [ ] Publish a validated trained inference model and pin it in desktop/release.json; current desktop model is base Qwen, not a fine-tune.
- [x] Document setup and run instructions for Windows, macOS, and Linux in docs/SETUP.md (execution verified on Linux; other platform walkthroughs pending).
- [x] Add clearly labeled vulnerable examples and a safe comparison for repeatable scans.
- [x] Test example uploads through the running website's HTTP endpoints and verify CVE.org, NVD, and Exploit-DB results; document results and limitations in examples/TEST_RESULTS.md.
- [ ] Record test results and limitations in the school-project presentation.
- [ ] Review and push each completed batch to GitHub; keep .env and downloaded data/cache files excluded.

## AI features and agent evaluation

The current goal is gradual, lightweight specialization of Qwen 2.5 Coder 3B for vulnerable-code identification and defensive fixes. The researched approach is in [docs/AI_TRAINING_PLAN.md](docs/AI_TRAINING_PLAN.md). Training has not started. The development evaluation CLI still uses existing synthetic cases and does not create a training dataset or update model weights. See docs/AI_EVALUATION.md.

- [x] Research a staged LoRA/QLoRA approach, context limits, data separation, and overfitting controls for CSC 733.
- [ ] Verify the AMD GPU training backend and memory with a one-batch smoke test; isolate and pin training dependencies.
- [x] Define approved-record validation and stable family-based train/validation/test manifests without reusing development fixtures for training; CLI and 24 regression tests implemented in app/training_data.py and tests/test_training_data.py.
- [x] Author an initial draft of 18 SQL examples in 10 families, with provenance, source hashes, proposed fixes, bounded explanation targets, and pending review/screening; see training/README.md.
- [x] Implement an opt-in local LoRA runner with readiness checks, export validation, completion-token masking, length checks, one-step smoke mode, one-epoch limits, and local run metadata. Real GPU/model execution is pending; runner orchestration is tested with mocks.
- [x] Revise draft SQL examples to expose construction in bounded excerpts and reject identical prompts across dataset splits.
- [x] Install qwen2.5-coder:3b in local Ollama and verify a live explanation on development fixtures; no human quality score or weight updates.
- [x] Add a source/fix/target review worksheet and guarded import of explicit review decisions into a new dataset version; generate the initial local worksheet without approving draft records.
- [ ] Curate 20–30 reviewed Python SQL-injection example families for a pilot, including safe and insufficient-context cases.
- [ ] Train and compare a small explanation adapter against the unchanged base; retain validation results and rollback artifacts.
- [ ] Implement and evaluate independent AI detection on bounded code context, including clean code, before claiming AI detection metrics.
- [ ] Implement reviewable patch proposals and isolated behavior/security verification before applying repairs.

- [x] Add a local AI readiness check in the UI without starting generation or sending source.

- [x] Add an optional local AI model to explain findings; clearly distinguish model output from verified rule results.
- [x] Define a narrow agent task: explain scanner findings and suggest defensive fixes for human review.
- [ ] Build a labeled training/evaluation dataset from permitted, documented sources and reviewed examples.
- [x] Save explicit development evaluation runs with model tags, observed model digest, rule/finding references, output, timestamps, and dataset/source/prompt/analyzer hashes. Browser upload scans remain export-only.
- [x] Preserve deterministic TP/FP/TN/FN outcomes against existing provisional fixture labels in paired AI evaluation reports; do not assign independent detection outcomes to the explanation-only agent.
- [ ] Obtain independently reviewed ground truth and score explanation quality across a broader evaluation set.
- [x] Implement a documented human scoring rubric for correctness, evidence/line references, and safe remediation; summaries use latest reviews and leave unreviewed outputs unscored. No scores are used for training.
- [x] Preserve reviewer IDs, feedback, ratings, rationale, timestamps, and prior review files bound to the exact report hash; identity is self-reported and files are not tamper-proof.
- [ ] Separate training, validation, and held-out test data to prevent leakage; report precision, recall, and false-positive rate.
- [x] Pair the explanation agent’s outputs with deterministic findings/recommendations on the same cases; default AI off in UI and CLI, and keep detector metrics separate from human explanation scores.
- [ ] Exclude secrets, personal data, unlicensed content, and exploit payloads from stored training records.
