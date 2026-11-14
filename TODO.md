# Project To-do List

Latest recorded verification: **96 backend tests and 9 frontend utility tests pass**. The expanded evaluation matches all **65 agent-reviewed labels**; independent sign-off is still pending. Fixture results do not establish real-world accuracy.

Dependency manifest inventory and opt-in OSV checks are implemented. Remaining work includes additional manifest formats and independent applicability/upgrade review. Browser verification and independent label review can proceed separately. Keep AI work until the non-AI scanner tasks are finished.

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

- [x] Make the GUI cleaner and easier to use, with a navigation sidebar and slightly darker colors.
- [x] Show skipped files and upload limits clearly in the selection and results.
- [x] Add a way to export findings as JSON or a readable text report.
- [x] Add severity filtering and separate code findings from unverified database references.
- [x] Review and enforce streaming upload limits, cleanup, readable errors, and loopback/same-origin API access; regression tests and docs/UPLOAD_REVIEW.md record the boundaries.
- [ ] Complete docs/BROWSER_QA.md in a real browser: desktop/mobile layouts, zoom, keyboard navigation, uploads, CVE lookups, filters, warnings, and report downloads. Record browser/version and outcomes. Agent browser access is unavailable; HTTP/unit checks do not count as visual verification.

## Project delivery

- [ ] Document setup and run instructions for Windows, macOS, and Linux.
- [x] Add clearly labeled vulnerable examples and a safe comparison for repeatable scans.
- [x] Test example uploads through the running website's HTTP endpoints and verify CVE.org, NVD, and Exploit-DB results; document results and limitations in examples/TEST_RESULTS.md.
- [ ] Record test results and limitations in the school-project presentation.
- [ ] Review and push each completed batch to GitHub; keep .env and downloaded data/cache files excluded.

## AI features and agent evaluation — do last

- [ ] Add an optional local AI model to explain findings; clearly distinguish model output from verified rule results.
- [ ] Define a narrow agent task: explain scanner findings and suggest defensive fixes for human review.
- [ ] Build a labeled training/evaluation dataset from permitted, documented sources and reviewed examples.
- [ ] Store each run's model/version, rule or finding ID, input reference, generated output, timestamp, and dataset/source version.
- [ ] Label outcomes as true positive, false positive, true negative, or false negative against reviewed ground truth.
- [ ] Record a documented reward/score for each run, including correctness, useful evidence/line references, and safe, relevant remediation.
- [ ] Keep reviewer feedback and reward rationale so scores can be audited; do not treat unreviewed model confidence as ground truth.
- [ ] Separate training, validation, and held-out test data to prevent leakage; report precision, recall, and false-positive rate.
- [ ] Compare the agent to the existing deterministic rules and keep an easy way to disable the model.
- [ ] Exclude secrets, personal data, unlicensed content, and exploit payloads from stored training records.
