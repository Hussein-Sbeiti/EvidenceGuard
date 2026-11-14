# Website endpoint test results

Tested November 14, 2026 against the running FastAPI website at
<http://127.0.0.1:8001>, started with `--env-file .env`. The NVD key was present
in local configuration and was not printed or included in this report.

These were HTTP tests against the running website, including real multipart
uploads and real provider responses. Browser click-through testing could not be
performed because browser control was unavailable in this session.

| Check | Observed result |
| --- | --- |
| Website homepage | HTTP 200; opt-in checkbox and manual CVE lookup form present |
| Health endpoint | OK |
| Four-file upload, online disabled | 4 files, 9 findings; no intelligence lookups |
| Safe comparison | 0 findings |
| Four-file upload, online enabled | 4 files, 9 findings, 3 CVE reference groups |
| Invalid CVE lookup | HTTP 400 |

| CVE | CVE.org | NVD | Exploit-DB |
| --- | --- | --- | --- |
| CVE-2020-14343 | Live record | Live record | Local index searched; 0 exact references |
| CVE-2021-44228 | Cached record | Cached record | 3 exact references |
| CVE-2019-11358 | Live record | Live record | 1 exact reference |

The four uploaded files were `vulnerable_python.py`, `vulnerable_log4j.java`,
`vulnerable_browser.js`, and `safe_patterns.py`. Findings totaled 4 high and
5 medium. No example code was executed. CVE applicability remained unverified;
the observed results confirm reference retrieval, not affected-version matching
or exploitability. Provider availability and local index contents may change.

See [README.md](README.md) for the browser steps and expected per-file counts.

## Interface update verification

After the sidebar redesign, the running website and its JavaScript, CSS, and
module assets all returned HTTP 200 with the correct content types. The new
configuration endpoint returned the server's upload limits. A multipart upload
of the four fixtures plus an unsupported text file and a binary file produced
4 scanned files, 9 findings, and 2 explicit skip reasons. Findings included named
CWE categories. A CVE lookup still returned cached CVE.org and NVD records and
local Exploit-DB references.

All 25 backend tests and 5 frontend utility tests passed. The frontend checks
cover selection limits and readable report content, including stale provider
warnings and affected-version evidence. Browser-based visual, navigation, and
download checks remain pending because browser control was unavailable.

## Syntax-analysis regression verification

The 39 original evaluation labels are unchanged. The former five false positives
and four missed rule matches are fixed for those cases; current results are
39/39 matching labels. The original results are preserved in
`evaluation/baseline/`, and the current report hashes the Python and JavaScript
analyzer modules as well as the scanner entry point.

All 53 backend tests and 6 frontend utility tests pass. A live multipart upload
of comment/string, import-alias, multiline JavaScript, incomplete Python, and
the original login fixtures returned four expected findings across four files,
plus one explicit partial-analysis warning for the incomplete file. The login
file no longer produces the spurious credential finding; its SQL injection is
still outside the implemented rules. Online lookup was disabled for this test.

Python AST analysis is flow-insensitive, and JavaScript uses a lightweight lexer
rather than a full parser. Passing this small synthetic corpus does not establish
real-world accuracy. Browser rendering of the new warning remains unverified.

## SQL, full language parser, and upload review

The current scanner has ten rules and 65 agent-reviewed synthetic cases.
All 65 match their labels. All labels are awaiting independent sign-off in
`evaluation/INDEPENDENT_REVIEW.md`; this is not an independently validated score.
The SQL diagnostic's label was expanded for the new rule, and the previous
39-case report is preserved in `evaluation/pre-sql/`.

All 73 backend tests and 7 frontend utility tests pass. They include SQL local
value flow, parameterized-query negatives, Python binding cases, complete
JS/JSX/TS/TSX grammar parsing, regex ambiguity, malformed syntax recovery,
streaming size limits, no disk rollover at the accepted file limit, buffer
cleanup, invalid encodings, malformed multipart, and loopback/origin checks.

A live six-file upload to localhost:8001 returned 11 expected findings: the five
existing source examples plus a TSX fixture. The login file now has one SQL
finding at line 18. JSX text was ignored while its executable expression was
detected. Online lookup was disabled and no analysis warnings were returned.
The running service returned `Cache-Control: no-store`, HTTP 404 for `/.env`,
HTTP 400 for an untrusted Host, and HTTP 403 for an external Origin.

See `docs/UPLOAD_REVIEW.md` for the enforced boundaries and practical limits.
Actual responsive, keyboard, and browser download checks remain pending in
`docs/BROWSER_QA.md`: browser control reported that its access host was
unavailable. No browser interaction is represented as a passing check.

## Dependency inventory and OSV verification

All 96 backend tests and 9 frontend utility tests pass after adding manifest
inventory and separately opted-in OSV queries. Coverage includes Python pins,
markers, extras, hashes, ranges, conflicts, URL/registry privacy, npm lockfile
v1/v2/v3 structures, scoped names, aliases, nested/optional/dev entries, malformed
JSON, cache corruption, pagination/resumption, advisory caps, stale fallback,
Retry-After cooldowns, and the two independent upload opt-in fields.

A live upload of the two `examples/dependencies/` fixtures first ran offline:
2 manifests, 5 inventory entries, 3 exact pins, 2 unresolved entries, no code
findings, and disabled OSV queries. With dependency lookup enabled, OSV returned
10 records for requests 2.19.1, 2 for PyYAML 5.3.1, and 5 for lodash 4.17.15 at
test time. The Flask range and local workspace link were not queried. The PyYAML
environment marker remained conditional rather than being evaluated on the host.

Those 17 advisory records are not 17 independently confirmed exploitable
vulnerabilities. Record aliases may overlap, and installation/applicability still
needs review. The live responses preserved matching affected ranges and reported
fixed boundaries; the text export was generated from these responses and checked
for version, location, marker, unresolved-entry, and affected-evidence content.
Provider feeds and returned record counts can change. No package was installed
from the fixtures, no source/manifest was modified, and no NVD key was sent to OSV.

The new UI and dependency download interaction remain part of the pending browser
walkthrough; endpoint and formatter tests are not visual/browser verification.
