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
