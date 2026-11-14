# Browser verification — pending

Browser control reported `The browser access host is unavailable` during this
session. No visual, keyboard, screen-reader, or download interaction is marked
as passed. HTTP and unit-test results are documented separately.

Open <http://127.0.0.1:8001> in the browser. Refresh after backend changes. If
needed, start the server from the project root:

```bash
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload --env-file .env
```

Record the browser/version, date, viewport, and observed outcome for each check.
A keyboard or narrow viewport test requires actual interaction; checking CSS or
HTML alone is insufficient.

| Check | Expected outcome | Result |
| --- | --- | --- |
| Desktop at 1440×900 | Fixed sidebar, readable panels, no overlap or horizontal page scrolling | Pending |
| Tablet at 768×1024 | Content remains within viewport and all controls remain reachable | Pending |
| Mobile at 375×812 and 320×740 | Navigation moves above content, buttons wrap, inputs and result cards fit | Pending |
| Desktop at 200% zoom | Navigation and controls remain usable; content is not clipped | Pending |
| First Tab from page start | Visible skip link; Enter focuses main content | Pending |
| Navigate sidebar using Tab/Enter | Selected section and heading change; focus remains visible | Pending |
| Source picker with keyboard | Choose files opens picker; selecting four primary fixtures enables scanning | Pending |
| Run primary fixtures | Results open with 4 files and 9 findings; no source is executed | Pending |
| Scan `examples/vulnerable_login.py` | One high finding: PY-SQL-INJECTION, CWE-89, line 18 | Pending |
| Severity filter by keyboard | High shows 4 primary-fixture findings; All returns 9 | Pending |
| File-list details with Enter/Space | Scanned and skipped files are readable and toggle correctly | Pending |
| CVE form invalid/valid input | Invalid ID has an understandable message; valid ID displays provider status | Pending |
| Failed scan | Error is visible and announced; controls re-enable; no stale report is presented as a new result | Pending |
| Incomplete `.py`/`.ts` upload | Partial-analysis warning is visible in the results | Pending |
| Download JSON/text while filtering | Both downloads contain the full completed report, warnings, and provenance | Pending |
| Online lookup off/on | No external lookup when off; only CVE IDs sent when on | Pending |
| Long filename and source snippet | Content wraps or scrolls within its own panel, not the page | Pending |

The existing sidebar anchors, semantic headings, focus indicators, skip link,
status regions, native form controls, and responsive styles are implemented.
Their presence is not proof that this walkthrough has passed.
