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
| CVE lookup off/on | No CVE lookup when off; only CVE IDs sent when on | Pending |
| Dependency manifests, networking off | Fixture inventory shows 3 exact and 2 unresolved entries; no OSV request | Pending |
| Separate OSV opt-in | Package/version results show status, locations, conditions, affected evidence, and fixed boundaries | Pending |
| Dependency exports | Full inventory, unresolved reasons, partial/stale warnings, and advisory evidence are retained | Pending |
| Long filename and source snippet | Content wraps or scrolls within its own panel, not the page | Pending |

The existing sidebar anchors, semantic headings, focus indicators, skip link,
status regions, native form controls, and responsive styles are implemented.
Their presence is not proof that this walkthrough has passed.

## Optional Ollama integration (manual verification pending)

- Install Ollama and pull `qwen2.5-coder:3b`; restart the scanner with `.env` loaded.
- Confirm **Explain findings with Ollama** defaults off and is reachable with the keyboard.
- Upload `examples/vulnerable_python.py`, enable AI, and scan. Confirm the separate AI explanations section labels model output as unverified and shows file/line/rule references.
- Verify severity filtering still affects rule cards independently of AI explanations.
- Download JSON and text reports; verify AI text, model, timestamp, prompt version, and input hash are included.
- Stop Ollama and repeat: confirm a visible AI warning and intact rule results.
- Scan safe code with AI enabled: confirm “no findings to explain” and no implication of AI security validation.
- Verify AI content wraps on mobile and at 200% zoom.

Automated coverage uses simulated Ollama responses. A live HTTP scan of `examples/vulnerable_browser.js` with local `qwen2.5-coder:3b` returned complete explanations for all three findings on November 18, 2026. This verifies connectivity and response handling; model quality and browser layout have not been signed off.

The app now versions the main JavaScript URL and serves HTML/static assets with `Cache-Control: no-store`. AI results explicitly report disabled or missing server output instead of silently hiding the section. Refresh the browser after updating to load these changes.

### AI-first report layout (manual verification pending)

- With AI output available, confirm AI explanations appear first with all explanation/fix/verification text visible, and Code findings starts collapsed.
- Use Tab and Enter/Space to expand Code findings; check severity filtering and source evidence.
- With AI off, confirm Code findings starts open. With unavailable AI or no explanations, confirm rule results remain open and the AI status is visible.
- Repeat with a second scan using a different AI setting; verify section order and dropdown state reset for the new report.
- Run a fresh AI scan to review the expanded model explanations; older downloaded reports keep their original text.

### Local AI readiness check (manual browser verification pending)

- Click **Check local AI**; verify configured model/status appears and no scan starts.
- Stop Ollama and retry; verify a readable unavailable status and an enabled retry button.
- Configure a missing local model and restart the scanner; verify model_missing guidance.
- Verify the check button and resulting status work with keyboard navigation and a screen reader.
