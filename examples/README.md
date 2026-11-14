# Educational scanner examples

These files are intentionally insecure fixtures. Upload them to the scanner;
do not execute, build, deploy, or install old dependencies for them. All
credential-looking strings are fake. No exploit payloads are included.

## Repeat the website test

1. Open <http://127.0.0.1:8001> while the test server is running. Port 8000 was
   already occupied, so this session uses 8001.
2. In **Scan source**, click **Choose files** and select these four files together:
   `vulnerable_python.py`, `vulnerable_browser.js`, `vulnerable_log4j.java`, and
   `safe_patterns.py`.
3. Leave online lookup unchecked and click **Scan selected files**. Expect
   **4 files, 9 findings, 4 high, 5 medium**. The safe comparison has no findings.
4. Select **Scan source** in the sidebar, check **Look up CVE IDs mentioned in source**, then scan again. Expect the
   same heuristic findings plus three separate CVE reference groups.
5. Select **CVE database** in the sidebar, enter `CVE-2021-44228`, and click **Look up CVE**.
   CVE.org and NVD should show a record when available; the downloaded local
   Exploit-DB index contains three exact CVE references at the time of setup.
6. Review the provider statuses. Uncached IDs requested within the same
   6.1-second provider interval may show throttling. Wait at least seven seconds,
   then use the manual form to retry a missing CVE. If a provider reports a
   longer cooldown, wait for that instead.
7. In **Scan results**, filter by High (expect 4 findings), then return to All
   severities (expect 9). Download JSON and the text report. Both should contain
   all findings even when a severity filter is selected.
8. Select the four examples again along with an unsupported file, such as this
   README. The file selection should show a skip reason. The completed report
   should include that skipped file too.
9. Verify that sidebar links and controls work with Tab/Enter, that the skip
   link appears on keyboard focus, and that navigation stays usable at a narrow
   mobile width. These browser checks remain pending in TODO.md.

| File | Expected heuristic findings | CVE reference |
| --- | --- | --- |
| `vulnerable_python.py` | 5: eval, pickle, shell, YAML, fake credential | CVE-2020-14343 |
| `vulnerable_browser.js` | 3: innerHTML, eval, document.write | CVE-2019-11358 |
| `vulnerable_log4j.java` | 1: fake credential | CVE-2021-44228 |
| `safe_patterns.py` | 0 | None |

CVE references are historical context. The scanner does not install libraries,
identify dependency versions, associate every rule with a CVE, or confirm
exploitability. The jQuery deep merge and Log4j logging examples are not detected
by the current heuristic rules; their comments exercise database lookups.

The older `vulnerable_login.py` example is also in this folder. Select only the
four files listed above to reproduce the counts. The SQL rule now reports one high
PY-SQL-INJECTION finding (CWE-89) at line 18, where the interpolated query reaches
`db.execute(query)`. The former credential false positive remains fixed. Upload
this file separately to test SQL detection. Selecting all five source fixtures
produces 10 code findings: 5 high and 5 medium. The separate manifests under
`examples/dependencies/` exercise dependency inventory and OSV queries; see
[dependency test steps](../docs/DEPENDENCY_SCANNING.md#try-the-fixtures). Do not
install the historical fixture packages. Zero findings in `safe_patterns.py` is a comparison for this small rule
catalog, not a security guarantee.

To start this server again from the project root:

```bash
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --env-file .env
```
