import {test} from "node:test";
import assert from "node:assert/strict";
import {selectUploadFiles, buildReadableReport, apiErrorMessage} from "../../app/static/ui-utils.mjs";

const config = {supported_extensions: [".py", ".js"], limits: {files: 2, file_bytes: 100, total_bytes: 150}};
const file = (name, size, path = "") => ({name, size, webkitRelativePath: path});

test("structured upload errors show skipped reasons and preserve safe fallback text", () => {
  assert.equal(apiErrorMessage({detail: "Too many files"}, "Failed"), "Too many files");
  assert.equal(apiErrorMessage({detail: {message: "No supported files.", skipped_files: [{file: "binary.py", reason: "Binary content detected"}]}}, "Failed"), "No supported files. binary.py: Binary content detected");
  assert.equal(apiErrorMessage({detail: [{input: "private-value"}]}, "Invalid request"), "Invalid request");
});

test("selection retains source files and explains unsupported and oversized skips", () => {
  const selection = selectUploadFiles([file("code.PY", 50, "src/code.PY"), file("notes.txt", 1), file("large.js", 101)], config);
  assert.deepEqual(selection.accepted.map(f => f.webkitRelativePath), ["src/code.PY"]);
  assert.deepEqual(selection.skipped, [
    {file: "notes.txt", reason: "Unsupported file extension"},
    {file: "large.js", reason: "Exceeds the per-file size limit"},
  ]);
  assert.equal(selection.totalBytes, 50);
  assert.equal(selection.error, "");
});

test("selection blocks excess counts and total bytes without silently dropping valid files", () => {
  const count = selectUploadFiles([file("a.py", 1), file("b.py", 1), file("c.py", 1)], config);
  assert.match(count.error, /no more than 2/);
  assert.equal(count.accepted.length, 3);
  const total = selectUploadFiles([file("a.py", 80), file("b.py", 80)], config);
  assert.match(total.error, /total limit/);
  assert.equal(total.accepted.length, 2);
});

test("selection accepts exact size boundaries and does not count skipped bytes", () => {
  const result = selectUploadFiles([file("a.py", 100), file("b.js", 50), file("skip.pdf", 1000000)], config);
  assert.equal(result.totalBytes, 150);
  assert.equal(result.error, "");
  assert.equal(result.skipped.length, 1);
});

test("text report preserves findings, skipped files, stale status, provenance, and version evidence", () => {
  const report = {
    completed_at: "2026-11-14T15:00:00.000Z", online_lookup: true,
    summary: {files_scanned: 1, findings: 1, high: 1, medium: 0},
    files_scanned: [{file: "src/<demo>.py", lines: 2}], skipped_files: [{file: "binary.py", reason: "Binary content detected"}],
    findings: [{file: "src/<demo>.py", line: 2, rule_id: "PY-EVAL", title: "Dynamic evaluation", severity: "high",
      cwe: "CWE-95", cwe_name: "Eval Injection", description: "Executes untrusted data.", evidence: 'eval("<script>")', recommendation: "Parse as data.", fix_example: "json.loads(input_text)"}],
    cve_mentions: {"CVE-2021-44228": []}, intelligence_notice: "Rate limits may defer results.", notice: "Needs human review.",
    intelligence: [{cve_id: "CVE-2021-44228", notice: "Reference only.", sources: [
      {provider: "NVD", status: "stale", retrieved_at: 1, warning: "Refresh unavailable.", data: {
        state: "Analyzed", description: "Historical vulnerability.", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", metrics: {baseScore: 10}, configurations: [{versionEndExcluding: "2.15.0"}]}},
      {provider: "Exploit-DB", status: "local", index_modified_at: 1, data: [{id: "50592", title: "Metadata reference", url: "https://www.exploit-db.com/exploits/50592"}]},
    ]}],
  };
  const output = buildReadableReport(report);
  for (const expected of ["1 heuristic finding", "CWE-95: Eval Injection", 'eval("<script>")', "Skipped binary.py", "APPLICABILITY UNVERIFIED", "NVD: stale", "Refresh unavailable", "2.15.0", "50592", "Needs human review.", "1970-01-01T00:00:01.000Z"]) {
    assert.ok(output.includes(expected), `Report missing ${expected}`);
  }
  assert.equal(report.findings.length, 1);
});

test("clean report states the scanner's limitations and reports no online lookup", () => {
  const text = buildReadableReport({completed_at: "now", summary: {files_scanned: 1, findings: 0, high: 0, medium: 0}, files_scanned: [], findings: [], intelligence: [], notice: "Review findings."});
  assert.match(text, /Online lookup: disabled/);
  assert.match(text, /does not prove the code is secure/);
});

test("partial-analysis warnings survive readable report export", () => {
  const text = buildReadableReport({completed_at: "now", summary: {files_scanned: 1, findings: 0, high: 0, medium: 0}, files_scanned: [], findings: [], intelligence: [],
    analysis_warnings: [{file: "incomplete.py", message: "Python syntax could not be fully analyzed; token-based fallback used."}], notice: "Review findings."});
  assert.match(text, /ANALYSIS WARNINGS/);
  assert.match(text, /incomplete.py: Python syntax could not be fully analyzed; token-based fallback used/);
});

test("file selection accepts only named dependency manifests, with existing upload limits", () => {
  const settings = {...config, manifest_filenames: ["requirements.txt", "package-lock.json"]};
  const selection = selectUploadFiles([file("requirements.txt", 50), file("package-lock.json", 80), file("notes.txt", 1), file("package.json", 1)], settings);
  assert.deepEqual(selection.accepted.map(item => item.name), ["requirements.txt", "package-lock.json"]);
  assert.equal(selection.skipped.length, 2);
  assert.equal(selection.error, "");
});

test("dependency reports preserve unresolved entries, package location, status, fixed boundaries, and evidence", () => {
  const report = {completed_at: "now", summary: {files_scanned: 1, findings: 0, high: 0, medium: 0},
    files_scanned: [{file: "requirements.txt", lines: 2, kind: "manifest"}], findings: [], intelligence: [],
    dependency_lookup: true, dependency_notice: "OSV-reported matches need review.",
    dependencies: [{file: "requirements.txt", location: "line 1", ecosystem: "PyPI", name: "requests", version: "2.0.0", status: "exact"},
      {file: "requirements.txt", location: "line 2", ecosystem: "PyPI", name: "flask", status: "unresolved", reason: "No exact version"}],
    dependency_results: [{ecosystem: "PyPI", name: "requests", version: "2.0.0", status: "partial", complete: false,
      locations: [{file: "requirements.txt", location: "line 1"}], warning: "More pages remain", advisories: [{id: "GHSA-test", url: "https://osv.dev/vulnerability/GHSA-test", summary: "Test", applicability: "osv_reported_version_match", severity: "high", fixed_versions: ["3.0.0"], notice: "Check installation and compatibility.", affected: [{versions: ["2.0.0"]}]}]}],
    notice: "Read-only suggestions."};
  const text = buildReadableReport(report);
  for (const expected of ["requests@2.0.0", "requirements.txt · line 1", "unresolved", "No exact version", "OSV: partial", "More pages remain", "3.0.0", "Affected-version evidence", "Check installation"]) assert.ok(text.includes(expected), `Missing ${expected}`);
  assert.ok(!text.includes("No advisories returned for this completed query"));
});
