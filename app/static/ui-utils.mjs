/** Selection checks shared by the UI and dependency-free frontend tests. */
export function apiErrorMessage(data, fallback) {
  if (typeof data?.detail === "string") return data.detail;
  if (typeof data?.detail?.message === "string") {
    const skipped = (data.detail.skipped_files || []).map(file => `${file.file}: ${file.reason}`).join("; ");
    return data.detail.message + (skipped ? ` ${skipped}` : "");
  }
  return fallback;
}

export function selectUploadFiles(files, config) {
  const accepted = [];
  const skipped = [];
  for (const file of files) {
    const name = file.webkitRelativePath || file.name;
    const dot = file.name.lastIndexOf(".");
    const extension = dot < 0 ? "" : file.name.slice(dot).toLowerCase();
    let reason = "";
    if (!config.supported_extensions.includes(extension) && !(config.manifest_filenames || []).includes(file.name.toLowerCase())) reason = "Unsupported file extension";
    else if (file.size > config.limits.file_bytes) reason = "Exceeds the per-file size limit";
    if (reason) skipped.push({file: name, reason});
    else accepted.push(file);
  }
  const totalBytes = accepted.reduce((total, file) => total + file.size, 0);
  let error = "";
  if (accepted.length > config.limits.files) error = `Select no more than ${config.limits.files} supported files at a time.`;
  else if (totalBytes > config.limits.total_bytes) error = `Selected files exceed the ${formatBytes(config.limits.total_bytes)} total limit. Choose fewer files.`;
  return {accepted, skipped, totalBytes, error};
}

export function formatBytes(bytes) {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1).replace(/\.0$/, "")} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1).replace(/\.0$/, "")} KB`;
  return `${bytes} bytes`;
}

export function buildReadableReport(data) {
  const summary = data.summary;
  const lines = ["VULNERABILITY SCANNER REPORT", `Completed: ${data.completed_at}`, "",
    `${summary.files_scanned} file(s) scanned; ${summary.findings} heuristic finding(s).`,
    `Critical: ${summary.critical || 0}; high: ${summary.high}; medium: ${summary.medium}; low: ${summary.low || 0}.`,
    `Online lookup: ${data.online_lookup ? "enabled" : "disabled"}`, "", "FILES"];
  for (const file of data.files_scanned) lines.push(`${file.file}: ${file.lines} line(s)`);
  for (const file of data.skipped_files || []) lines.push(`Skipped ${file.file}: ${file.reason}`);
  if (data.analysis_warnings?.length) {
    lines.push("", "ANALYSIS WARNINGS");
    for (const warning of data.analysis_warnings) lines.push(`${warning.file}: ${warning.message}`);
  }
  lines.push("", "CODE FINDINGS");
  if (!data.findings.length) lines.push("No matches in the current rule catalog. This does not prove the code is secure.");
  for (const finding of data.findings) {
    lines.push("", `[${finding.severity.toUpperCase()}] ${finding.title}`,
      `${finding.file}:${finding.line} (${finding.rule_id})`, `${finding.cwe}: ${finding.cwe_name || "Software weakness"}`,
      `Why: ${finding.description}`, `Source: ${finding.evidence}`, `Recommendation: ${finding.recommendation}`,
      `Example fix: ${finding.fix_example}`);
  }
  if (data.dependencies?.length || data.manifest_issues?.length || data.files_scanned.some(file => file.kind === "manifest")) {
    lines.push("", "DEPENDENCY INVENTORY", `OSV lookup: ${data.dependency_lookup ? "enabled" : "disabled"}`, data.dependency_notice || "");
    for (const issue of data.manifest_issues || []) lines.push(`${issue.file}: ${issue.message}`);
    for (const entry of data.dependencies || []) lines.push(`${entry.ecosystem} ${entry.name || "Unresolved entry"}${entry.version ? "@" + entry.version : ""}: ${entry.status}${entry.dev ? " · dev dependency" : ""}${entry.optional ? " · optional" : ""} — ${entry.file} · ${entry.location}${entry.marker ? " · marker: " + entry.marker : ""}${entry.reason ? " · " + entry.reason : ""}`);
    for (const result of data.dependency_results || []) {
      lines.push("", `${result.ecosystem} ${result.name}@${result.version} — OSV: ${result.status} — ${result.complete ? "query complete" : "check incomplete"}`);
      for (const location of result.locations) lines.push(`${location.file} · ${location.location}${location.conditional ? " · conditional; installation conditions not evaluated" : ""}`);
      if (result.retrieved_at) lines.push(`Retrieved: ${new Date(result.retrieved_at * 1000).toISOString()}`);
      if (result.warning) lines.push(result.warning);
      if (result.complete && ["live", "cached"].includes(result.status) && !result.advisories.length) lines.push("No advisories returned for this completed query; this is not proof of security.");
      for (const advisory of result.advisories) lines.push(advisory.id, advisory.url, advisory.summary, `Applicability: ${advisory.applicability}`, `Severity: ${advisory.severity}`, `Withdrawn: ${advisory.withdrawn || "no"}`, `Reported fixed versions: ${advisory.fixed_versions.join(", ") || "not supplied"}`, advisory.notice, "Affected-version evidence:", JSON.stringify(advisory.affected, null, 2));
    }
  }
  lines.push("", "DATABASE REFERENCES — APPLICABILITY UNVERIFIED", data.intelligence_notice || "");
  if (Object.keys(data.cve_mentions || {}).length) lines.push(`CVE mentions: ${Object.keys(data.cve_mentions).join(", ")}`);
  for (const reference of data.intelligence || []) {
    lines.push("", reference.cve_id, reference.notice);
    for (const source of reference.sources) {
      lines.push(`${source.provider}: ${source.status}`);
      if (source.retrieved_at) lines.push(`Retrieved: ${new Date(source.retrieved_at * 1000).toISOString()}`);
      if (source.index_modified_at) lines.push(`Local index modified: ${new Date(source.index_modified_at * 1000).toISOString()}`);
      if (source.warning) lines.push(source.warning);
      if (source.provider === "Exploit-DB") {
        for (const exploit of source.data || []) lines.push(`${exploit.id}: ${exploit.title} — ${exploit.url}`);
      } else if (source.data) {
        lines.push(`Record state: ${source.data.state || "unknown"}`, source.data.description, source.data.url,
          "Severity and version evidence:", JSON.stringify({metrics: source.data.metrics, affected: source.data.affected, configurations: source.data.configurations}, null, 2));
      } else if (["live", "cached", "stale"].includes(source.status)) lines.push("No matching record returned by this provider.");
    }
  }
  lines.push("", data.notice, "", "Reports contain flagged source snippets. Review before sharing.");
  return lines.join("\n");
}
