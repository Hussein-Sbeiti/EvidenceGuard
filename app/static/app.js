import {selectUploadFiles, formatBytes, buildReadableReport, apiErrorMessage} from "./ui-utils.mjs?v=ollama-2";
import {renderDependencies} from "./dependency-ui.js";

const $ = selector => document.querySelector(selector);
const fileInput = $("#fileInput");
const folderInput = $("#folderInput");
const dropzone = $("#dropzone");
const scanButton = $("#scanButton");
const status = $("#status");
const viewNames = {scan: "Scan source", results: "Scan results", database: "CVE database"};
let config;
let selection = {accepted: [], skipped: [], totalBytes: 0, error: ""};
let lastReport = null;
let scanning = false;

function addText(parent, tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  parent.append(element);
  return element;
}

function setStatus(element, message, error = false) {
  element.textContent = message;
  element.classList.toggle("error", error);
}

function showView(focus = false) {
  const requested = location.hash.slice(1);
  if (requested === "main" && focus) return;
  const name = Object.hasOwn(viewNames, requested) ? requested : "scan";
  for (const view of Object.keys(viewNames)) $(`#${view}View`).hidden = view !== name;
  for (const link of document.querySelectorAll("nav a")) {
    if (link.dataset.view === name) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  document.title = `${viewNames[name]} · Vulnerability Scanner`;
  if (focus && requested !== "main") $(`#${name}View h1`).focus();
}
window.addEventListener("hashchange", () => showView(true));
showView();

function updateScanControls() {
  scanButton.disabled = scanning || !config || !selection.accepted.length || Boolean(selection.error);
  $("#chooseFiles").disabled = scanning || !config;
  $("#chooseFolder").disabled = scanning || !config;
  $("#onlineLookup").disabled = scanning;
  $("#dependencyLookup").disabled = scanning;
  $("#aiExplain").disabled = scanning || !config?.ai;
  scanButton.textContent = scanning ? "Scanning…" : "Scan selected files →";
}

function appendFile(parent, name, description) {
  const row = document.createElement("li");
  addText(row, "span", name);
  addText(row, "span", description, "file-reason");
  parent.append(row);
}

function selectFiles(files) {
  if (scanning) return;
  if (!config) {
    setStatus(status, "Upload settings are still loading. Refresh the page if this continues.", true);
    return;
  }
  selection = selectUploadFiles([...files], config);
  const skipped = selection.skipped.length;
  $("#selected").textContent = `${selection.accepted.length} file(s) ready · ${formatBytes(selection.totalBytes)}${skipped ? ` · ${skipped} skipped` : ""}`;
  const list = $("#selectionList");
  list.replaceChildren();
  for (const file of selection.accepted) appendFile(list, file.webkitRelativePath || file.name, formatBytes(file.size));
  for (const file of selection.skipped) appendFile(list, file.file, `Skipped: ${file.reason}`);
  $("#selectionDetails").hidden = !list.childElementCount;
  $("#selectionDetails").open = Boolean(skipped || selection.error);
  setStatus(status, selection.error || (!selection.accepted.length ? "Choose supported source files or manifests. Use Choose folder to select a project directory." : ""), Boolean(selection.error));
  lastReport = null;
  $("#reportContent").hidden = true;
  $("#resultsEmpty").hidden = false;
  $("#navCount").hidden = true;
  $("#exportJson").disabled = true;
  $("#exportText").disabled = true;
  updateScanControls();
}

$("#chooseFiles").addEventListener("click", () => fileInput.click());
$("#chooseFolder").addEventListener("click", () => folderInput.click());
fileInput.addEventListener("change", () => { selectFiles(fileInput.files); fileInput.value = ""; });
folderInput.addEventListener("change", () => { selectFiles(folderInput.files); folderInput.value = ""; });
for (const eventName of ["dragenter", "dragover"]) dropzone.addEventListener(eventName, event => {
  event.preventDefault();
  if (!scanning) dropzone.classList.add("dragging");
});
for (const eventName of ["dragleave", "drop"]) dropzone.addEventListener(eventName, event => {
  event.preventDefault();
  dropzone.classList.remove("dragging");
});
dropzone.addEventListener("drop", event => selectFiles(event.dataTransfer.files));

async function loadConfig() {
  try {
    const response = await fetch("/api/config");
    if (!response.ok) throw new Error("Unable to load scanner settings. Refresh the page to try again.");
    config = await response.json();
    const desktopControls = $("#desktopControls");
    if (desktopControls) desktopControls.hidden = !config.desktop;
    fileInput.accept = [...new Set([...config.supported_extensions, ...(config.manifest_filenames || []).map(name => name.slice(name.lastIndexOf(".")))])].join(",");
    $("#uploadLimits").textContent = `Up to ${config.limits.files} supported files · ${formatBytes(config.limits.file_bytes)} per file · ${formatBytes(config.limits.total_bytes)} total`;
    $("#lookupLimit").textContent = `Up to ${config.max_cve_lookups} CVE IDs per scan. Rate limits may defer results; affected versions still need review.`;
    $("#dependencyLimit").textContent = `Manifests are parsed locally. Online OSV checks use at most ${config.max_osv_requests} requests in ${config.max_osv_seconds}s; cached checks do not use this request budget. Unchecked packages remain visible.`;
    $("#aiConfig").textContent = `${config.ai.provider} · ${config.ai.model} · up to ${config.ai.max_findings} findings per scan · request timeout ${config.ai.timeout_seconds}s. Start Ollama and install this model first.`;
    updateScanControls();
  } catch (error) {
    $("#uploadLimits").textContent = "Upload settings unavailable.";
    setStatus(status, error.message || "Unable to load scanner settings. Refresh the page.", true);
  }
}
loadConfig();

function renderFindings() {
  const parent = $("#results");
  parent.replaceChildren();
  if (!lastReport) return;
  const severity = $("#severityFilter").value;
  const findings = lastReport.findings.filter(finding => severity === "all" || finding.severity === severity);
  if (!findings.length) {
    addText(parent, "p", lastReport.findings.length ? "No findings match this severity. Choose another filter to see the rest of the report." : lastReport.files_scanned.every(file => file.kind === "manifest") ? "No source code files were included. See the dependency review below." : "No matches in the current rule catalog. This does not prove the code is secure.", "empty");
    return;
  }
  for (const finding of findings) {
    const card = document.createElement("article");
    // Severity controls styling only; all returned text is inserted as text.
    const severityClass = ["critical", "high", "medium", "low"].includes(finding.severity) ? finding.severity : "";
    card.className = `finding ${severityClass}`;
    const header = document.createElement("div");
    header.className = "finding-header";
    addText(header, "h3", finding.title);
    addText(header, "span", finding.severity.toUpperCase(), "severity");
    card.append(header);
    addText(card, "p", `${finding.file} · Line ${finding.line} · ${finding.rule_id}`, "location");
    addText(card, "p", `${finding.cwe} — ${finding.cwe_name || "Software weakness"}`, "category");
    for (const [title, text, code] of [
      ["Why this was flagged", finding.description],
      [`Source · line ${finding.line}`, null, finding.evidence],
      ["Suggested mitigation", finding.recommendation, finding.fix_example],
    ]) {
      const section = document.createElement("section");
      section.className = "finding-section";
      addText(section, "h4", title);
      if (text) addText(section, "p", text);
      if (code) addText(section, "pre", code);
      card.append(section);
    }
    parent.append(card);
  }
}
$("#severityFilter").addEventListener("change", renderFindings);

function renderIntelligence(parent, reference) {
  const card = document.createElement("article");
  card.className = "finding reference-card";
  const header = document.createElement("div");
  header.className = "finding-header";
  addText(header, "h3", reference.cve_id);
  addText(header, "span", "Unverified", "badge");
  card.append(header);
  addText(card, "p", reference.notice, "muted");
  if (reference.mentions) addText(card, "p", reference.mentions.map(m => `${m.file}:${m.line}`).join(", "), "location");
  for (const source of reference.sources) {
    const section = document.createElement("section");
    section.className = "provider-result";
    addText(section, "h4", `${source.provider} · ${source.status}`);
    if (source.retrieved_at) addText(section, "p", `Retrieved: ${new Date(source.retrieved_at * 1000).toLocaleString()}`, "muted");
    if (source.index_modified_at) addText(section, "p", `Local index modified: ${new Date(source.index_modified_at * 1000).toLocaleString()}`, "muted");
    if (source.warning) addText(section, "p", source.warning, "muted");
    if (source.provider === "Exploit-DB") {
      for (const exploit of source.data || []) {
        const a = addText(section, "a", `${exploit.id}: ${exploit.title}`);
        a.href = `https://www.exploit-db.com/exploits/${encodeURIComponent(exploit.id)}`;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        section.append(document.createElement("br"));
      }
      if (source.status === "local" && !source.data.length) addText(section, "p", "No exact CVE references in the local index.");
    } else if (source.data) {
      addText(section, "p", `Record state: ${source.data.state || "unknown"}`);
      addText(section, "p", source.data.description);
      const a = addText(section, "a", `Open ${source.provider} record ↗`);
      a.href = source.provider === "NVD"
        ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(reference.cve_id)}`
        : `https://www.cve.org/CVERecord?id=${encodeURIComponent(reference.cve_id)}`;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      const details = document.createElement("details");
      addText(details, "summary", "Severity and affected version evidence");
      addText(details, "pre", JSON.stringify({metrics: source.data.metrics, affected: source.data.affected, configurations: source.data.configurations}, null, 2));
      section.append(details);
    } else if (["live", "cached", "stale"].includes(source.status)) addText(section, "p", "No matching record returned by this provider.");
    card.append(section);
  }
  parent.append(card);
}

function renderReport(data) {
  $("#resultsEmpty").hidden = true;
  $("#reportContent").hidden = false;
  $("#severityFilter").value = "all";
  const stats = $("#summaryStats");
  stats.replaceChildren();
  for (const [value, label] of [
    [data.summary.files_scanned, "Files scanned"], [data.summary.findings, "Code findings"],
    [(data.summary.high || 0) + (data.summary.critical || 0), "High / critical"], [data.summary.medium || 0, "Medium"],
  ]) {
    const stat = document.createElement("div");
    stat.className = "stat";
    addText(stat, "span", String(value), "stat-value");
    addText(stat, "span", label, "stat-label");
    stats.append(stat);
  }
  $("#reportTime").textContent = `Completed ${new Date(data.completed_at).toLocaleString()}`;
  $("#scanFilesSummary").textContent = `${data.files_scanned.length} file(s) scanned · ${data.skipped_files.length} skipped — review files`;
  const files = $("#scanFilesList");
  files.replaceChildren();
  for (const file of data.files_scanned) appendFile(files, file.file, `${file.lines} line(s) scanned`);
  for (const file of data.skipped_files) appendFile(files, file.file, `Skipped: ${file.reason}`);
  $("#scanFiles").open = data.skipped_files.length > 0;
  const warnings = $("#analysisWarnings");
  warnings.replaceChildren();
  warnings.hidden = !(data.analysis_warnings || []).length;
  if (!warnings.hidden) addText(warnings, "h2", "Some files need closer review");
  for (const warning of data.analysis_warnings || []) addText(warnings, "p", `${warning.file}: ${warning.message}`);
  renderFindings();
  renderDependencies(data);
  renderAI(data.ai);
  $("#intelligenceNotice").textContent = data.intelligence_notice;
  const references = $("#scanReferences");
  references.replaceChildren();
  for (const reference of data.intelligence || []) renderIntelligence(references, reference);
  if (!data.intelligence?.length && Object.keys(data.cve_mentions || {}).length) addText(references, "p", `CVE mentions (unverified): ${Object.keys(data.cve_mentions).join(", ")}`, "muted");
  $("#scanNotice").textContent = data.notice;
  $("#navCount").textContent = String(data.summary.findings + (data.dependency_summary?.advisories || 0));
  $("#navCount").hidden = false;
  $("#exportJson").disabled = false;
  $("#exportText").disabled = false;
}

scanButton.addEventListener("click", async () => {
  if (scanning || !selection.accepted.length || selection.error || !config) return;
  const body = new FormData();
  body.append("online_lookup", $("#onlineLookup").checked);
  body.append("dependency_lookup", $("#dependencyLookup").checked);
  body.append("ai_explain", $("#aiExplain").checked);
  for (const file of selection.accepted) body.append("files", file, file.webkitRelativePath || file.name);
  scanning = true;
  updateScanControls();
  $("#scanView").setAttribute("aria-busy", "true");
  setStatus(status, "Scanning selected files… Optional lookups and local AI may take a little longer.");
  try {
    const response = await fetch("/api/scan", {method: "POST", body});
    const data = await response.json();
    if (!response.ok) throw new Error(apiErrorMessage(data, "Scan failed. Check your files and try again."));
    lastReport = {...data, completed_at: new Date().toISOString(), skipped_files: [...selection.skipped, ...(data.skipped_files || [])]};
    renderReport(lastReport);
    setStatus(status, "Scan complete. Open Scan results to review or export the report.");
    location.hash = "results";
  } catch (error) {
    setStatus(status, error.message || "Unable to complete scan. Try again.", true);
  } finally {
    scanning = false;
    $("#scanView").removeAttribute("aria-busy");
    updateScanControls();
  }
});

function downloadReport(format) {
  if (!lastReport) return;
  const text = format === "json" ? JSON.stringify(lastReport, null, 2) : buildReadableReport(lastReport);
  const blob = new Blob([text], {type: format === "json" ? "application/json;charset=utf-8" : "text/plain;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `vulnerability-report-${lastReport.completed_at.replace(/[:.]/g, "-")}.${format}`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$("#exportJson").addEventListener("click", () => downloadReport("json"));
$("#exportText").addEventListener("click", () => downloadReport("txt"));

$("#lookupForm").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("#lookupButton");
  if (button.disabled) return;
  const output = $("#lookupResults");
  const message = $("#lookupStatus");
  button.disabled = true;
  button.textContent = "Looking up…";
  output.replaceChildren();
  $("#lookupResults").setAttribute("aria-busy", "true");
  setStatus(message, "Looking up vulnerability records…");
  try {
    const cve = $("#cveInput").value.trim().toUpperCase();
    const response = await fetch(`/api/intelligence/${encodeURIComponent(cve)}`);
    const data = await response.json();
    if (!response.ok) throw new Error(apiErrorMessage(data, "Lookup failed."));
    renderIntelligence(output, data);
    setStatus(message, "Lookup completed. Review each provider's status for partial results.");
  } catch (error) {
    setStatus(message, error.message || "Lookup unavailable. Try again later.", true);
  } finally {
    button.disabled = false;
    button.textContent = "Look up CVE →";
    $("#lookupResults").removeAttribute("aria-busy");
  }
});

function renderAI(ai) {
  const aiSection = $("#aiSection");
  const codeFindings = $("#codeFindings");
  const aiEnabled = Boolean(ai && ai.status !== "disabled");
  // Keep rule evidence accessible if AI could not produce explanations.
  codeFindings.open = !aiEnabled || !ai.explanations?.length;
  if (aiEnabled) codeFindings.before(aiSection);
  else codeFindings.after(aiSection);
  aiSection.hidden = false;
  const parent = $("#aiResults");
  parent.replaceChildren();
  if (!ai) {
    $("#aiStatus").textContent = "This server returned no AI status. Restart the scanner and refresh this page, then enable Explain findings with Ollama and scan again.";
    return;
  }
  if (ai.status === "disabled") {
    $("#aiStatus").textContent = "AI explanations were off for this scan. Enable Explain findings with Ollama on the Scan source page and run the scan again.";
    return;
  }
  $("#aiStatus").textContent = `${ai.model || ai.requested_model} · ${ai.status}. ${ai.notice}`;
  if (ai.warning) addText(parent, "p", ai.warning, "notice");
  if (ai.status === "no_findings") addText(parent, "p", "No rule findings to explain. AI does not independently search for vulnerabilities.");
  if (ai.omitted_findings) addText(parent, "p", `${ai.omitted_findings} additional finding(s) were not explained because of the per-scan limit.`);
  for (const entry of ai.explanations || []) {
    const card = document.createElement("article");
    card.className = "finding reference-card";
    const finding = lastReport?.findings?.[entry.finding_index];
    addText(card, "h3", finding?.title || entry.rule_id);
    addText(card, "p", `${entry.file} · Line ${entry.line} · ${entry.rule_id}`, "location");
    for (const [label, key] of [["AI explanation", "explanation"], ["Suggested fix", "remediation"], ["Needs verification", "limitation"]]) {
      const section = document.createElement("section");
      section.className = "finding-section";
      addText(section, "h4", label);
      addText(section, "p", entry[key], "ai-description");
      card.append(section);
    }
    parent.append(card);
  }
}

$("#checkAI").addEventListener("click", async () => {
  const button = $("#checkAI");
  button.disabled = true;
  setStatus($("#aiConnection"), "Checking local Ollama…");
  try {
    const response = await fetch("/api/ai/status");
    if (!response.ok) throw new Error("Unable to check local AI. Restart the scanner and retry.");
    const data = await response.json();
    setStatus($("#aiConnection"), `${data.model} · ${data.status}. ${data.message}`, data.status !== "ready");
  } catch (error) {
    setStatus($("#aiConnection"), error.message || "Local AI check failed.", true);
  } finally {
    button.disabled = false;
  }
});
