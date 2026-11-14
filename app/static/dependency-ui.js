/** Render dependency data as text; advisory URLs are derived from OSV IDs. */
export function renderDependencies(data) {
  const $ = id => document.getElementById(id);
  const add = (parent, tag, text, className) => {
    const element = document.createElement(tag);
    element.textContent = text;
    if (className) element.className = className;
    parent.append(element);
    return element;
  };
  const entries = data.dependencies || [];
  const issues = data.manifest_issues || [];
  const present = entries.length || issues.length || data.files_scanned.some(file => file.kind === "manifest");
  $("dependenciesSection").hidden = !present;
  if (!present) return;
  const summary = data.dependency_summary;
  $("dependencySummary").textContent = `${summary.entries} entries · ${summary.exact} exact pins · ${summary.unresolved} unresolved · ${summary.advisories} non-withdrawn advisory records`;
  $("dependencyNotice").textContent = `${data.dependency_lookup ? "OSV lookup enabled." : "OSV lookup disabled; inventory only."} ${data.dependency_notice}`;
  const warnings = $("manifestIssues");
  warnings.replaceChildren();
  for (const issue of issues) add(warnings, "p", `${issue.file}: ${issue.message}`, "muted");
  const inventory = $("dependencyInventory");
  inventory.replaceChildren();
  for (const entry of entries) {
    const row = document.createElement("li");
    add(row, "span", `${entry.ecosystem} · ${entry.name || "Unresolved entry"}${entry.version ? `@${entry.version}` : ""}\n${entry.file} · ${entry.location}`, "dependency-location");
    add(row, "span", `${entry.status}${entry.dev ? " · dev dependency" : ""}${entry.optional ? " · optional" : ""}${entry.conditional ? " · conditional" : ""}${entry.marker ? ` · ${entry.marker}` : ""}${entry.reason ? ` · ${entry.reason}` : ""}`, "file-reason");
    inventory.append(row);
  }
  $("dependencyInventoryDetails").open = summary.unresolved > 0;
  const output = $("dependencyResults");
  output.replaceChildren();
  for (const result of data.dependency_results || []) {
    if (result.status === "disabled") continue;
    const card = document.createElement("article");
    card.className = "finding reference-card";
    add(card, "h3", `${result.ecosystem} · ${result.name}@${result.version}`);
    add(card, "p", `OSV · ${result.status}${result.complete ? " · query complete" : " · check incomplete"}`, "category");
    for (const location of result.locations) add(card, "p", `${location.file} · ${location.location}${location.dev ? " · dev dependency" : ""}${location.conditional ? " · conditional entry; installation conditions not evaluated" : ""}${location.reason ? ` · ${location.reason}` : ""}`, "location");
    if (result.retrieved_at) add(card, "p", `Retrieved: ${new Date(result.retrieved_at * 1000).toLocaleString()}`, "muted");
    if (result.warning) add(card, "p", result.warning, "muted");
    if (!result.advisories.length && result.complete && ["live", "cached"].includes(result.status)) {
      add(card, "p", "OSV returned no advisories for this query. This does not prove the package or application is secure.", "muted");
    }
    if (result.advisories.length) {
      const details = document.createElement("details");
      add(details, "summary", `${result.advisories.length} advisory record(s) — review evidence`);
      let rendered = false;
      details.addEventListener("toggle", () => {
        if (!details.open || rendered) return;
        rendered = true;
        for (const advisory of result.advisories) {
          const section = document.createElement("section");
          section.className = "provider-result";
          const link = add(section, "a", `${advisory.id} · ${advisory.summary}`);
          link.href = `https://osv.dev/vulnerability/${encodeURIComponent(advisory.id)}`;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          add(section, "p", `Severity: ${advisory.severity} · ${advisory.applicability}`, "category");
          if (advisory.withdrawn) add(section, "p", `Withdrawn: ${advisory.withdrawn}. This is not an active advisory finding.`, "muted");
          if (advisory.aliases.length) add(section, "p", `Aliases: ${advisory.aliases.join(", ")}`, "muted");
          add(section, "p", `Reported fixed versions: ${advisory.fixed_versions.join(", ") || "Not supplied in the matching package evidence"}`);
          add(section, "p", advisory.notice, "muted");
          const evidence = document.createElement("details");
          add(evidence, "summary", "Affected-version and severity evidence");
          add(evidence, "pre", JSON.stringify({affected: advisory.affected, severity: advisory.severity_evidence}, null, 2));
          section.append(evidence);
          details.append(section);
        }
      });
      card.append(details);
    }
    output.append(card);
  }
}
