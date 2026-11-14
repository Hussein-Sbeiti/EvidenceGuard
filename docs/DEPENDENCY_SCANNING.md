# Dependency inventory and advisory checks

The scanner accepts uploaded files named `requirements.txt` and
`package-lock.json`, including files inside selected folders. They share the
existing 50-file, 512 KB per-file, and 5 MB total upload limits. A manifest-only
scan is valid. Parsing reads data in memory; it does not run pip/npm, install
packages, inspect the scanner's own environment, follow includes, expand
variables, fetch URLs, or change uploaded files.

## Parsing rules

- **Python:** uses the `packaging` library for requirement syntax. A single
  non-wildcard `==` pin with a valid PEP 440 version is an exact entry. Names are
  canonicalized. Extras and environment markers are retained; markers are not
  evaluated against the scanner host. Conditional pins can be queried, but their
  applicability is explicitly conditional.
- Ranges, wildcard/missing versions, multiple constraints, conflicting
  unconditional pins, direct URLs/VCS/editables, and include/constraint options
  remain unresolved. Registry-selection options leave otherwise exact Python
  entries unresolved because package provenance is uncertain. Credential-bearing
  URLs are not copied into inventory diagnostics or OSV queries.
- **npm:** supports lockfile versions 1, 2, and 3. Version 1 traverses nested
  dependency maps; versions 2/3 use the packages map and ignore its root project
  entry. Scoped names, aliases, nested installation locations, dev dependencies,
  and optional/target conditions are retained. Exact registry semver is required.
- Workspace/file links, git/URL versions, non-default registry provenance,
  missing versions, ranges, and tags stay unresolved. A missing registry URL
  leaves a visible identity assumption. Optional/OS/CPU conditions are not
  evaluated; a lock entry is not proof of runtime installation.
- Duplicate JSON keys, malformed JSON, or unsupported lockfile structures produce
  a manifest issue instead of silently selecting a version. npm locations use
  JSON Pointers; Python entries retain their logical line's starting line number.
- Inventory is capped at 250 entries per manifest and 500 per scan. Truncation is
  explicitly reported, and omitted entries are not claimed as checked.

The project's own requirements currently use ranges. Uploading them produces
unresolved entries by design; the scanner does not guess installed versions.
Supply exact pins from the target environment or an npm lockfile for version
queries. Other manifests such as pyproject.toml, poetry.lock, yarn.lock, and
pnpm-lock.yaml are not supported in this pass.

## Separate online opt-in

**Check pinned dependencies with OSV** is off by default and independent of
**Look up CVE IDs mentioned in source**. Turning it on sends package ecosystem,
name (possibly a private name), and exact version to
`https://api.osv.dev/v1/query`. Pagination requests may also send an opaque
provider-issued page token. Manifest contents, filenames, paths, markers,
registry URLs, credentials, and the NVD API key are not sent. OSV needs no key
for this public query path.

API clients use the multipart field `dependency_lookup=true` on `POST /api/scan`.
Omitting it leaves advisory lookup off while still building the local inventory.
Unresolved entries are never queried. Duplicate ecosystem/name/version triples
share a lookup but retain every manifest location. No automatic CVE/NVD lookups
are triggered by CVE aliases in OSV responses.

## Cache, pacing, and partial results

OSV shares the existing SQLite cache and HTTP safety handling. Successful query
results (including empty results) are cached for 24 hours. Expired entries fall
back to explicitly stale data when refresh fails. Old OSV cache entries are
pruned after 30 days during successful writes.

The OSV gate permits at most one outgoing request per second across local workers
sharing the cache. Each scan schedules at most 10 OSV requests within a 30-second
budget; requests use a socket timeout up to 12 seconds and a 4 MB response limit.
This is a scheduling budget, not a hard guarantee against every network stall.
A worker can briefly wait for the one-second interval; provider cooldowns fail
fast. HTTP 403/429/5xx responses and network/invalid-JSON failures reuse the
existing cooldown handling and Retry-After support. Separate machines/cache
paths do not share a quota.

Pagination is followed within the same budgets. Partial pages are cached and
can resume on a later scan. Advisory results are capped at 100 records and about
4 MB per package query; truncated or repeated-token responses remain partial.
Cached complete results do not consume the request budget, so retrying a large
scan can progress to remaining packages. No background retry job is started.
`disabled`, `deferred`, `unavailable`, `partial`, and `stale` are not clean results.
A complete empty response means only that OSV returned no records for that query.

## Findings and reports

Results show inventory resolution, manifest location, package/version, provider
status and retrieval time, advisory ID and aliases, matching affected-package
ranges/versions, severity evidence, and reported fixed-version events. Git fixed
commit hashes are not presented as package upgrade versions. Withdrawn records
remain labeled and are excluded from the non-withdrawn advisory count.

OSV performs the version query; this scanner does not independently re-evaluate
all ecosystem range semantics. The label `osv_reported_version_match` means the
query returned a record with matching package identity, not that installation,
environment conditions, exploitability, or upgrade compatibility is proven.
Records without matching affected-package identity are explicitly unverified.
Fixed versions are advisory boundaries, potentially covering different release
branches, not a selected or registry-verified upgrade recommendation.

Code findings, CVE references, and dependency review remain separate sections.
The result summary's `findings` count and severity filter concern code findings;
`dependency_summary` reports inventory/advisory counts separately. Multiple OSV
IDs can describe the same underlying CVE, so record count is not a count of
unique exploitable vulnerabilities. JSON/text exports preserve the full
inventory, statuses, warnings, evidence, and provenance regardless of code filters.
No source or manifest is automatically patched.

## Try the fixtures

1. Open <http://127.0.0.1:8001> and choose the two files under
   `examples/dependencies/python/requirements.txt` and
   `examples/dependencies/npm/package-lock.json`. Do not install these versions.
2. Leave both online options off and scan. Expect 2 manifests, 5 entries,
   3 exact pins, 2 unresolved entries, and no code findings or OSV requests.
3. Enable **Check pinned dependencies with OSV** and scan again. The historical
   requests, PyYAML, and lodash pins can return advisory records. The Flask range
   and local workspace link must stay unresolved and unqueried.
4. Review conditional markers, expand package advisory details, and inspect the
   source's affected ranges and fixed boundaries. Provider status may be cached,
   partial, or unavailable; do not treat incomplete checks as clean.
5. Download JSON/text and verify that manifest locations and unresolved reasons
   are included. Browser interaction checks are still pending in BROWSER_QA.md.

Official references: [OSV query and pagination](https://google.github.io/osv.dev/post-v1-query/),
[OSV schema](https://ossf.github.io/osv-schema/),
[pip requirements format](https://pip.pypa.io/en/stable/reference/requirements-file-format/),
[packaging requirements](https://packaging.pypa.io/en/stable/requirements.html),
[npm lockfile format](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).
