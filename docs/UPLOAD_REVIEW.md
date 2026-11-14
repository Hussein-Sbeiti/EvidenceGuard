# Upload and local-access review

The current ASGI tests exercise real streamed multipart parsing, not just direct
calls to the scan helper. The tests are in `tests/test_web_boundaries.py`.

## Enforced boundaries

- At most 50 file parts and one optional `online_lookup` field.
- At most 512 KB per file and 5 MB combined file bytes, including unsupported
  files that will later be skipped. Exact boundaries are accepted.
- At most 5 MB + 256 KB of raw multipart body. Both Content-Length and streamed
  byte counts are checked; omitting a length does not bypass the limit.
- Multipart headers and text fields are bounded. Oversized file/body data returns
  HTTP 413; malformed multipart/forms return HTTP 400; an incorrect content type
  returns HTTP 415. Underlying multipart header validation may return 400 before
  the custom header limit returns 413.
- Size checks happen in parser callbacks before file writes. File buffers never
  exceed the in-memory spool threshold, and are closed after success or failure,
  including unfinished parts. Tests assert early stream termination, no disk
  rollover, and buffer cleanup for successful and oversized uploads.
- Unsupported extensions, NUL-containing binary content, and invalid UTF-8 text
  are skipped with reasons. UTF-8 BOMs are accepted. When no supported text files
  remain, the API returns an error with per-file skip reasons; the UI displays
  those reasons. Invalid syntax uses explicitly labeled partial analysis.
- Source analysis runs in a worker thread. Uploaded files are neither imported
  nor executed. Uploaded source is not written to the intelligence cache. Runtime
  buffers exist until the request is cleaned up; this is not a secure-memory
  erasure guarantee.

## Local-only API behavior

Requests must have a loopback peer and a Host naming localhost, 127.0.0.1, or ::1.
Untrusted hosts and remote peers are rejected. API Origin headers must match the
page's scheme, hostname, and port; cross-site Fetch Metadata requests are also
rejected. API responses include `Cache-Control: no-store`. The service still
should be started with `--host 127.0.0.1`; it is a local development app, not a
multi-user authenticated service or a reverse-proxy deployment.

Offline scanning is the default. Same-origin tests confirm that CVE mentions do
not call the intelligence provider without opt-in. API keys stay server-side;
only CVE identifiers are used in the configured online lookups. JSON and text
exports contain flagged source excerpts and should be reviewed before sharing.

## Practical limits

These are per-request limits. Simultaneous requests can still consume CPU and
memory; there is no global resource quota or sandbox for arbitrary third-party
parser vulnerabilities. The dependency ranges in requirements.txt match the
multipart APIs exercised by the tests. Browser interactions and responsive
behavior remain pending in `BROWSER_QA.md`.
