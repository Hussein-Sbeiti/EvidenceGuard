from pathlib import PurePosixPath

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from app.intelligence import CVE_PATTERN, MAX_LOOKUPS, Intelligence, validate_cve
from app.scanner import SUPPORTED_EXTENSIONS, analyze_source, display_filename
from app.uploads import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, parse_upload
from app.local_access import LocalOnlyMiddleware


app = FastAPI(title="Local Vulnerability Scanner")
app.add_middleware(LocalOnlyMiddleware)
intelligence = Intelligence()
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse("app/static/index.html")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/config")
async def configuration() -> dict[str, object]:
    return {
        "limits": {"files": MAX_FILES, "file_bytes": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES},
        "supported_extensions": sorted(SUPPORTED_EXTENSIONS),
        "max_cve_lookups": MAX_LOOKUPS,
    }


@app.post("/api/scan", openapi_extra={"requestBody": {"required": True, "content": {
    "multipart/form-data": {"schema": {"type": "object", "required": ["files"], "properties": {
        "files": {"type": "array", "items": {"type": "string", "format": "binary"}},
        "online_lookup": {"type": "boolean", "default": False},
    }}}
}}})
async def upload_scan(request: Request) -> dict[str, object]:
    async with parse_upload(request) as (files, online_lookup):
        return await scan(files, online_lookup)


async def scan(files: list[UploadFile], online_lookup: bool = False) -> dict[str, object]:
    if not files:
        raise HTTPException(status_code=400, detail="Choose at least one source file.")
    if len(files) > MAX_FILES:
        raise HTTPException(status_code=413, detail=f"Upload no more than {MAX_FILES} files at a time.")

    scanned_files: list[dict[str, object]] = []
    skipped_files: list[dict[str, str]] = []
    findings = []
    analysis_warnings = []
    total_bytes = 0
    cve_mentions: dict[str, list[dict]] = {}

    for upload in files:
        filename = display_filename(upload.filename or "uploaded-file")
        extension = PurePosixPath(filename).suffix.lower()
        content = await upload.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"{filename} exceeds the {MAX_FILE_BYTES // 1024} KB per-file limit.",
            )
        total_bytes += len(content)
        if total_bytes > MAX_TOTAL_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Uploads must total no more than {MAX_TOTAL_BYTES // (1024 * 1024)} MB.",
            )
        if extension not in SUPPORTED_EXTENSIONS:
            skipped_files.append({"file": filename, "reason": "Unsupported file extension"})
            continue
        if b"\x00" in content:
            skipped_files.append({"file": filename, "reason": "Binary content detected"})
            continue

        try:
            source = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            skipped_files.append({"file": filename, "reason": "Not valid UTF-8 text"})
            continue
        scanned_files.append({"file": filename, "lines": len(source.splitlines())})
        file_findings, warnings = await run_in_threadpool(analyze_source, filename, source)
        findings.extend(file_findings)
        analysis_warnings.extend({"file": filename, "message": warning} for warning in warnings)
        for line_number, line in enumerate(source.splitlines(), 1):
            for match in CVE_PATTERN.finditer(line):
                cve = match.group().upper()
                if cve not in cve_mentions and len(cve_mentions) >= 100:
                    continue
                locations = cve_mentions.setdefault(cve, [])
                if len(locations) < 20:
                    locations.append({"file": filename, "line": line_number})

    if not scanned_files:
        raise HTTPException(
            status_code=400,
            detail={"message": "No supported UTF-8 text source files were found.", "skipped_files": skipped_files},
        )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda finding: (severity_order[finding.severity], finding.file, finding.line))
    references = []
    if online_lookup:
        for cve in list(cve_mentions)[:MAX_LOOKUPS]:
            reference = await run_in_threadpool(intelligence.lookup, cve)
            reference["mentions"] = cve_mentions[cve]
            references.append(reference)
    return {
        "files_scanned": scanned_files,
        "skipped_files": skipped_files,
        "analysis_warnings": analysis_warnings,
        "findings": [finding.to_dict() for finding in findings],
        "summary": {
            "files_scanned": len(scanned_files),
            "findings": len(findings),
            "high": sum(f.severity == "high" for f in findings),
            "medium": sum(f.severity == "medium" for f in findings),
            "critical": sum(f.severity == "critical" for f in findings),
            "low": sum(f.severity == "low" for f in findings),
        },
        "cve_mentions": cve_mentions,
        "online_lookup": online_lookup,
        "intelligence": references,
        "intelligence_notice": (
            f"Looked up at most {MAX_LOOKUPS} mentioned CVE IDs. Provider cooldowns may leave partial results; retry missing lookups later."
            if online_lookup else "Online lookups are disabled. Enable them to look up CVE IDs mentioned in source."
        ),
        "notice": "Heuristic findings need human review. Only CVE IDs are sent when online lookup is enabled; uploaded source stays local.",
    }


@app.get("/api/intelligence/{cve_id}")
async def lookup_cve(cve_id: str) -> dict:
    try:
        cve = validate_cve(cve_id)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from None
    return await run_in_threadpool(intelligence.lookup, cve)
