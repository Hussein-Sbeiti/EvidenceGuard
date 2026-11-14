from pathlib import PurePosixPath

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from app.intelligence import CVE_PATTERN, MAX_LOOKUPS, Intelligence, validate_cve
from app.scanner import SUPPORTED_EXTENSIONS, display_filename, scan_source


MAX_FILES = 50
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 5 * 1024 * 1024

app = FastAPI(title="Local Vulnerability Scanner")
intelligence = Intelligence()
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse("app/static/index.html")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan")
async def scan(files: list[UploadFile] = File(...), online_lookup: bool = Form(False)) -> dict[str, object]:
    if not files:
        raise HTTPException(status_code=400, detail="Choose at least one source file.")
    if len(files) > MAX_FILES:
        raise HTTPException(status_code=413, detail=f"Upload no more than {MAX_FILES} files at a time.")

    scanned_files: list[dict[str, object]] = []
    findings = []
    total_bytes = 0
    cve_mentions: dict[str, list[dict]] = {}

    for upload in files:
        filename = display_filename(upload.filename or "uploaded-file")
        extension = PurePosixPath(filename).suffix.lower()
        if extension not in SUPPORTED_EXTENSIONS:
            continue

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
        if b"\x00" in content:
            continue

        source = content.decode("utf-8", errors="replace")
        scanned_files.append({"file": filename, "lines": len(source.splitlines())})
        findings.extend(scan_source(filename, source))
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
            detail="No supported text source files were found. Supported extensions: "
            + ", ".join(sorted(SUPPORTED_EXTENSIONS)),
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
        "findings": [finding.to_dict() for finding in findings],
        "summary": {
            "files_scanned": len(scanned_files),
            "findings": len(findings),
            "high": sum(f.severity == "high" for f in findings),
            "medium": sum(f.severity == "medium" for f in findings),
        },
        "cve_mentions": cve_mentions,
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
