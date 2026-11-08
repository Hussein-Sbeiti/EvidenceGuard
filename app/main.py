from pathlib import PurePosixPath

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.scanner import SUPPORTED_EXTENSIONS, display_filename, scan_source


MAX_FILES = 50
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 5 * 1024 * 1024

app = FastAPI(title="Local Vulnerability Scanner")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse("app/static/index.html")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan")
async def scan(files: list[UploadFile] = File(...)) -> dict[str, object]:
    if not files:
        raise HTTPException(status_code=400, detail="Choose at least one source file.")
    if len(files) > MAX_FILES:
        raise HTTPException(status_code=413, detail=f"Upload no more than {MAX_FILES} files at a time.")

    scanned_files: list[dict[str, object]] = []
    findings = []
    total_bytes = 0

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

    if not scanned_files:
        raise HTTPException(
            status_code=400,
            detail="No supported text source files were found. Supported extensions: "
            + ", ".join(sorted(SUPPORTED_EXTENSIONS)),
        )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda finding: (severity_order[finding.severity], finding.file, finding.line))
    return {
        "files_scanned": scanned_files,
        "findings": [finding.to_dict() for finding in findings],
        "summary": {
            "files_scanned": len(scanned_files),
            "findings": len(findings),
            "high": sum(f.severity == "high" for f in findings),
            "medium": sum(f.severity == "medium" for f in findings),
        },
        "notice": "Heuristic findings need human review; no source is sent to an external service.",
    }
