"""Enforce upload limits while parsing, before file buffers can roll to disk."""

from contextlib import asynccontextmanager

from fastapi import HTTPException, Request
from starlette.formparsers import MultiPartException, MultiPartParser


MAX_FILES = 50
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 5 * 1024 * 1024
MAX_BODY_BYTES = MAX_TOTAL_BYTES + 256 * 1024


class UploadLimitError(MultiPartException):
    pass


class BoundedMultipartParser(MultiPartParser):
    # Every file is rejected at <=512 KB, before this threshold can roll over.
    spool_max_size = MAX_FILE_BYTES + 1

    def __init__(self, *args, **kwargs):
        super().__init__(*args, max_files=MAX_FILES, max_fields=3, max_part_size=4096, **kwargs)
        self.total_file_bytes = 0
        self.finished = False

    def on_part_begin(self):
        super().on_part_begin()
        self.part_bytes = 0
        self.header_bytes = 0

    def on_header_field(self, data, start, end):
        self.check_headers(end - start)
        super().on_header_field(data, start, end)

    def on_header_value(self, data, start, end):
        self.check_headers(end - start)
        super().on_header_value(data, start, end)

    def check_headers(self, count):
        self.header_bytes += count
        if self.header_bytes > 4096:
            raise UploadLimitError("A multipart file header exceeds the 4 KB limit.")

    def on_headers_finished(self):
        super().on_headers_finished()
        part = self._current_part
        if part.file and part.field_name != "files":
            raise MultiPartException('File parts must use the field name "files".')
        if not part.file and part.field_name not in {"online_lookup", "dependency_lookup", "ai_explain"}:
            raise MultiPartException('Only the optional "online_lookup", "dependency_lookup", and "ai_explain" text fields are supported.')

    def on_part_data(self, data, start, end):
        if self._current_part.file is not None:
            size = end - start
            self.part_bytes += size
            self.total_file_bytes += size
            if self.part_bytes > MAX_FILE_BYTES:
                raise UploadLimitError("A file exceeds the 512 KB per-file limit.")
            if self.total_file_bytes > MAX_TOTAL_BYTES:
                raise UploadLimitError("Uploads must total no more than 5 MB of file data, including skipped files.")
        super().on_part_data(data, start, end)

    def on_end(self):
        self.finished = True


@asynccontextmanager
async def parse_upload(request: Request):
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "multipart/form-data":
        raise HTTPException(415, "Upload source files using multipart/form-data.")
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            length = int(declared)
            if length < 0:
                raise ValueError
        except ValueError:
            raise HTTPException(400, "Invalid Content-Length header.") from None
        if length > MAX_BODY_BYTES:
            raise HTTPException(413, "Upload request exceeds the 5 MB file-data limit plus multipart overhead.")

    async def stream():
        received = 0
        async for chunk in request.stream():
            received += len(chunk)
            if received > MAX_BODY_BYTES:
                raise UploadLimitError("Upload request exceeds the maximum size, including multipart overhead.")
            yield chunk

    parser = BoundedMultipartParser(request.headers, stream())
    try:
        try:
            form = await parser.parse()
        except MultiPartException as error:
            code = 413 if isinstance(error, UploadLimitError) or error.message.startswith("Too many files") else 400
            raise HTTPException(code, error.message) from None
        if not parser.finished:
            raise HTTPException(400, "Incomplete multipart upload. Select the files and try again.")
        flags = []
        for name in ("online_lookup", "dependency_lookup", "ai_explain"):
            options = form.getlist(name)
            if len(options) > 1:
                raise HTTPException(400, f"Provide {name} only once.")
            option = str(options[0]).strip().lower() if options else "false"
            if option not in {"true", "false", "1", "0"}:
                raise HTTPException(400, f"{name} must be true or false.")
            flags.append(option in {"true", "1"})
        yield form.getlist("files"), *flags
    finally:
        # Also closes unfinished parts, not just entries returned in FormData.
        for buffer in parser._files_to_close_on_error:
            buffer.close()
