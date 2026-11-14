import asyncio
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from fastapi import HTTPException, UploadFile

from app.intelligence import Intelligence, ProviderUnavailable, normalize, retry_seconds, validate_cve
from app.main import MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES, app, configuration, lookup_cve, scan


CVE = "CVE-2021-44228"
CVE_RECORD = {"cveMetadata": {"cveId": CVE, "state": "PUBLISHED"}, "containers": {"cna": {
    "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
    "affected": [{"vendor": "Apache", "product": "Log4j", "versions": [{"version": "2.14.1", "status": "affected"}]}]}}}


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now = 1000000.0
        self.requests = []
        self.service = Intelligence(str(Path(self.directory.name) / "cache.db"), exploit_csv="", api_key="test-key",
                                    opener=self.open, clock=lambda: self.now)

    def open(self, request, timeout):
        self.requests.append(request)
        payload = {"records": [CVE_RECORD]} if request.get_method() == "POST" else {"vulnerabilities": [{"cve": {
            "id": CVE, "vulnStatus": "Analyzed", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10}}]},
            "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True}]}]}]}}]}
        return io.BytesIO(json.dumps(payload).encode())

    def test_exact_lookup_normalizes_preserves_version_evidence_and_caches(self):
        first = self.service.lookup(CVE.lower())
        second = self.service.lookup(CVE)
        self.assertEqual(first["applicability"], "unverified")
        self.assertEqual(first["sources"][0]["data"]["affected"][0]["product"], "Log4j")
        self.assertTrue(first["sources"][1]["data"]["configurations"])
        self.assertEqual([s["status"] for s in second["sources"][:2]], ["cached", "cached"])
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(json.loads(self.requests[0].data), {"cveIds": CVE, "resultsPerPage": 1})
        self.assertNotIn("test-key", self.requests[1].full_url)
        self.assertEqual(self.requests[1].get_header("Apikey"), "test-key")
        self.assertNotIn("test-key", json.dumps(first))

    def test_gates_persist_and_coordinate_concurrent_workers(self):
        def reserve(_):
            try:
                self.service.reserve("NVD")
                return True
            except ProviderUnavailable:
                return False
        with ThreadPoolExecutor(max_workers=8) as executor:
            self.assertEqual(sum(executor.map(reserve, range(8))), 1)
        other = Intelligence(self.service.db_path, clock=lambda: self.now)
        with self.assertRaises(ProviderUnavailable):
            other.reserve("NVD")
        self.now += 6.1
        other.reserve("NVD")

    def test_rate_limit_honors_retry_after_without_retrying(self):
        def limited(request, timeout):
            self.requests.append(request)
            raise HTTPError(request.full_url, 429, "limited", {"Retry-After": "120"}, None)
        self.service.opener = limited
        self.assertEqual(self.service.provider("NVD", CVE)["status"], "unavailable")
        self.now += 61
        self.assertEqual(self.service.provider("NVD", CVE)["status"], "unavailable")
        self.assertEqual(len(self.requests), 1)
        self.now += 60
        self.service.provider("NVD", CVE)
        self.assertEqual(len(self.requests), 2)

    def test_expired_cache_returned_as_stale_on_failure(self):
        self.service.provider("NVD", CVE)
        self.now += 86401
        self.service.opener = lambda *args, **kwargs: (_ for _ in ()).throw(URLError("test-key"))
        result = self.service.provider("NVD", CVE)
        self.assertEqual(result["status"], "stale")
        self.assertNotIn("test-key", json.dumps(result))

    def test_malformed_and_oversized_responses_do_not_crash(self):
        for body in (b'not json', b'[]', b'{}', b'{"records":null}', b'x' * (4 * 1024 * 1024 + 1)):
            with self.subTest(body=body[:30]):
                self.now += 61
                self.service.opener = lambda *args, **kwargs: io.BytesIO(body)
                self.assertEqual(self.service.provider("CVE.org", CVE)["status"], "unavailable")

    def test_rejected_records_preserved_not_reported_as_confirmed(self):
        record = {"cveMetadata": {"cveId": CVE, "state": "REJECTED"}}
        self.assertEqual(normalize("CVE.org", {"records": [record]}, CVE)["state"], "REJECTED")
        self.assertIsNone(normalize("CVE.org", {"records": []}, CVE))

    def test_exploit_csv_exact_id_match_and_metadata_only(self):
        path = Path(self.directory.name) / "files_exploits.csv"
        path.write_text('id,description,codes,date_published,platform\n1,"Example, title",CVE-2021-442280,2021-01-01,java\n2,Correct,CVE-2021-44228;OSVDB-1,2021-01-01,java\n')
        self.service.exploit_csv = str(path)
        data = self.service.exploits(CVE)["data"]
        self.assertEqual([r["id"] for r in data], ["2"])
        self.assertEqual(data[0]["url"], "https://www.exploit-db.com/exploits/2")
        self.assertNotIn("code", data[0])

    def test_missing_index_and_cache_failure_degrade(self):
        self.service.exploit_csv = "/missing/index.csv"
        self.assertEqual(self.service.exploits(CVE)["status"], "unavailable")
        with patch.object(self.service, "connect", side_effect=sqlite3.OperationalError):
            self.assertEqual(self.service.lookup(CVE)["sources"][0]["status"], "unavailable")
        self.assertEqual(self.requests, [])

    def test_corrupt_cache_payload_is_replaced(self):
        self.service.provider("CVE.org", CVE)
        self.now += 7
        with closing(sqlite3.connect(self.service.db_path)) as db, db:
            db.execute("UPDATE cache SET payload='invalid-json'")
        self.assertEqual(self.service.provider("CVE.org", CVE)["status"], "live")

    def test_empty_results_are_cached_and_do_not_mean_provider_failure(self):
        self.service.opener = lambda *args, **kwargs: io.BytesIO(b'{"records":[]}')
        self.assertIsNone(self.service.provider("CVE.org", CVE)["data"])
        self.assertEqual(self.service.provider("CVE.org", CVE)["status"], "cached")

    def test_validation_and_retry_after_dates(self):
        for value in ("log4j", "CVE-2021-44228&apiKey=bad", "CVE-2021-1"):
            with self.assertRaises(ValueError):
                validate_cve(value)
        self.assertEqual(retry_seconds("Thu, 01 Jan 1970 00:02:00 GMT", 0), 120)
        self.assertEqual(retry_seconds("bad", 0), 60)


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_fix_suggestions_leave_uploaded_source_unchanged(self):
        source = b"# Preserve original bytes and line endings\r\nvalue = eval(user_input)\r\n"
        buffer = io.BytesIO(source)
        with patch.object(buffer, "write", side_effect=AssertionError("Uploaded source must not be rewritten")) as write:
            result = await scan([UploadFile(filename="original.py", file=buffer)], False)
        write.assert_not_called()
        self.assertEqual(buffer.getvalue(), source)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "PY-EVAL")
        self.assertTrue(finding["recommendation"])
        self.assertTrue(finding["fix_example"])
        self.assertEqual(finding["evidence"], "value = eval(user_input)")

    async def test_incomplete_python_returns_analysis_warning_and_partial_findings(self):
        source = b'eval(user_input)\nif (\n'
        result = await scan([UploadFile(filename="incomplete.py", file=io.BytesIO(source))], False)
        self.assertEqual(result["findings"][0]["rule_id"], "PY-EVAL")
        self.assertEqual(result["analysis_warnings"][0]["file"], "incomplete.py")
        self.assertIn("fallback", result["analysis_warnings"][0]["message"])

    async def test_upload_configuration_matches_server_limits(self):
        config = await configuration()
        self.assertEqual(config["limits"], {"files": MAX_FILES, "file_bytes": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES})
        self.assertIn(".py", config["supported_extensions"])

    async def test_skipped_files_reported_without_blocking_valid_source(self):
        files = [UploadFile(filename="safe.py", file=io.BytesIO(b"print('hello')")),
                 UploadFile(filename="notes.txt", file=io.BytesIO(b"notes")),
                 UploadFile(filename="binary.py", file=io.BytesIO(b"\x00\x01"))]
        result = await scan(files, False)
        self.assertEqual(result["summary"]["files_scanned"], 1)
        self.assertEqual(result["summary"]["findings"], 0)
        self.assertEqual(result["skipped_files"], [
            {"file": "notes.txt", "reason": "Unsupported file extension"},
            {"file": "binary.py", "reason": "Binary content detected"}])
        self.assertFalse(result["online_lookup"])

    async def test_upload_limits_enforced_at_server(self):
        cases = [
            [UploadFile(filename="example.py", file=io.BytesIO(b"x")) for _ in range(MAX_FILES + 1)],
            [UploadFile(filename="large.py", file=io.BytesIO(b"x" * (MAX_FILE_BYTES + 1)))],
            [UploadFile(filename=f"file{i}.py", file=io.BytesIO(b"x" * MAX_FILE_BYTES)) for i in range(MAX_TOTAL_BYTES // MAX_FILE_BYTES + 1)],
        ]
        for files in cases:
            with self.subTest(files=len(files)):
                with self.assertRaises(HTTPException) as error:
                    await scan(files, False)
                self.assertEqual(error.exception.status_code, 413)

    async def test_all_binary_files_rejected_clearly(self):
        with self.assertRaises(HTTPException) as error:
            await scan([UploadFile(filename="binary.py", file=io.BytesIO(b"\x00"))], False)
        self.assertEqual(error.exception.status_code, 400)
        self.assertIn("No supported UTF-8 text source", error.exception.detail["message"])

    async def test_multipart_route_parses_opt_in_and_returns_results(self):
        body = (f'--boundary\r\nContent-Disposition: form-data; name="online_lookup"\r\n\r\ntrue\r\n'
                f'--boundary\r\nContent-Disposition: form-data; name="files"; filename="example.py"\r\n'
                f'Content-Type: text/plain\r\n\r\n# {CVE}\neval(user)\r\n--boundary--\r\n').encode()
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
                 "scheme": "http", "path": "/api/scan", "query_string": b"",
                 "headers": [(b"host", b"127.0.0.1"), (b"content-type", b"multipart/form-data; boundary=boundary")],
                 "server": ("testserver", 80), "client": ("127.0.0.1", 1234), "root_path": ""}
        messages = []
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        async def send(message):
            messages.append(message)
        with patch("app.main.intelligence.lookup", return_value={"cve_id": CVE}) as lookup:
            await app(scope, receive, send)
        self.assertEqual(messages[0]["status"], 200)
        data = json.loads(b"".join(m.get("body", b"") for m in messages))
        self.assertEqual(data["intelligence"][0]["cve_id"], CVE)
        self.assertEqual(data["summary"]["high"], 1)
        lookup.assert_called_once_with(CVE)

    async def test_scan_offline_default_sends_nothing(self):
        with patch("app.main.intelligence.lookup") as lookup:
            result = await scan([UploadFile(filename="test.py", file=io.BytesIO(f'# {CVE}\neval(user)'.encode()))], False)
        lookup.assert_not_called()
        self.assertEqual(result["findings"][0]["rule_id"], "PY-EVAL")
        self.assertIn(CVE, result["cve_mentions"])
        self.assertEqual(result["intelligence"], [])

    async def test_online_scan_deduplicates_bounds_and_only_sends_ids(self):
        text = f'# {CVE} {CVE}\n# CVE-2020-1111 CVE-2020-2222 CVE-2020-3333\nsecret="private-source"'
        with patch("app.main.intelligence.lookup", side_effect=lambda cve: {"cve_id": cve}) as lookup:
            result = await scan([UploadFile(filename="test.py", file=io.BytesIO(text.encode()))], True)
        self.assertEqual(lookup.call_count, 3)
        self.assertEqual(lookup.call_args_list[0].args, (CVE,))
        self.assertEqual(len(result["intelligence"]), 3)
        self.assertEqual(len(result["intelligence"][0]["mentions"]), 2)

    async def test_invalid_lookup_endpoint_rejected_before_network(self):
        with patch("app.main.intelligence.lookup") as lookup:
            with self.assertRaises(HTTPException) as error:
                await lookup_cve("not-a-cve")
        self.assertEqual(error.exception.status_code, 400)
        lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
