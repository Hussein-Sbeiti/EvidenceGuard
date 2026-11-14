"""Read-only CVE intelligence. Uploaded source never enters provider requests."""

import csv
from contextlib import closing
import json
import os
import re
import sqlite3
import threading
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,19}\b", re.IGNORECASE)
MAX_LOOKUPS = 3
TTL = 24 * 60 * 60
MAX_RESPONSE = 4 * 1024 * 1024


class ProviderUnavailable(Exception):
    pass


def validate_cve(value: str) -> str:
    value = value.strip().upper()
    if not CVE_PATTERN.fullmatch(value):
        raise ValueError("Use a CVE ID such as CVE-2021-44228.")
    return value


def retry_seconds(value: str | None, now: float) -> float:
    try:
        if value and value.strip().isdigit():
            return max(60, int(value))
        if value:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            return max(60, date.timestamp() - now)
    except (ValueError, TypeError, OverflowError):
        pass
    return 60


class Intelligence:
    def __init__(self, db_path: str | None = None, exploit_csv: str | None = None,
                 api_key: str | None = None, opener=urlopen, clock=time.time):
        self.db_path = db_path or os.environ.get("VULN_CACHE_PATH", ".cache/intelligence.sqlite3")
        self.exploit_csv = exploit_csv if exploit_csv is not None else os.environ.get("EXPLOITDB_CSV", "data/files_exploits.csv")
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY", "")
        self.opener = opener
        self.clock = clock
        self._init_lock = threading.Lock()
        self._initialized = False

    def connect(self):
        with self._init_lock:
            if not self._initialized:
                Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
                with closing(sqlite3.connect(self.db_path, timeout=2)) as db, db:
                    db.execute("CREATE TABLE IF NOT EXISTS cache (provider TEXT, cve TEXT, fetched REAL, payload TEXT, PRIMARY KEY(provider,cve))")
                    db.execute("CREATE TABLE IF NOT EXISTS gates (provider TEXT PRIMARY KEY, next_request REAL)")
                self._initialized = True
        return sqlite3.connect(self.db_path, timeout=2)

    def reserve(self, provider: str):
        # Persistent atomic reservation also coordinates multiple local workers.
        # Fail fast instead of accumulating sleeping workers or request queues.
        now = self.clock()
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT next_request FROM gates WHERE provider=?", (provider,)).fetchone()
            if row and row[0] > now:
                raise ProviderUnavailable(f"{provider}: throttled; retry in {int(row[0] - now) + 1}s.")
            db.execute("INSERT OR REPLACE INTO gates VALUES (?,?)", (provider, now + 6.1))

    def cooldown(self, provider: str, seconds: float):
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO gates VALUES (?,?) ON CONFLICT(provider) DO UPDATE SET next_request=MAX(next_request,excluded.next_request)",
                       (provider, self.clock() + seconds))

    def fetch(self, provider: str, cve: str) -> dict:
        if provider == "CVE.org":
            return self.request_json(provider, Request(
                "https://search.cve.org/search",
                data=json.dumps({"cveIds": cve, "resultsPerPage": 1}).encode(),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                method="POST"))
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return self.request_json(provider, Request(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode({"cveId": cve}), headers=headers))

    def request_json(self, provider: str, request: Request) -> dict:
        self.reserve(provider)
        try:
            with self.opener(request, timeout=12) as response:
                data = response.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    raise ValueError("response too large")
                result = json.loads(data)
                if not isinstance(result, dict):
                    raise ValueError("invalid response")
                return result
        except HTTPError as error:
            code = error.code
            if code in {403, 429} or code >= 500:
                self.cooldown(provider, retry_seconds(error.headers.get("Retry-After") if error.headers else None, self.clock()))
            error.close()
            # Never return exception text/headers: they may contain credentials.
            raise ProviderUnavailable(f"{provider}: HTTP {code}; lookup unavailable.") from None
        except (URLError, OSError, ValueError, TimeoutError):
            self.cooldown(provider, 60)
            raise ProviderUnavailable(f"{provider}: unavailable or invalid response; retry later.") from None

    def provider(self, name: str, cve: str) -> dict:
        with closing(self.connect()) as db, db:
            cached = db.execute("SELECT fetched,payload FROM cache WHERE provider=? AND cve=?", (name, cve)).fetchone()
            if cached:
                try:
                    json.loads(cached[1])
                except (ValueError, TypeError):
                    db.execute("DELETE FROM cache WHERE provider=? AND cve=?", (name, cve))
                    cached = None
        if cached and self.clock() - cached[0] < TTL:
            return {"provider": name, "status": "cached", "retrieved_at": cached[0], "data": json.loads(cached[1])}
        try:
            raw = self.fetch(name, cve)
            data = normalize(name, raw, cve)
            fetched = self.clock()
            with closing(self.connect()) as db, db:
                # Bound cache growth; successful empty lookups are cached too.
                db.execute("DELETE FROM cache WHERE fetched < ?", (fetched - 30 * TTL,))
                db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?,?)", (name, cve, fetched, json.dumps(data)))
            return {"provider": name, "status": "live", "retrieved_at": fetched, "data": data}
        except (ProviderUnavailable, ValueError, TypeError, KeyError, AttributeError) as error:
            # Malformed provider payloads must not make a local scan fail.
            warning = str(error) if isinstance(error, ProviderUnavailable) else f"{name}: invalid record data."
            if cached:
                return {"provider": name, "status": "stale", "retrieved_at": cached[0],
                        "data": json.loads(cached[1]), "warning": warning + " Showing stale data."}
            return {"provider": name, "status": "unavailable", "data": None,
                    "warning": warning}

    def exploits(self, cve: str) -> dict:
        if not self.exploit_csv:
            return {"provider": "Exploit-DB", "status": "not_configured", "data": [],
                    "warning": "Set EXPLOITDB_CSV to a local files_exploits.csv metadata index."}
        try:
            path = Path(self.exploit_csv)
            modified = path.stat().st_mtime
            matches = []
            with path.open(encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                if not {"id", "description", "codes"}.issubset(reader.fieldnames or []):
                    raise ValueError("Unsupported metadata columns")
                for row in reader:
                    if cve not in CVE_PATTERN.findall((row.get("codes") or "").upper()):
                        continue
                    exploit_id = row.get("id", "")
                    if not exploit_id.isdigit():
                        continue
                    matches.append({"id": exploit_id, "title": row.get("description", ""),
                                    "url": f"https://www.exploit-db.com/exploits/{exploit_id}",
                                    "published": row.get("date_published", ""), "platform": row.get("platform", "")})
                    if len(matches) == 50:
                        break
            return {"provider": "Exploit-DB", "status": "local", "index_modified_at": modified,
                    "retrieved_at": self.clock(), "data": matches,
                    "warning": "Local index may be outdated; at most 50 exact CVE references returned."}
        except (OSError, ValueError, csv.Error):
            return {"provider": "Exploit-DB", "status": "unavailable", "data": [],
                    "warning": "Exploit-DB metadata index could not be read."}

    def lookup(self, cve: str) -> dict:
        cve = validate_cve(cve)
        sources = []
        for name in ("CVE.org", "NVD"):
            try:
                sources.append(self.provider(name, cve))
            except (OSError, sqlite3.Error):
                sources.append({"provider": name, "status": "unavailable", "data": None,
                                "warning": "Local cache unavailable; network request skipped or result unavailable."})
        sources.append(self.exploits(cve))
        return {"cve_id": cve, "applicability": "unverified", "sources": sources,
                "notice": "Reference only. Confirm software, affected version, and configuration before reporting a vulnerability. Exploit references do not prove exploitability."}


def normalize(provider: str, payload: dict, cve: str) -> dict | None:
    """Keep source attribution and version evidence without inferring applicability."""
    if provider == "CVE.org":
        records = payload["records"]
        if not isinstance(records, list):
            raise ValueError("Invalid CVE records")
        for record in records:
            metadata = record["cveMetadata"]
            if metadata["cveId"].upper() != cve:
                continue
            cna = record.get("containers", {}).get("cna", {})
            return {"id": cve, "state": metadata.get("state"),
                    "description": next((d["value"] for d in cna.get("descriptions", []) if d.get("lang") == "en"), ""),
                    "affected": cna.get("affected", []), "metrics": cna.get("metrics", []),
                    "references": cna.get("references", []), "modified": metadata.get("dateUpdated"),
                    "url": f"https://www.cve.org/CVERecord?id={cve}"}
    else:
        records = payload["vulnerabilities"]
        if not isinstance(records, list):
            raise ValueError("Invalid NVD records")
        for entry in records:
            record = entry["cve"]
            if record["id"].upper() != cve:
                continue
            return {"id": cve, "state": record.get("vulnStatus"),
                    "description": next((d["value"] for d in record.get("descriptions", []) if d.get("lang") == "en"), ""),
                    "metrics": record.get("metrics", {}), "configurations": record.get("configurations", []),
                    "references": record.get("references", []), "modified": record.get("lastModified"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}
    return None
