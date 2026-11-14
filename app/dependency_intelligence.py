"""OSV queries using the scanner's persistent cache, gates, and HTTP handling."""

import hashlib
import json
import sqlite3
import time
from contextlib import closing
from urllib.request import Request
from urllib.parse import quote

from packaging.utils import canonicalize_name

from app.intelligence import MAX_RESPONSE, ProviderUnavailable, TTL


MAX_OSV_REQUESTS = 10
MAX_OSV_SECONDS = 30
MAX_ADVISORIES = 100
OSV_INTERVAL = 1.0


def identity(entry):
    return entry["ecosystem"], entry["name"], entry["version"]


def same_package(package, ecosystem, name):
    if not isinstance(package, dict) or package.get("ecosystem") != ecosystem or not isinstance(package.get("name"), str):
        return False
    other = package["name"]
    return canonicalize_name(other) == canonicalize_name(name) if ecosystem == "PyPI" else other == name


def normalize_record(record, ecosystem, name):
    if not isinstance(record, dict) or not isinstance(record.get("id"), str) or not 1 <= len(record["id"]) <= 200:
        raise ValueError("Invalid advisory")
    if not isinstance(record.get("aliases", []), list) or not all(isinstance(alias, str) for alias in record.get("aliases", [])):
        raise ValueError("Invalid aliases")
    if record.get("withdrawn") is not None and not isinstance(record["withdrawn"], str):
        raise ValueError("Invalid withdrawal date")
    affected = record.get("affected", [])
    if not isinstance(affected, list):
        raise ValueError("Invalid affected evidence")
    evidence = [item for item in affected if isinstance(item, dict) and same_package(item.get("package"), ecosystem, name)]
    fixed = set()
    for item in evidence:
        for version_range in item.get("ranges", []):
            if not isinstance(version_range, dict):
                raise ValueError("Invalid version range")
            # Git 'fixed' events are commit hashes, not package versions.
            if version_range.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                continue
            for event in version_range.get("events", []):
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.add(event["fixed"])
    severity = record.get("database_specific", {}).get("severity", "unknown")
    severity = severity.lower() if isinstance(severity, str) else "unknown"
    severity = {"moderate": "medium"}.get(severity, severity)
    if severity not in {"critical", "high", "medium", "low"}:
        severity = "unknown"
    return {
        "id": record["id"], "url": "https://osv.dev/vulnerability/" + quote(record["id"], safe=""),
        "summary": record.get("summary") or "Advisory returned by OSV", "details": record.get("details", ""),
        "aliases": record.get("aliases", []), "severity": severity, "severity_evidence": record.get("severity", []),
        "affected": evidence, "fixed_versions": sorted(fixed), "modified": record.get("modified"),
        "withdrawn": record.get("withdrawn"),
        "applicability": "withdrawn" if record.get("withdrawn") else "osv_reported_version_match" if evidence else "unverified_package_identity",
        "notice": "OSV reported this record for the queried name/version. Installation, environment markers, exploitability, and upgrade compatibility are not verified. Fixed versions are advisory boundaries, not a chosen upgrade.",
    }


class DependencyIntelligence:
    def __init__(self, transport, monotonic=time.monotonic, sleeper=time.sleep):
        self.transport = transport
        self.monotonic = monotonic
        self.sleeper = sleeper

    def lookup_many(self, entries, enabled=False):
        grouped = {}
        for entry in entries:
            if entry["status"] != "exact":
                continue
            key = identity(entry)
            grouped.setdefault(key, []).append({field: entry[field] for field in ("file", "location", "line", "conditional", "marker", "reason", "dev", "optional") if field in entry})
        budget = {"remaining": MAX_OSV_REQUESTS, "deadline": self.monotonic() + MAX_OSV_SECONDS}
        results = []
        for (ecosystem, name, version), locations in grouped.items():
            result = {"ecosystem": ecosystem, "name": name, "version": version, "locations": locations, "provider": "OSV"}
            if not enabled:
                result.update(status="disabled", advisories=[], warning="Dependency advisory lookup is disabled; no request was sent.")
            else:
                try:
                    result.update(self.lookup(ecosystem, name, version, budget))
                except (OSError, sqlite3.Error):
                    result.update(status="unavailable", advisories=[], warning="OSV cache unavailable; lookup could not complete.")
            results.append(result)
        return results

    def cached(self, key):
        with closing(self.transport.connect()) as db, db:
            row = db.execute("SELECT fetched,payload FROM cache WHERE provider='OSV' AND cve=?", (key,)).fetchone()
            if row:
                try:
                    data = json.loads(row[1])
                    if not isinstance(data, dict) or not isinstance(data.get("advisories"), list) or not isinstance(data.get("complete"), bool):
                        raise ValueError
                    for record in data["advisories"]:
                        if not isinstance(record, dict) or not isinstance(record.get("id"), str) or not all(isinstance(record.get(key), list) for key in ("aliases", "affected", "fixed_versions")):
                            raise ValueError
                    return row[0], data
                except (ValueError, TypeError):
                    db.execute("DELETE FROM cache WHERE provider='OSV' AND cve=?", (key,))
        return None

    def store(self, key, fetched, data):
        with closing(self.transport.connect()) as db, db:
            db.execute("DELETE FROM cache WHERE provider='OSV' AND fetched < ?", (fetched - 30 * TTL,))
            db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?,?)", ("OSV", key, fetched, json.dumps(data)))

    def lookup(self, ecosystem, name, version, budget):
        key = hashlib.sha256(json.dumps([ecosystem, name, version]).encode()).hexdigest()
        cached = self.cached(key)
        fresh = cached and self.transport.clock() - cached[0] < TTL
        if fresh and cached[1]["complete"]:
            return self.present(cached[1], "cached", cached[0])
        data = cached[1].copy() if fresh else {"advisories": [], "next_page_token": None, "complete": False}
        fetched = cached[0] if fresh else None
        status = "deferred"
        warning = "OSV request/time budget reached; retry this scan to check remaining packages or pages."
        while not data["complete"]:
            remaining_time = budget["deadline"] - self.monotonic()
            if budget["remaining"] <= 0 or remaining_time <= 0:
                break
            with closing(self.transport.connect()) as db, db:
                gate = db.execute("SELECT next_request FROM gates WHERE provider='OSV'").fetchone()
            delay = max(0, gate[0] - self.transport.clock()) if gate else 0
            if delay > OSV_INTERVAL + 0.05:
                status, warning = "unavailable", "OSV is cooling down; retry later."
                break
            if delay >= remaining_time:
                break
            if delay:
                self.sleeper(delay)
            payload = {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
            if data.get("next_page_token"):
                payload["page_token"] = data["next_page_token"]
            budget["remaining"] -= 1
            try:
                raw = self.transport.request_json("OSV", Request("https://api.osv.dev/v1/query", data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST"),
                    interval=OSV_INTERVAL, timeout=min(12, max(0.1, budget["deadline"] - self.monotonic())))
                records = raw.get("vulns", [])
                token = raw.get("next_page_token")
                if not isinstance(records, list) or (token is not None and not isinstance(token, str)) or ("vulns" not in raw and set(raw) - {"next_page_token"}):
                    raise ValueError("Invalid OSV response")
                by_id = {record["id"]: record for record in data["advisories"]}
                sizes = {identifier: len(json.dumps(record).encode()) for identifier, record in by_id.items()}
                accumulated = sum(sizes.values())
                truncated = False
                for record in records:
                    normalized = normalize_record(record, ecosystem, name)
                    size = len(json.dumps(normalized).encode())
                    updated_size = accumulated - sizes.get(normalized["id"], 0) + size
                    if (len(by_id) >= MAX_ADVISORIES and normalized["id"] not in by_id) or updated_size > MAX_RESPONSE - 1024:
                        truncated = True
                        break
                    by_id[normalized["id"]] = normalized
                    sizes[normalized["id"]] = size
                    accumulated = updated_size
                # Repeated pagination tokens cannot form an unbounded loop.
                repeated = bool(token and token == data.get("next_page_token"))
                data = {"advisories": list(by_id.values()), "next_page_token": token,
                        "complete": not token or truncated or repeated, "truncated": truncated or repeated}
                fetched = self.transport.clock()
                self.store(key, fetched, data)
                status, warning = "live", ""
            except (ProviderUnavailable, ValueError, TypeError, KeyError, AttributeError) as error:
                status = "unavailable"
                warning = str(error) if isinstance(error, ProviderUnavailable) else "OSV returned invalid advisory data."
                if not isinstance(error, ProviderUnavailable):
                    self.transport.cooldown("OSV", 60)
                break
        if fetched is not None:
            return self.present(data, "live" if status == "live" else "partial" if not data["complete"] else "stale", fetched, warning)
        if cached:
            return self.present(cached[1], "stale", cached[0], warning + " Showing stale data.")
        return {"status": status, "advisories": [], "warning": warning, "complete": False}

    @staticmethod
    def present(data, status, fetched, warning=""):
        partial = not data["complete"] or data.get("truncated", False)
        if partial and status in {"live", "cached"}:
            status = "partial"
        if partial:
            warning = (warning + " Partial advisory results; pagination or the advisory-count/size cap prevents a complete check.").strip()
        return {"status": status, "retrieved_at": fetched, "advisories": data["advisories"],
                "complete": not partial, "warning": warning}
