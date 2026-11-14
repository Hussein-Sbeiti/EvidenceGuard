"""Parse uploaded manifests as data; never resolve, install, or fetch packages."""

import json
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


MANIFEST_FILENAMES = {"requirements.txt", "package-lock.json"}
MAX_MANIFEST_ENTRIES = 250
MAX_SCAN_ENTRIES = 500
NPM_NAME = re.compile(r"(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*\Z")
SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z")


def is_manifest(filename):
    return PurePosixPath(filename).name.lower() in MANIFEST_FILENAMES


def exact_npm_version(value):
    if not isinstance(value, str) or len(value) > 200:
        return False
    match = SEMVER.fullmatch(value)
    return bool(match and (not match[4] or all(not part.isdigit() or part == "0" or not part.startswith("0") for part in match[4].split("."))))


def entry(file, ecosystem, location, **kwargs):
    return {"file": file, "ecosystem": ecosystem, "location": location, "name": None,
            "version": None, "status": "unresolved", "conditional": False, **kwargs}


def requirements(filename, source):
    entries = []
    custom_registry = False
    pending = ""
    start = 1
    for number, raw in enumerate(source.splitlines(), 1):
        line = re.split(r"\s+#", raw, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if not pending:
            start = number
        pending += line[:-1] + " " if line.endswith("\\") else line
        if line.endswith("\\"):
            continue
        item = entry(filename, "PyPI", f"line {start}", line=start)
        text = re.sub(r"\s+--hash(?:=|\s+)\S+", "", pending).strip()
        pending = ""
        if text.startswith("-"):
            item["reason"] = "Requirement includes, constraints, editable references, and pip options are not followed."
            if text.startswith(("--index-url", "--extra-index-url", "--find-links", "--no-index", "-i", "-f")):
                custom_registry = True
        else:
            try:
                requirement = Requirement(text)
                item.update(name=canonicalize_name(requirement.name), marker=str(requirement.marker) if requirement.marker else None,
                            extras=sorted(requirement.extras), conditional=bool(requirement.marker))
                specs = list(requirement.specifier)
                if requirement.url:
                    item["reason"] = "Direct URL/VCS references are not resolved; the URL is not fetched or sent."
                elif len(specs) != 1 or specs[0].operator != "==" or "*" in specs[0].version:
                    item["reason"] = "An exact == version is required; ranges, wildcards, multiple constraints, and missing versions remain unresolved."
                else:
                    item.update(version=str(Version(specs[0].version)), status="exact")
                    if item["conditional"]:
                        item["reason"] = "Environment marker is preserved, not evaluated against the scanner's environment."
            except (InvalidRequirement, InvalidVersion):
                item["reason"] = "Invalid or unsupported requirement; no environment variables or references are resolved."
        entries.append(item)
    if pending:
        entries.append(entry(filename, "PyPI", f"line {start}", line=start, reason="Unfinished requirement line continuation."))
    pins = {}
    for item in entries:
        if item["status"] == "exact" and not item["conditional"]:
            pins.setdefault(item["name"], set()).add(item["version"])
    for item in entries:
        if custom_registry and item["status"] == "exact":
            item.update(status="unresolved", reason="Registry-selection options are present; package provenance cannot be verified without resolving the environment.")
        if not item["conditional"] and len(pins.get(item["name"], set())) > 1:
            item.update(status="unresolved", reason="Conflicting unconditional pins for this package; no installed version is selected.")
    return entries


def pointer(parts):
    return "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def npm_entry(filename, name, info, path, modern=False):
    item = entry(filename, "npm", pointer([*path, "version"]), install_path=path[-1])
    if not isinstance(info, dict):
        return {**item, "reason": "Malformed lockfile package entry."}
    if modern:
        name = name.rsplit("node_modules/", 1)[-1] if "node_modules/" in name else None
    explicit = info.get("name")
    if isinstance(explicit, str):
        name = explicit
    version = info.get("version")
    if isinstance(version, str) and version.startswith("npm:"):
        match = re.fullmatch(r"npm:(.+)@([^@]+)", version)
        if match:
            name, version = match.groups()
    if isinstance(name, str) and len(name) <= 214 and NPM_NAME.fullmatch(name):
        item["name"] = name
    if info.get("link") or (modern and "node_modules/" not in path[-1]):
        item["reason"] = "Local/workspace links are not confirmed registry package versions."
        return item
    resolved = info.get("resolved")
    if isinstance(resolved, str):
        try:
            url = urlsplit(resolved)
            registry = url.scheme == "https" and url.hostname == "registry.npmjs.org" and not url.username and not url.password
        except ValueError:
            registry = False
        if not registry:
            item["reason"] = "Non-default registry, URL, file, or VCS provenance is unverified; no reference is fetched."
            return item
    if item["name"] is None or not exact_npm_version(version):
        item["reason"] = "Missing package identity or exact registry semver; ranges, tags, and references remain unresolved."
        return item
    item.update(version=version, status="exact", dev=bool(info.get("dev")), optional=bool(info.get("optional")),
                conditional=bool(info.get("optional") or info.get("os") or info.get("cpu")))
    if not resolved:
        item["reason"] = "Registry source is absent; package identity is assumed from the lockfile."
    if item["conditional"]:
        item["reason"] = (item.get("reason", "") + " Optional/OS/CPU installation conditions are not evaluated.").strip()
    return item


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys")
        result[key] = value
    return result


def package_lock(filename, source):
    data = json.loads(source, object_pairs_hook=unique_object)
    if not isinstance(data, dict) or type(data.get("lockfileVersion")) is not int or data["lockfileVersion"] not in {1, 2, 3}:
        raise ValueError("Unsupported lockfile version")
    if data["lockfileVersion"] in {2, 3}:
        if not isinstance(data.get("packages"), dict):
            raise ValueError("Missing packages map")
        for path, info in data["packages"].items():
            if path:
                yield npm_entry(filename, path, info, ["packages", path], modern=True)
    else:
        if not isinstance(data.get("dependencies"), dict):
            raise ValueError("Missing dependencies map")
        stack = [(name, info, ["dependencies", name]) for name, info in reversed(list(data["dependencies"].items()))]
        while stack:
            name, info, path = stack.pop()
            yield npm_entry(filename, name, info, path)
            if isinstance(info, dict) and isinstance(info.get("dependencies"), dict):
                stack.extend((child, value, [*path, "dependencies", child]) for child, value in reversed(list(info["dependencies"].items())))


def parse_manifest(filename, source, limit=MAX_MANIFEST_ENTRIES):
    limit = min(limit, MAX_MANIFEST_ENTRIES)
    issues, entries = [], []
    try:
        parsed = requirements(filename, source) if PurePosixPath(filename).name.lower() == "requirements.txt" else package_lock(filename, source)
        for item in parsed:
            if len(entries) >= limit:
                issues.append({"file": filename, "message": f"Dependency inventory was truncated at {limit} entries; remaining entries were not checked."})
                break
            entries.append(item)
    except (ValueError, TypeError, RecursionError):
        return [], [{"file": filename, "message": "Manifest could not be parsed unambiguously. Check JSON structure/duplicate keys and lockfileVersion (1, 2, or 3). No dependency versions were inferred."}]
    return entries, issues
