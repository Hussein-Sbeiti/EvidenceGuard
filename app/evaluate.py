"""Evaluate rule presence on synthetic source fixtures without executing them."""

import argparse
import hashlib
import json
from importlib.metadata import version
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app import scanner


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CASES = ROOT / "evaluation" / "cases.json"


def load_cases(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1 or not isinstance(payload.get("cases"), list):
        raise ValueError("Unsupported evaluation dataset format")
    rule_ids = {rule.id for rule in scanner.RULES}
    seen = set()
    for case in payload["cases"]:
        if not isinstance(case.get("id"), str) or case["id"] in seen:
            raise ValueError("Case IDs must be unique strings")
        seen.add(case["id"])
        if case.get("suite") not in {"coverage", "variant", "diagnostic"}:
            raise ValueError(f"Unknown suite: {case['id']}")
        if not all(isinstance(case.get(key), str) for key in ("filename", "source", "review")):
            raise ValueError(f"Missing fixture text: {case['id']}")
        expected = case.get("expected_rule_ids")
        if not isinstance(expected, list) or not all(isinstance(rule, str) and rule in rule_ids for rule in expected):
            raise ValueError(f"Unknown expected rule: {case['id']}")
        if len(expected) != len(set(expected)):
            raise ValueError(f"Duplicate expected rule: {case['id']}")
        if case.get("suite") == "coverage" and case.get("target_rule") not in rule_ids:
            raise ValueError(f"Missing coverage target: {case['id']}")
        if case.get("review_status", "pending_independent_review") not in {"pending_independent_review", "independently_reviewed"}:
            raise ValueError(f"Unknown review status: {case['id']}")
        if case.get("review_status") == "independently_reviewed" and not case.get("reviewer"):
            raise ValueError(f"Independent review needs a reviewer identifier: {case['id']}")
    return payload["cases"]


def evaluate_cases(cases: list[dict], scan=scanner.scan_source) -> dict:
    rule_ids = {rule.id for rule in scanner.RULES}
    per_rule = {rule: Counter(tp=0, fp=0, fn=0, tn=0) for rule in sorted(rule_ids)}
    results = []
    for case in cases:
        findings = scan(case["filename"], case["source"])
        actual = {finding.rule_id for finding in findings}
        expected = set(case["expected_rule_ids"])
        for rule in rule_ids:
            bucket = ("tp" if rule in actual else "fn") if rule in expected else ("fp" if rule in actual else "tn")
            per_rule[rule][bucket] += 1
        results.append({
            "id": case["id"], "suite": case["suite"], "filename": case["filename"],
            "expected_rule_ids": sorted(expected), "actual_rule_ids": sorted(actual),
            "false_positives": sorted(actual - expected), "false_negatives": sorted(expected - actual),
            "matches_review": actual == expected,
            "findings": [{"rule_id": finding.rule_id, "line": finding.line} for finding in findings],
            "review": case["review"], "unsupported_weaknesses": case.get("unsupported_weaknesses", []),
        })
    totals = Counter(tp=0, fp=0, fn=0, tn=0)
    for counts in per_rule.values():
        totals.update(counts)
    precision = totals["tp"] / (totals["tp"] + totals["fp"]) if totals["tp"] + totals["fp"] else None
    recall = totals["tp"] / (totals["tp"] + totals["fn"]) if totals["tp"] + totals["fn"] else None
    return {
        "cases": len(cases), "rule_count": len(rule_ids),
        "matching_cases": sum(result["matches_review"] for result in results),
        "counts": dict(totals), "precision": precision, "recall": recall,
        "pending_independent_review": sum(case.get("review_status", "pending_independent_review") != "independently_reviewed" for case in cases),
        "per_rule": {rule: dict(counts) for rule, counts in per_rule.items()}, "results": results,
    }


def percentage(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def markdown_report(report: dict) -> str:
    lines = ["# Deterministic scanner evaluation", "", f"Generated: {report['generated_at']}", "",
             f"Scanner SHA-256: `{report['scanner_sha256']}`", "",
             f"Dataset SHA-256: `{report['dataset_sha256']}`", "",
             "Analyzer module hashes: " + ", ".join(f"`{name}` = `{digest}`" for name, digest in report.get("analyzer_sha256", {}).items()), "",
             "Parser versions: " + ", ".join(f"{name} {number}" for name, number in report.get("parser_versions", {}).items()), "",
             "## Scope", "",
             "These are agent-reviewed synthetic fixtures for the current heuristic rules; independent review status is recorded separately. "
             "Labels describe expected pattern detection, not proven vulnerabilities. No fixture code is executed or sent to a service.", "",
             "Each case/rule pair is one observation. Multiple occurrences of a rule in a case count once. "
             "Line locations appear in the JSON results; the metrics compare rule presence, not location accuracy. "
             "Unsupported weaknesses are listed separately and excluded from recall. "
             "This small, deliberately selected dataset is not a real-world accuracy estimate or a held-out benchmark.", "",
             "## Results", "",
             f"- Cases awaiting independent review: {report.get('pending_independent_review', 0)}. No external reviewer is claimed by this report.",
             f"- Cases: {report['cases']} across {report['rule_count']} rules.",
             f"- Cases matching reviewed labels exactly: {report['matching_cases']}/{report['cases']}.",
             f"- True positives: {report['counts']['tp']}; false positives: {report['counts']['fp']}; "
             f"false negatives: {report['counts']['fn']}; true negatives: {report['counts']['tn']}.",
             f"- Precision: {percentage(report['precision'])}; recall: {percentage(report['recall'])}.", "",
             "True negatives include every absent rule in every case; no accuracy score is reported because that count would dominate it.", "",
             "| Rule | TP | FP | FN | TN |", "| --- | ---: | ---: | ---: | ---: |"]
    for rule, counts in report["per_rule"].items():
        lines.append(f"| {rule} | {counts['tp']} | {counts['fp']} | {counts['fn']} | {counts['tn']} |")
    lines.extend(["", "## Review exceptions", "",
                  "These are observed disagreements with the reviewed labels, not passing cases. "
                  "Fixes belong in scanner changes with regression tests; do not relabel a case just to improve the score.", ""])
    exceptions = [result for result in report["results"] if not result["matches_review"]]
    if not exceptions:
        lines.append("No disagreements in this dataset.")
    for result in exceptions:
        lines.extend([f"### {result['id']}", "",
                      f"- False positives: {', '.join(result['false_positives']) or 'none'}.",
                      f"- Missed rules: {', '.join(result['false_negatives']) or 'none'}.",
                      f"- Review: {result['review']}", ""])
    lines.extend(["## Unsupported weaknesses", ""])
    for result in report["results"]:
        for gap in result["unsupported_weaknesses"]:
            lines.append(f"- `{result['id']}`: {gap['cwe']} — {gap['description']}")
    lines.extend(["", "## Reproduce", "", "```bash",
                  "python -m app.evaluate --output-dir evaluation/results", "```", "",
                  "The command reports all disagreements and exits normally; it is a review tool, not a passing-quality gate. "
                  "The positive/negative coverage fixtures are checked by the unit-test suite. "
                  "The JSON report contains every case outcome and detected line number.", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--output-dir", type=Path, default=Path(".cache/evaluation"))
    args = parser.parse_args()
    report = evaluate_cases(load_cases(args.cases))
    report.update({"generated_at": datetime.now(timezone.utc).isoformat(),
                   "scanner_sha256": hashlib.sha256(Path(scanner.__file__).read_bytes()).hexdigest(),
                   "analyzer_sha256": {name: hashlib.sha256((ROOT / "app" / name).read_bytes()).hexdigest()
                                       for name in ("python_analysis.py", "sql_analysis.py", "javascript_parser.py")},
                   "parser_versions": {package: version(package) for package in ("tree-sitter", "tree-sitter-javascript", "tree-sitter-typescript")},
                   "dataset_sha256": hashlib.sha256(args.cases.read_bytes()).hexdigest()})
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "report.md").write_text(markdown_report(report), encoding="utf-8")
    print(f"Reviewed {report['cases']} cases: {report['matching_cases']} match labels; "
          f"{report['counts']['fp']} false positives, {report['counts']['fn']} missed rule matches.")
    print(f"Fixture precision {percentage(report['precision'])}; recall {percentage(report['recall'])}.")
    print(f"Reports: {args.output_dir / 'report.md'} and {args.output_dir / 'report.json'}")


if __name__ == "__main__":
    main()
