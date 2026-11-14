import ast
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.evaluate import DEFAULT_CASES, evaluate_cases, load_cases
from app.scanner import RULES, SUPPORTED_EXTENSIONS, scan_source


class RuleCorpusTests(unittest.TestCase):
    def test_every_rule_has_positive_and_negative_coverage(self):
        cases = load_cases(DEFAULT_CASES)
        for rule in RULES:
            targets = [case for case in cases if case.get("target_rule") == rule.id]
            with self.subTest(rule=rule.id):
                self.assertTrue(any(rule.id in case["expected_rule_ids"] for case in targets))
                self.assertTrue(any(not case["expected_rule_ids"] for case in targets))

    def test_all_reviewed_cases_including_diagnostics(self):
        for case in load_cases(DEFAULT_CASES):
            with self.subTest(case=case["id"]):
                findings = scan_source(case["filename"], case["source"])
                self.assertEqual({f.rule_id for f in findings}, set(case["expected_rule_ids"]))
                for rule_id, lines in case.get("expected_lines", {}).items():
                    self.assertEqual([f.line for f in findings if f.rule_id == rule_id], lines)

    def test_python_fixtures_parse_without_executing(self):
        for case in load_cases(DEFAULT_CASES):
            if case["filename"].endswith(".py"):
                with self.subTest(case=case["id"]):
                    ast.parse(case["source"])

    def test_global_credential_rule_applies_to_all_supported_extensions(self):
        for extension in SUPPORTED_EXTENSIONS:
            with self.subTest(extension=extension):
                findings = scan_source("sample" + extension, 'password = "fixture-only-fake-password"')
                self.assertEqual([finding.rule_id for finding in findings], ["HARDCODED-SECRET"])

    def test_language_specific_rules_do_not_leak_to_other_languages(self):
        samples = {"PY-EVAL": "eval(user_input)", "PY-EXEC": "exec(user_input)",
                   "PY-PICKLE": "pickle.loads(data)", "PY-YAML": "yaml.load(document)",
                   "PY-SHELL": "subprocess.run(command, shell=True)",
                   "JS-EVAL": "eval(userInput)", "JS-INNERHTML": "node.innerHTML = userInput",
                   "JS-DOCUMENT-WRITE": "document.write(userInput)"}
        for rule in RULES:
            if rule.id not in samples:
                continue
            for extension in SUPPORTED_EXTENSIONS - rule.languages:
                with self.subTest(rule=rule.id, extension=extension):
                    actual = {f.rule_id for f in scan_source("example" + extension, samples[rule.id])}
                    self.assertNotIn(rule.id, actual)

    def test_evaluation_counts_exact_rule_presence_and_deduplicates_occurrences(self):
        cases = [
            {"id": "one", "suite": "coverage", "filename": "one.py", "source": "", "review": "fixture", "expected_rule_ids": ["PY-EVAL"]},
            {"id": "two", "suite": "coverage", "filename": "two.py", "source": "", "review": "fixture", "expected_rule_ids": ["PY-EXEC"]},
        ]
        def fake_scan(filename, source):
            if filename == "one.py":
                return [SimpleNamespace(rule_id="PY-EVAL", line=1), SimpleNamespace(rule_id="PY-EVAL", line=2), SimpleNamespace(rule_id="JS-EVAL", line=3)]
            return []
        report = evaluate_cases(cases, scan=fake_scan)
        self.assertEqual(report["counts"], {"tp": 1, "fp": 1, "fn": 1, "tn": 2 * len(RULES) - 3})
        self.assertEqual(report["precision"], 0.5)
        self.assertEqual(report["recall"], 0.5)
        self.assertFalse(report["results"][0]["matches_review"])
        self.assertEqual(len(report["results"][0]["findings"]), 3)

    def test_invalid_labels_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            path.write_text(json.dumps({"schema_version": 1, "cases": [
                {"id": "bad", "suite": "diagnostic", "filename": "sample.py", "source": "", "review": "fixture", "expected_rule_ids": ["INVENTED-RULE"]}]}))
            with self.assertRaises(ValueError):
                load_cases(path)


if __name__ == "__main__":
    unittest.main()
