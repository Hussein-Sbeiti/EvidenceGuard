import unittest

from app.scanner import display_filename, scan_source


class ScannerTests(unittest.TestCase):
    def test_detects_risky_python_call_with_line_number(self) -> None:
        findings = scan_source("src/example.py", "print('safe')\nresult = eval(user_input)\n")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 2)
        self.assertEqual(findings[0].rule_id, "PY-EVAL")
        self.assertEqual(findings[0].file, "src/example.py")

    def test_detects_multiple_rules_on_one_file(self) -> None:
        findings = scan_source(
            "app.py",
            "subprocess.run(command, shell=True)\n"
            "password = 'example-password'\n",
        )

        self.assertEqual({finding.rule_id for finding in findings}, {"PY-SHELL", "HARDCODED-SECRET"})

    def test_skips_safe_yaml_load(self) -> None:
        self.assertEqual(scan_source("config.py", "yaml.safe_load(document)\n"), [])

    def test_skips_unknown_extensions(self) -> None:
        self.assertEqual(scan_source("notes.txt", "eval(input())"), [])

    def test_sanitizes_uploaded_path_for_display(self) -> None:
        self.assertEqual(display_filename("../../src/example.py"), "src/example.py")


if __name__ == "__main__":
    unittest.main()
