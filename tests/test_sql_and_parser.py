import unittest
from pathlib import Path

from app.scanner import analyze_source, scan_source


class SqlTests(unittest.TestCase):
    def test_original_login_detected_at_execution(self):
        source = Path('examples/vulnerable_login.py').read_text()
        findings = scan_source('vulnerable_login.py', source)
        self.assertEqual([finding.rule_id for finding in findings], ['PY-SQL-INJECTION'])
        self.assertEqual(findings[0].line, 18)
        self.assertIn('db.execute(query)', findings[0].evidence)
        self.assertEqual(findings[0].cwe, 'CWE-89')

    def test_safe_parameters_and_static_formatting(self):
        for source in ['cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                       'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                       'cursor.execute("SELECT * FROM users WHERE id = {}".format(1))',
                       'table = "users"\ncursor.execute(f"SELECT * FROM {table}")']:
            with self.subTest(source=source):
                self.assertEqual(scan_source('sample.py', source), [])

    def test_local_query_aliases_branch_flow_and_augmented_assignment(self):
        for source in ['query = f"SELECT * FROM users WHERE id = {user_id}"\nother = query\ncursor.execute(other)',
                       'query = "SELECT * FROM users"\nquery += " WHERE name = " + username\ncursor.execute(query)',
                       'if condition:\n    query = f"SELECT * FROM users WHERE id = {user_id}"\nelse:\n    query = "SELECT * FROM users"\ncursor.execute(query)']:
            with self.subTest(source=source):
                self.assertEqual([f.rule_id for f in scan_source('sample.py', source)], ['PY-SQL-INJECTION'])

    def test_function_local_query_does_not_escape_into_other_function(self):
        source = 'def unsafe(name):\n    query = f"SELECT * FROM users WHERE name = {name}"\n    db.execute(query)\ndef safe(name):\n    query = "SELECT * FROM users WHERE name = ?"\n    db.execute(query, (name,))'
        findings = scan_source('sample.py', source)
        self.assertEqual([(finding.rule_id, finding.line) for finding in findings], [('PY-SQL-INJECTION', 3)])


class FullParserTests(unittest.TestCase):
    def test_jsx_text_and_regex_statement_do_not_produce_calls(self):
        for filename, source in [('sample.jsx', 'const ui = <p>eval(fake) document.write(fake)</p>;'),
                                 ('sample.tsx', 'const ui: JSX.Element = <p>eval(fake)</p>;'),
                                 ('sample.js', 'if (ready) /eval(fake)/.test(value);')]:
            with self.subTest(filename=filename):
                findings, warnings = analyze_source(filename, source)
                self.assertEqual(findings, [])
                self.assertEqual(warnings, [])

    def test_computed_sinks_unicode_and_typescript_type_assertions(self):
        findings, warnings = analyze_source('sample.ts', 'const label = "é😀";\nnode["innerHTML"] = userInput;\n(eval as Function)(userInput);')
        self.assertEqual([(f.rule_id, f.line) for f in findings], [('JS-INNERHTML', 2), ('JS-EVAL', 3)])
        self.assertEqual(warnings, [])

    def test_javascript_import_shadowing_and_document_parameter(self):
        self.assertEqual(scan_source('sample.js', 'import {eval} from "custom"; eval(input);'), [])
        self.assertEqual(scan_source('sample.js', 'function run(document) { document.write(input); }'), [])
        self.assertEqual(scan_source('sample.js', 'for (const eval of handlers) { eval(input); }'), [])
        self.assertEqual(scan_source('sample.js', 'for (var eval of handlers) {} eval(input);'), [])
        self.assertEqual(scan_source('sample.js', 'const Local = class eval { run() { eval(input); } };'), [])

    def test_invalid_typescript_has_recovery_warning(self):
        findings, warnings = analyze_source('broken.ts', 'const broken = ;\neval(userInput);')
        self.assertEqual([finding.rule_id for finding in findings], ['JS-EVAL'])
        self.assertTrue(warnings)
        self.assertIn('recovery', warnings[0])

    def test_module_eval_before_rebinding_and_match_capture(self):
        self.assertEqual([f.rule_id for f in scan_source('sample.py', 'eval(user_input)\neval = handler')], ['PY-EVAL'])
        self.assertEqual(scan_source('sample.py', 'def run(value):\n    match value:\n        case [eval, *rest]:\n            eval(user_input)'), [])


if __name__ == '__main__':
    unittest.main()
