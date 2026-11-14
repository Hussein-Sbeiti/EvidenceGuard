import unittest

from app.scanner import analyze_source, scan_source


class PythonSyntaxTests(unittest.TestCase):
    def assertRules(self, source, expected):
        findings, warnings = analyze_source("example.py", source)
        self.assertEqual({finding.rule_id for finding in findings}, set(expected))
        self.assertEqual(warnings, [])
        return findings

    def test_comments_docstrings_and_sql_strings_are_not_code(self):
        self.assertRules('"""exec(user_input)"""\n# eval(user_input)\ntext = "pickle.loads(data)"\nquery = f"SELECT * FROM users WHERE password = \'{password}\'"\n', [])

    def test_multiline_builtin_calls_keep_call_line_and_source_context(self):
        source = '\nvalue = eval \\\n    (user_input)\n'
        findings = self.assertRules(source, ["PY-EVAL"])
        self.assertEqual(findings[0].line, 2)
        self.assertIn("user_input", findings[0].evidence)

    def test_real_calls_inside_fstrings_still_detected(self):
        self.assertRules('text = f"Result: {eval(user_input)}"', ["PY-EVAL"])

    def test_import_aliases_and_from_imports(self):
        self.assertRules('import pickle as p\nfrom pickle import loads as restore\np.loads(data)\nrestore(data)', ["PY-PICKLE"])
        self.assertRules('from builtins import exec as execute\nexecute(user_input)', ["PY-EXEC"])
        self.assertRules('import subprocess as process\nprocess.run(command, shell=\n    True)', ["PY-SHELL"])

    def test_same_named_methods_and_non_subprocess_keywords_do_not_trigger(self):
        self.assertRules('calculator.eval(user_input)\ncustom.run(command, shell=True)\nsettings(shell=True)', [])

    def test_shadowed_builtins_and_import_aliases_are_not_treated_as_known_apis(self):
        self.assertRules('def eval(value):\n    return value\neval(user_input)', [])
        self.assertRules('import pickle as p\ndef parse(p):\n    return p.loads(data)', [])
        self.assertRules('import pickle as p\np = custom_parser\np.loads(data)', [])

    def test_inner_scope_alias_does_not_escape(self):
        self.assertRules('def parse(data):\n    import pickle as p\n    return p.loads(data)\np.loads(data)', ["PY-PICKLE"])
        self.assertEqual(len(scan_source("test.py", 'def parse(data):\n    import pickle as p\n    return p.loads(data)\np.loads(data)')), 1)

    def test_method_skips_class_namespace_and_global_declarations_skip_outer_bindings(self):
        self.assertRules('class Demo:\n    eval = lambda value: value\n    def run(self):\n        return eval(user_input)', ["PY-EVAL"])
        self.assertRules('import pickle as p\ndef outer(p):\n    def inner():\n        global p\n        return p.loads(data)', ["PY-PICKLE"])

    def test_local_comprehension_and_lambda_bindings_shadow_builtins(self):
        self.assertRules('[eval(value) for eval in functions]\n(lambda eval: eval(value))(handler)', [])
        self.assertRules('[eval(value) for value in values]', ["PY-EVAL"])

    def test_yaml_safe_loader_variants_and_aliases(self):
        self.assertRules('import yaml as y\nfrom yaml import CSafeLoader as Safe\ny.load(\n    document,\n    Loader=Safe\n)\ny.load(document, y.SafeLoader)', [])
        self.assertRules('yaml.load(document, Loader=UnsafeLoader)', ["PY-YAML"])
        self.assertRules('yaml.load(document, Loader=SafeLoader); yaml.load(other, Loader=UnsafeLoader)', ["PY-YAML"])

    def test_credentials_are_literal_assignments_not_strings_describing_assignments(self):
        self.assertRules('password: str = "fixture-only-fake-password"\nconfig = {"api_key": "fixture-only-fake-key"}', ["HARDCODED-SECRET"])
        self.assertRules('text = "password = \'not-a-real-secret\'"\npassword = os.environ["PASSWORD"]\npassword = f"{user_input}"', [])
        findings = self.assertRules('config = {\n    "password":\n        "fixture-only-fake-password"\n}', ["HARDCODED-SECRET"])
        self.assertEqual(findings[0].line, 2)
        self.assertIn("fixture-only-fake-password", findings[0].evidence)

    def test_incomplete_python_has_labeled_fallback_and_preserves_available_findings(self):
        source = '# eval(hidden)\ntext = "exec(hidden)"\npassword = "fixture-only-fake-password"\neval(user_input)\nif (\n'
        findings, warnings = analyze_source("broken.py", source)
        self.assertEqual({finding.rule_id for finding in findings}, {"PY-EVAL", "HARDCODED-SECRET"})
        self.assertEqual([finding.line for finding in findings], [3, 4])
        self.assertEqual(len(warnings), 1)
        self.assertIn("fallback", warnings[0])


class JavaScriptLexicalTests(unittest.TestCase):
    def assertRules(self, source, expected):
        findings = scan_source("example.js", source)
        self.assertEqual({finding.rule_id for finding in findings}, set(expected))
        return findings

    def test_comments_and_quoted_demonstrations_are_not_code(self):
        self.assertRules('// eval(userInput)\n/* document.write(input); */\nconst text = "element.innerHTML = input";\nconst example = `eval(userInput)`;', [])

    def test_multiline_access_preserves_location_and_source(self):
        findings = self.assertRules('const value = 1;\nelement .\n    innerHTML\n    = userInput;', ["JS-INNERHTML"])
        self.assertEqual(findings[0].line, 2)
        self.assertIn("=", findings[0].evidence)

    def test_comment_between_call_tokens(self):
        self.assertRules('document /* explanation */ .\n    write(userInput);', ["JS-DOCUMENT-WRITE"])

    def test_template_expressions_are_code_while_template_text_is_not(self):
        self.assertRules('const html = `eval(fake) ${eval(userInput)}`;', ["JS-EVAL"])
        self.assertRules('const html = `text ${`nested ${document.write(input)}`} tail`;', ["JS-DOCUMENT-WRITE"])
        self.assertRules('const text = `escaped \\${eval(fake)}`;', [])

    def test_regex_literals_are_masked_without_hiding_division_operands(self):
        self.assertRules('const pattern = /eval\\(userInput\\)/g;', [])
        self.assertRules('function check() { return /document.write(input)/.test(value); }', [])
        self.assertRules('const result = total / eval(userInput) / scale;', ["JS-EVAL"])

    def test_returned_eval_is_a_call_but_declaration_or_member_eval_is_not(self):
        self.assertRules('function run() { return eval(userInput); }', ["JS-EVAL"])
        self.assertRules('function eval(value) { return value; }\nobject . eval(userInput);', [])

    def test_comparisons_are_not_innerhtml_assignments(self):
        self.assertRules('if (element.innerHTML === expected) { check(); }\nconst test = element.innerHTML == expected;', [])

    def test_js_credentials_are_assignments_not_literals_describing_them(self):
        self.assertRules('const password = "fixture-only-fake-password";', ["HARDCODED-SECRET"])
        self.assertRules('const password = `fixture-only-fake-password`;', ["HARDCODED-SECRET"])
        self.assertRules('const message = "password = \'fixture-only-fake-password\'";\nconst password = `${userInput}`;', [])


if __name__ == "__main__":
    unittest.main()
