# Deterministic scanner evaluation

Generated: 2026-11-14T16:19:15.604491+00:00

Scanner SHA-256: `b83dfe8f10677a8d994e006f93114701022ded8428f6141220d5c1b8c92a4634`

Dataset SHA-256: `07bff602660912f41345a518f5d0db40e4737f65903499cad2d05820d8e7a87e`

## Scope

These are manually reviewed synthetic fixtures for the current heuristic rules. Labels describe expected pattern detection, not proven vulnerabilities. No fixture code is executed or sent to a service.

Each case/rule pair is one observation. Multiple occurrences of a rule in a case count once. Line locations appear in the JSON results; the metrics compare rule presence, not location accuracy. Unsupported weaknesses are listed separately and excluded from recall. This small, deliberately selected dataset is not a real-world accuracy estimate or a held-out benchmark.

## Results

- Cases: 39 across 9 rules.
- Cases matching reviewed labels exactly: 30/39.
- True positives: 17; false positives: 5; false negatives: 4; true negatives: 325.
- Precision: 77.3%; recall: 81.0%.

True negatives include every absent rule in every case; no accuracy score is reported because that count would dominate it.

| Rule | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| HARDCODED-SECRET | 2 | 1 | 0 | 36 |
| JS-DOCUMENT-WRITE | 3 | 1 | 0 | 35 |
| JS-EVAL | 2 | 0 | 0 | 37 |
| JS-INNERHTML | 2 | 0 | 1 | 36 |
| PY-EVAL | 2 | 2 | 1 | 34 |
| PY-EXEC | 1 | 0 | 0 | 38 |
| PY-PICKLE | 3 | 0 | 1 | 35 |
| PY-SHELL | 1 | 0 | 1 | 37 |
| PY-YAML | 1 | 1 | 0 | 37 |

## Review exceptions

These are observed disagreements with the reviewed labels, not passing cases. Fixes belong in scanner changes with regression tests; do not relabel a case just to improve the score.

### comment_false_positive

- False positives: PY-EVAL.
- Missed rules: none.
- Review: A comment does not execute eval; the current regex flags it.

### string_false_positive

- False positives: PY-EVAL.
- Missed rules: none.
- Review: A quoted demonstration string does not execute eval.

### javascript_comment_false_positive

- False positives: JS-DOCUMENT-WRITE.
- Missed rules: none.
- Review: A JavaScript comment does not write HTML.

### yaml_multiline_safe_false_positive

- False positives: PY-YAML.
- Missed rules: none.
- Review: The selected SafeLoader is on another line, which the current exclusion misses.

### pickle_alias_missed

- False positives: none.
- Missed rules: PY-PICKLE.
- Review: The pickle import alias is not resolved by the current rule.

### eval_line_continuation_missed

- False positives: none.
- Missed rules: PY-EVAL.
- Review: An explicit Python line continuation separates the name from the call.

### shell_multiline_value_missed

- False positives: none.
- Missed rules: PY-SHELL.
- Review: The shell keyword and True value are on separate lines.

### javascript_multiline_assignment_missed

- False positives: none.
- Missed rules: JS-INNERHTML.
- Review: A valid assignment spans two lines; the current per-line regex misses it.

### sql_text_credential_false_positive

- False positives: HARDCODED-SECRET.
- Missed rules: none.
- Review: The SQL interpolation is not a literal credential. SQL injection itself has no current detection rule.

## Unsupported weaknesses

- `sql_text_credential_false_positive`: CWE-89 — SQL injection through interpolation; no SQL injection rule exists in this catalog.

## Reproduce

```bash
python -m app.evaluate --output-dir evaluation/results
```

The command reports all disagreements and exits normally; it is a review tool, not a passing-quality gate. The positive/negative coverage fixtures are checked by the unit-test suite. The JSON report contains every case outcome and detected line number.
