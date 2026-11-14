# Deterministic scanner evaluation

Generated: 2026-11-14T16:30:57.570336+00:00

Scanner SHA-256: `94067fc966c8df7ae47bc47feff40b45732069e495f7b35200af733deffdccab`

Dataset SHA-256: `07bff602660912f41345a518f5d0db40e4737f65903499cad2d05820d8e7a87e`

Analyzer module hashes: `python_analysis.py` = `61ab0bc2b1704455805c730316dee0fb0959043828a95963bd3925cbb93ed9ba`, `javascript_analysis.py` = `a4242ce8ff5f0bde40b90cf370b07c7c5e10d3e044197ea3bc1de9c5f6245079`

## Scope

These are manually reviewed synthetic fixtures for the current heuristic rules. Labels describe expected pattern detection, not proven vulnerabilities. No fixture code is executed or sent to a service.

Each case/rule pair is one observation. Multiple occurrences of a rule in a case count once. Line locations appear in the JSON results; the metrics compare rule presence, not location accuracy. Unsupported weaknesses are listed separately and excluded from recall. This small, deliberately selected dataset is not a real-world accuracy estimate or a held-out benchmark.

## Results

- Cases: 39 across 9 rules.
- Cases matching reviewed labels exactly: 39/39.
- True positives: 21; false positives: 0; false negatives: 0; true negatives: 330.
- Precision: 100.0%; recall: 100.0%.

True negatives include every absent rule in every case; no accuracy score is reported because that count would dominate it.

| Rule | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| HARDCODED-SECRET | 2 | 0 | 0 | 37 |
| JS-DOCUMENT-WRITE | 3 | 0 | 0 | 36 |
| JS-EVAL | 2 | 0 | 0 | 37 |
| JS-INNERHTML | 3 | 0 | 0 | 36 |
| PY-EVAL | 3 | 0 | 0 | 36 |
| PY-EXEC | 1 | 0 | 0 | 38 |
| PY-PICKLE | 4 | 0 | 0 | 35 |
| PY-SHELL | 2 | 0 | 0 | 37 |
| PY-YAML | 1 | 0 | 0 | 38 |

## Review exceptions

These are observed disagreements with the reviewed labels, not passing cases. Fixes belong in scanner changes with regression tests; do not relabel a case just to improve the score.

No disagreements in this dataset.
## Unsupported weaknesses

- `sql_text_credential_false_positive`: CWE-89 — SQL injection through interpolation; no SQL injection rule exists in this catalog.

## Reproduce

```bash
python -m app.evaluate --output-dir evaluation/results
```

The command reports all disagreements and exits normally; it is a review tool, not a passing-quality gate. The positive/negative coverage fixtures are checked by the unit-test suite. The JSON report contains every case outcome and detected line number.
