# Deterministic scanner evaluation

Generated: 2026-11-14T17:16:39.765926+00:00

Scanner SHA-256: `1549f6fe7237d21a6674368e53facee827afc4b26878d09b2c9287e84aa345fc`

Dataset SHA-256: `7a1b2e60a865056dec905a2360a17476c0f0a397b3767fe12afe02f15dfe5b5a`

Analyzer module hashes: `python_analysis.py` = `508243b664bbe120afc37de1b75c48f12492a37149e34893c231f5dd57fde682`, `sql_analysis.py` = `92ad7909a43ce5e1d14596a8dcd727d591a78dfbdf1708e25f838edaa2025b68`, `javascript_parser.py` = `47ada790ec027540585ce9cc7e154f06272251104ad5afb552c14ab9c0f3e2bb`

Parser versions: tree-sitter 0.25.2, tree-sitter-javascript 0.25.0, tree-sitter-typescript 0.23.2

## Scope

These are agent-reviewed synthetic fixtures for the current heuristic rules; independent review status is recorded separately. Labels describe expected pattern detection, not proven vulnerabilities. No fixture code is executed or sent to a service.

Each case/rule pair is one observation. Multiple occurrences of a rule in a case count once. Line locations appear in the JSON results; the metrics compare rule presence, not location accuracy. Unsupported weaknesses are listed separately and excluded from recall. This small, deliberately selected dataset is not a real-world accuracy estimate or a held-out benchmark.

## Results

- Cases awaiting independent review: 65. No external reviewer is claimed by this report.
- Cases: 65 across 10 rules.
- Cases matching reviewed labels exactly: 65/65.
- True positives: 37; false positives: 0; false negatives: 0; true negatives: 613.
- Precision: 100.0%; recall: 100.0%.

True negatives include every absent rule in every case; no accuracy score is reported because that count would dominate it.

| Rule | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| HARDCODED-SECRET | 2 | 0 | 0 | 63 |
| JS-DOCUMENT-WRITE | 3 | 0 | 0 | 62 |
| JS-EVAL | 7 | 0 | 0 | 58 |
| JS-INNERHTML | 4 | 0 | 0 | 61 |
| PY-EVAL | 4 | 0 | 0 | 61 |
| PY-EXEC | 1 | 0 | 0 | 64 |
| PY-PICKLE | 6 | 0 | 0 | 59 |
| PY-SHELL | 2 | 0 | 0 | 63 |
| PY-SQL-INJECTION | 7 | 0 | 0 | 58 |
| PY-YAML | 1 | 0 | 0 | 64 |

## Review exceptions

These are observed disagreements with the reviewed labels, not passing cases. Fixes belong in scanner changes with regression tests; do not relabel a case just to improve the score.

No disagreements in this dataset.
## Unsupported weaknesses


## Reproduce

```bash
python -m app.evaluate --output-dir evaluation/results
```

The command reports all disagreements and exits normally; it is a review tool, not a passing-quality gate. The positive/negative coverage fixtures are checked by the unit-test suite. The JSON report contains every case outcome and detected line number.
