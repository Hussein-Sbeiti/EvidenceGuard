# Deterministic scanner evaluation

This directory reviews the deterministic scanner rules. It does not train or call an
AI agent, contact vulnerability APIs, install vulnerable packages, or execute
fixture code.

`cases.json` contains 65 synthetic snippets with agent-reviewed labels and a rationale
for each label. These are expectations about the current heuristic patterns,
not an independently validated dataset of exploitable applications. They assume
conventional library names and imports; aliases and formatting exceptions are
explicitly labeled in diagnostic cases.

- **Coverage:** one positive and one negative case for each of the ten rules.
  Unit tests check exact rule sets and line numbers for these cases.
- **Variant:** additional cases for spacing, safe YAML loading, language
  boundaries, TypeScript/JSX/TSX, and shared credential detection.
- **Diagnostic:** nine former disagreements involving comments, quoted text,
  multiline statements, import aliases, and the SQL-string credential false
  positive. They are regression tests alongside coverage/variant cases. The SQL case now
  expects the newly implemented SQL rule; its former unsupported classification
  is preserved in the pre-SQL report.

The tests also check language isolation for all supported extensions and shared
credential detection across the full supported extension list.

## Run

From the project root, with the virtual environment activated:

```bash
python -m unittest discover -s tests -v
python -m app.evaluate --output-dir evaluation/results
```

The default output directory for the evaluator, when `--output-dir` is omitted,
is `.cache/evaluation`. The command accepts `--cases path/to/cases.json` for an
alternate dataset using the same schema. It exits normally after writing results,
including known disagreements. This is a review command, not a quality gate that
claims zero defects.

The checked-in [report](results/report.md) and [JSON results](results/report.json)
record parser package versions, scanner/analyzer/dataset SHA-256 hashes, expected/actual rule sets,
false positives, missed rules, and detected line numbers. Regenerate the reports
when the implementation or dataset changes. No real keys or submitted user
source are part of this corpus.

## How to read the results

The scoring unit is a **case/rule pair**, with repeated occurrences counted once.
A true positive means the rule appears in both the expected and actual rule sets;
a false positive is an unexpected rule; a false negative is an expected rule that
was missed. An absent rule in both sets is a true negative. Metrics compare rule
presence, not whether the line number is correct; coverage unit tests separately
check locations.

The [original baseline](baseline/report.md) had 30 of 39 cases matching exactly,
with 5 false positives and 4 missed rule matches (77.3% precision, 81.0% recall).
The [pre-SQL report](pre-sql/report.md) preserves the 39/39 result after the first
syntax fixes. The current report evaluates 65 cases across ten rules, including
Python binding/SQL-flow cases and JS/JSX/TS/TSX parser cases. It currently has
65/65 matches, with 100% fixture precision and recall. The SQL diagnostic label
was expanded to include the new detector, rather than silently comparing the
new catalog to the old nine-rule score. These numbers are specific to the
selected synthetic dataset and are not real-world accuracy estimates.

All 65 labels await independent review; see [review checklist](INDEPENDENT_REVIEW.md).
The authoring agent performed the current label review. No external reviewer,
independent sign-off, held-out test set, or proven application exploitability is
claimed. `review_status` and `reviewer` fields track actual future sign-off.
Dependency/version discovery, Log4j applicability, interprocedural SQL flow,
and unimplemented detection classes remain outside these metrics.

## Follow-up

Python uses AST analysis with a labeled fallback for incomplete syntax. SQL
analysis follows local query construction through simple assignments, overwrites,
branches, and loops. General Python import/binding analysis remains conservative;
dynamic imports, arbitrary assignment aliases, and complicated conditional
bindings can be missed. JavaScript-family files now use full Tree-sitter language
grammars rather than the former lexer. Syntax recovery is reported to users;
complete parsing does not imply complete semantic analysis or cross-file binding
resolution. Preserve the baseline reports and review provenance when changing
cases. Independent review and a larger held-out benchmark are still needed.
