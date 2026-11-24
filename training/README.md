# SQL training pilot

This directory contains 18 newly authored draft Python examples in 10 families:
8 suspected vulnerable cases, 8 safe counterparts, and 2 cases needing more context.
These are educational SQL/SQLite examples, not independently validated ground truth.
All records have pending label review and data screening. No model has been trained.

The first deliverable is dataset preparation for explanation fine-tuning. Independent
detection, patch generation, tokenization, and the training loop are separate work.
See [the training plan](../docs/AI_TRAINING_PLAN.md).

## Inspect the draft

From the project root, using the existing scanner virtual environment:

```bash
python -m app.training_data doctor
python -m app.training_data validate
python -m app.training_data preview --record customer_lookup_vulnerable
```

`doctor` checks package presence and visible AMD device nodes without importing
PyTorch, downloading weights, or allocating GPU memory. It is an inventory, not a
training smoke test. In the inspected session on November 23, 2026, Python was
3.14.4, the training libraries were absent, and `/dev/kfd` and `/dev/dri` were not
visible. GPU access from this execution environment must be resolved before testing
a GPU training stack. This does not establish that the host GPU is incompatible.

`validate` checks schema, source hashes, evidence-line bounds, Python syntax,
provenance, review metadata, and structural overlap. It does not execute snippets
or certify their labels, source permissions, fixes, or secret-free status.
AST fingerprints ignore comments, formatting, and simple local identifier renames.
This catches some clones, not all semantic duplicates. Review related variants and
assign them to one family before accepting the dataset.

`preview` shows the exact single-finding prompt and draft completion, plus the
record hash needed for approval. The runtime exposes only a short execution
excerpt and rule metadata. The separate `explanation_target` therefore uses
conditional advice rather than asserting details available only in the full source.
Full-source rationale and fixes remain annotations for future detection/repair work.
Review these targets against the preview as well as the complete source.

## Review records

For each record, a reviewer other than `author` should check the SQL behavior,
input assumptions, evidence line, label, full-source rationale, and proposed fix.
For vulnerable records, also check the bounded explanation preview. Review the
fixed source for behavior changes, not just whether the scanner stops flagging it.
The safe labels apply only to the shown SQL construction.

A data reviewer should inspect source, fixed source, annotations, and target text
for secrets and personal data, confirm authorship/permissions, and document the
screening decision. The pilot contains no copied third-party source; an external
redistribution license has not been assigned.

After those checks, edit that record's `review` and `screening` objects:

- Set `status` to `approved` only for the review actually performed.
- Supply the actual `reviewer`, a `date` in `YYYY-MM-DD` format, and a specific `rationale`.
- Set `record_sha256` to the hash returned by `preview` for vulnerable records.
  For any record, compute it with `app.training_data.record_digest(record)`.

Changing code, labels, provenance, or target text invalidates existing approvals.
Reviewer identifiers and local JSON files are self-reported and editable; hashes
detect stale approvals, not identity fraud. Do not bulk-approve the draft merely
to make the export command succeed. Validation does not independently confirm
that a review or screening was performed.

## Prepare approved examples

Once the selected dataset has approved review and screening for every record:

```bash
python -m app.training_data prepare --output .cache/training/sql-pilot-v1
```

The command refuses pending/rejected records, stale approvals, development-fixture
overlap, and cross-family structural duplicates, including fixed-source overlap.
It requires a new output directory and never overwrites an existing export.
Use `--dataset PATH` to prepare a separately curated, versioned subset rather than
silently skipping unapproved records. Preserve family membership when curating it.

Family assignment uses a fixed SHA-256 rule with approximately 70/15/15 allocation
to train/validation/test. Adding families does not move existing ones. The current
draft assigns 7 families to training, 1 to validation, and 2 to testing. Small splits
need not match the percentages; one validation family is too little for a useful
generalization estimate. Expand the dataset before a meaningful training comparison.

The export contains:

- `explanation.train.jsonl` and `explanation.validation.jsonl`: TRL conversational
  prompt/completion records matching the current Ollama interface. Only vulnerable
  cases in those splits produce explanation training examples.
- `manifest.json`: all record IDs by split, family assignments, dataset hash,
  prompt and implementation hashes, output hashes, and explanation counts.

Safe and insufficient-context cases remain in the manifest for future independent
detection evaluation. No test completions are exported. Keeping test data sealed
from tuning is still a workflow responsibility; source records are visible locally.
Use completion-only loss and verify actual tokenizer lengths and masks before
training. The character limit in validation is not a token-length check.

## Observed checks and limitations

The 15 dataset tests verify pending-review rejection, stale approvals, family
separation, development-fixture exclusion, deterministic exports, and prompt/output
compatibility with the real AI client. All 130 backend tests passed on November 23,
2026. A three-case offline development evaluation was saved under `.cache/ai-evaluation`;
it made no model request and supplies no AI-quality score.

The scanner flags all eight draft vulnerable examples. It also flags the safe
`membership_list` and `report_sort` variants, whose generated placeholders and fixed
identifier allowlist require more context than the current rules interpret. Preserve
these disagreements for label review; scanner output is not the training ground truth.

Next work is independent review, more varied families, verified GPU/backend access,
a separately pinned training environment, and a one-batch training smoke test.
