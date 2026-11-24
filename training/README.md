# SQL training pilot

This directory contains 18 newly authored draft Python examples in 10 families:
8 suspected vulnerable cases, 8 safe counterparts, and 2 cases needing more context.
These are educational SQL/SQLite examples, not independently validated ground truth.
All records have pending label review and data screening. No model has been trained.

Dataset preparation and an opt-in explanation LoRA runner are implemented. Independent
detection and patch generation remain separate work. The runner has unit tests and
a mocked smoke workflow; a real GPU/model training smoke test has not run.
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

A subsequent host check outside the sandbox found `/dev/kfd`, `/dev/dri`, and an
AMD Navi 23 Radeon RX 6600-class GPU with about 8 GiB VRAM. The earlier missing
device nodes were a sandbox observation. PyTorch/ROCm training remains unverified.
The card is not listed in the checked
[ROCm 7.2.1 Radeon table](https://rocm.docs.amd.com/projects/radeon-ryzen/en/docs-7.2.1/docs/compatibility/compatibilityrad/native_linux/native_linux_compatibility.html);
check the [current AMD matrix](https://rocm.docs.amd.com/en/latest/compatibility/compatibility-matrix.html)
against the exact GPU, OS, and Python before selecting a backend. Device-node
presence and working Ollama inference alone do not verify PyTorch training support.

`validate` checks schema, source hashes, evidence-line bounds, Python syntax,
provenance, review metadata, and structural overlap. It does not execute snippets
or certify their labels, source permissions, fixes, or secret-free status.
AST fingerprints ignore comments, formatting, and simple local identifier renames.
This catches some clones, not all semantic duplicates. Review related variants and
assign them to one family before accepting the dataset.

`preview` shows the exact single-finding prompt and draft completion, plus the
record hash needed for approval. The runtime exposes only a short execution
excerpt and rule metadata. Draft version 2 puts query construction in the execution
excerpt, rather than giving different source examples identical bounded prompts.
Export also rejects identical prompts across splits. The separate `explanation_target` uses
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

### Use a review worksheet

An initial worksheet is available locally at `.cache/training/sql-review-round-1.json`.
To create a fresh worksheet in a new file:

```bash
python -m app.training_data review-packet --output .cache/training/sql-review-round-2.json
```

Each entry contains the complete source record, fixed code where available,
record hash, split, scanner observations, and the bounded training example.
Only fill its `decisions.review` and `decisions.screening` fields after completing
the corresponding checks. Use your actual reviewer identifier, ISO date, and
specific rationale. Leave unreviewed decisions `pending`; use `rejected` for
examples needing correction. The worksheet includes test-label review, so keep
that portion separate from model/prompt tuning.

Import completed decisions to a new dataset, preserving the original draft:

```bash
python -m app.training_data apply-reviews \
  --packet .cache/training/sql-review-round-1.json \
  --output .cache/training/sql-reviewed-v1.json \
  --version sql-reviewed-v1
python -m app.training_data validate --dataset .cache/training/sql-reviewed-v1.json
```

The importer checks the exact dataset snapshot, record contents, and bounded
prompt/target. It rejects stale or edited worksheet content and self-approval by
the recorded author. Correct source or annotations in the draft dataset, update
its source hash if needed, and generate a fresh worksheet before reviewing again.
Partial review can be saved; it remains ineligible for export. To export a fully
approved reviewed copy, pass its path explicitly:

```bash
python -m app.training_data prepare \
  --dataset .cache/training/sql-reviewed-v1.json \
  --output .cache/training/sql-pilot-reviewed-v1
```

Also pass `--dataset .cache/training/sql-reviewed-v1.json` and the matching
`--export` path to `app.train_adapter` when using this reviewed copy.

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

The 24 dataset tests verify pending-review rejection, stale approvals, family
separation, development-fixture exclusion, deterministic exports, and prompt/output
compatibility with the real AI client. Nine additional runner tests cover export
integrity, token masking, length rejection, and mocked training orchestration.
All 148 backend tests passed on November 23, 2026 outside the sandbox; the same
suite stalled in an existing API test inside the sandbox.
A three-case offline development evaluation was saved under `.cache/ai-evaluation`;
it made no model request and supplies no AI-quality score.

The scanner flags all eight draft vulnerable examples. It also flags the safe
`membership_list` and `report_sort` variants, whose generated placeholders and fixed
identifier allowlist require more context than the current rules interpret. Preserve
these disagreements for label review; scanner output is not the training ground truth.

Qwen `qwen2.5-coder:3b` was installed in local Ollama on November 23, 2026
(reported size 1.9 GB, abbreviated model ID `f72c60cabf62`). A live two-case
development evaluation produced one explanation for `python_eval_positive` and
made no model request for `python_eval_negative`. Its report is saved locally as
`.cache/ai-evaluation/552099ce-8a0a-44e5-a895-6620f1868c4f.json`.
It has no human score and performs no fine-tuning.
A second live run of `sql_positive` and `sql_negative` completed with one SQL
explanation and no request for the safe case, saved as
`.cache/ai-evaluation/01e29f9c-8cb1-43db-bf97-26ab123b6a3c.json`.
This SQL baseline also awaits human review and supplies no AI detection metric.

## Run the adapter experiment

You can inspect current readiness without installing training libraries:

```bash
.venv/bin/python -m app.train_adapter check
```

The current draft is not trainable yet: all 18 records await review, training
packages are absent, and GPU access is unverified. `check` reports these conditions;
it makes no inference request and updates no weights. The `train` command cannot
bypass missing record review or use stale exports.

After review, export with `app.training_data prepare` as above. Verify the export
without importing the training stack or loading a model:

```bash
.venv/bin/python -m app.train_adapter dry-run --export .cache/training/sql-pilot-v1
```

For actual training, create `.venv-training` using a Python version supported by
the selected PyTorch backend. Install the GPU-specific PyTorch build using its
official platform instructions, then install project and training dependencies:

```bash
.venv-training/bin/python -m pip install -r requirements.txt -r training/requirements.in
.venv-training/bin/python -m pip freeze > .cache/training-environment.txt
```

`requirements.in` is a candidate dependency range, not a tested lockfile. Record
the resolved versions after the hardware test. Do not install a CUDA build for
the AMD GPU. The runner checks `torch.cuda.is_available()` for both CUDA and ROCm;
ROCm PyTorch exposes AMD devices through this API. Normal LoRA is supported by
the runner on either backend; its optional `--four-bit` path is restricted to
CUDA with a separately installed compatible bitsandbytes build.

Obtain the exact 40-character commit revision from the
[Qwen model repository](https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct/commits/main).
Set `MODEL_REVISION` to that actual commit hash. Download the matching checkpoint
and tokenizer once in the training environment:

```bash
HF_HOME="$PWD/.cache/huggingface" .venv-training/bin/hf download Qwen/Qwen2.5-Coder-3B-Instruct --revision "$MODEL_REVISION"
```

This is a multi-gigabyte weight download. The training commands themselves use
only local cached weights and refuse missing files. They do not load `.env` or
reuse the quantized model installed in Ollama.

Start with a single optimizer step in a new directory:

```bash
.venv-training/bin/python -m app.train_adapter smoke \
  --export .cache/training/sql-pilot-v1 \
  --output .cache/training/sql-smoke-1 \
  --revision "$MODEL_REVISION"
```

After a successful smoke test and review of memory/token lengths, start one pass
through the training split with a fresh adapter and new output directory:

```bash
.venv-training/bin/python -m app.train_adapter train \
  --export .cache/training/sql-pilot-v1 \
  --output .cache/training/sql-round-1 \
  --revision "$MODEL_REVISION"
```

The runner uses Transformers Trainer and PEFT with explicit completion-only
labels, so TRL is not required. It rejects incompatible chat templates and records
over 2,048 tokens instead of truncating targets. LoRA uses rank 8, alpha 16,
dropout 0.05, and learning rate `5e-5`. A normal run uses gradient accumulation 8,
at most one epoch, validation/checkpoints every five optimizer steps, and early
stopping after two checks without validation-loss improvement. Very small runs
can finish before a periodic checkpoint; baseline and final validation still run.
The smoke run uses accumulation 1 and exactly one optimizer step.

`run.json` records the immutable base revision, dataset/export/runner hashes,
package versions, token lengths, settings, validation losses, and training status.
`adapter/` contains only the adapter and tokenizer, not a deployed Ollama model.
All output stays local under the selected directory. The runner does not upload
artifacts, automatically deploy, merge weights, or change the scanner's model.
Validation-loss improvement is not evidence of secure detection or repair; perform
the human output review before selecting a deployment candidate.

Next work is independent review, more varied families, verified GPU/backend access,
a resolved training environment, and a real one-step smoke test. Base-versus-adapter
generated-output comparisons and served-model evaluation remain pending.
