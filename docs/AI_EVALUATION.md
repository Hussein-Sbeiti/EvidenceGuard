# AI agent evaluation and human review

The agent's task is narrow: explain findings already detected by rules and suggest
defensive fixes for a person to review. It has no execution tools, cannot modify
uploads, and cannot run repairs. The proposed gradual fine-tuning workflow is in
[AI training plan](AI_TRAINING_PLAN.md); this evaluator does not update model weights.

## Development runs

From the repository root with the virtual environment activated:

```bash
python -m app.ai_evaluate run --limit 3
```

This offline baseline makes no Ollama request. To pair the deterministic rules
with actual local AI explanations on the same existing synthetic examples:

```bash
python -m app.ai_evaluate run --ai --case python_eval_positive --case python_eval_negative --limit 2
```

`--ai` is explicit opt-in. Default selection is the first three cases in corpus
order. `--case` can be repeated; selected IDs retain corpus order, and `--limit`
caps the number of cases, not model requests. A case with no rule findings makes
no inference request. Each case has the scanner's existing five-finding limit and
60-second socket timeout. There are no automatic retries or background jobs.
Larger evaluations may take several minutes. Stop between cases with Ctrl+C;
a report is saved only after the selected batch completes.

The command prints a unique report path under `.cache/ai-evaluation/`. Runs and
reviews are new files; previous artifacts are never overwritten by these commands.
This directory is ignored by Git. Use `--output-dir` to choose another local
location. Do not commit run artifacts without reviewing their contents.
The CLI reads `OLLAMA_MODEL` from the process environment (default
`qwen2.5-coder:3b`); unlike the uvicorn `--env-file` command, it does not load `.env`.

Records include run ID, UTC times, requested/returned model tags, the installed
model digest observed **before** the batch, prompt version/hash, analyzer hashes,
dataset/source hashes, case/finding references, rule recommendations, AI output,
and generation statuses. The digest is an observation before generation, not proof
that a model tag was unchanged throughout the batch. Label-review provenance stays
visible. Browser scans receive a run ID too, but still stay in browser memory until
exported; normal uploaded files are not automatically written to evaluation history.

If runtime/model checks fail, generation is skipped with an explicit unavailable
status; rule results remain in the report. Missing output never receives a zero
quality score by default: it remains unreviewed/unavailable.

## What the comparison means

Reports pair rule findings/recommendations with AI explanations for the same cases.
TP, FP, FN, TN, precision, and recall describe the **deterministic detector** against
the existing provisional labels. Repeated occurrences count once per case/rule.
AI explains those detections; it is not an independent detector, so assigning it
separate detection precision/recall would be misleading. Human explanation scores
are reported separately. Neither result estimates real-world application security.
The 65 labels still await independent review; this workflow does not supply sign-off.

## Human review rubric, version explanation-review-v1

Read the referenced snippet in `evaluation/cases.json`, the rule recommendation,
and every part of the AI answer before rating. A score of 2 requires checking the
answer, not merely agreeing with the model's confidence.

| Criterion | 0 | 1 | 2 |
| --- | --- | --- | --- |
| Correctness | Wrong or unsupported conclusion | Partly correct, overstates risk, or misses key uncertainty | Accurate conditional explanation with appropriate limits |
| Evidence | Wrong/missing connection to the flagged operation | Relevant operation but vague or incomplete location/context | Correct line/operation reference and clear connection to the supplied evidence |
| Remediation | Unsafe, irrelevant, or contradicts the rule's defensive guidance | Safe direction but incomplete or too vague to apply | Safe, relevant steps and appropriate verification guidance |

Score = `(correctness + evidence + remediation) / 6 * 100`, rounded to two decimals.
If remediation is 0, the overall score is 0 regardless of the other ratings. This
manual quality score is not a vulnerability probability or a training reward fed
back into the model. Unreviewed outputs have no score.

Replace `REPORT.json` with the printed run path and use your actual reviewer ID:

```bash
python -m app.ai_evaluate review REPORT.json --case python_eval_positive --finding-index 0 --reviewer YOUR_REVIEWER_ID --correctness 2 --evidence 1 --remediation 2 --rationale "Explains the risk accurately but needs a clearer line reference."
python -m app.ai_evaluate summary REPORT.json
```

The ratings above illustrate syntax; choose ratings from your own review.
`finding-index` is the AI entry's `finding_index` within that case. Reviews must
reference an existing explanation and supply a non-empty reviewer ID and rationale.
Each review creates a new JSON file in the report's adjacent `.reviews` directory,
bound to the exact report SHA256. Re-reviewing preserves the earlier record.
The summary uses the latest review per case/finding, shows how many reviews remain,
and reports the history count. It rejects reviews bound to a modified report or
whose numeric score disagrees with the rubric. Files are locally editable; hashes
help detect accidental mismatches but are not cryptographic signatures or a
protected audit log. Reviewer identity is self-reported, not authenticated.

## Data boundaries and pending work

The evaluator accepts IDs only from the repository's authored synthetic corpus;
there is no arbitrary-upload ingestion or dataset harvesting. It saves source
references/hashes rather than full source files. AI output and human comments are
stored, so keep real secrets and personal data out of fixtures and review comments.
Credential-rule evidence is withheld by the normal AI client, but this is not a
general secret-redaction guarantee for arbitrary snippets or generated text.

These records are development evaluation artifacts, not an approved training
corpus. Source permissions, independent label review, held-out data, broader
quality evaluation, and any future training-data screening remain separate work.
No training, model weight updates, or reinforcement learning is performed.

## Recorded verification

On November 18, 2026, a development run of `python_eval_positive` with local
`qwen2.5-coder:3b` completed and saved one AI explanation with its model digest and
input/dataset/implementation metadata. It remained pending human review; no model
quality score or independent sign-off was assigned. An offline three-case run
saved the deterministic baseline without checking or calling Ollama. Automated
tests exercise review scoring/history, invalid references, unavailable runtime,
modified-report detection, and frontend readiness status.
