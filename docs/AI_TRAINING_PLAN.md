# Lightweight AI training for CSC 733

The goal is a small local model that identifies vulnerable code, explains the evidence,
and proposes a minimal defensive fix. Start with Qwen 2.5 Coder 3B and a small LoRA
adapter, using short, measured experiments on reviewed examples. Adding examples
gradually is sensible; training continuously on every upload is not part of this plan.
Fine-tuning specializes behavior but does not reduce the base model's parameter count.

This is the proposed development plan as of November 23, 2026. No training has run,
no approved training dataset exists yet, and the runtime remains explanation-only.
The [SQL pilot workflow](../training/README.md) now includes 18 draft examples in
10 families, validation, grouped split preparation, bounded prompt previews, and
review gates. All draft records await review and data screening. Training libraries
and GPU device access are unavailable in the inspected project execution environment;
a training smoke test has not run.

## What already exists

`app/ai.py` sends existing rule findings to local Ollama and validates the returned
JSON. It uses temperature 0, an 8,192-token context limit, a 2,400-token output cap,
a 60-second socket timeout, and at most five findings per request. Each finding
includes at most 300 characters of evidence; credential evidence is withheld.
The model has no execution or file-editing tools. These are useful starting boundaries.

The AI does not examine clean files, discover independent findings, or generate
validated patches. Training alone cannot add those application capabilities.
The existing 65 synthetic cases are development regressions with provisional labels;
keep them out of the new training corpus and do not present them as held-out evidence.
See [AI evaluation](AI_EVALUATION.md) for the existing explanation review workflow.

## Stages and first experiment

1. **Measure the current model.** Run a small development batch using the existing
   evaluator and manually review explanations. Record errors, latency, output validity,
   model digest, and prompt version before changing weights.
2. **Curate one narrow topic.** Begin with Python SQL injection and parameterized
   SQLite queries. Collect 20–30 independently authored example families for a pilot,
   including vulnerable, safe, and insufficient-context cases. Have a person review
   labels and fixes. This pilot checks the workflow, not general security accuracy.
3. **Train explanation behavior first.** Use the current finding input and exact
   `explanations` response contract. Compare a fresh small adapter with the base
   model on validation examples. This can improve explanation/remediation behavior
   without changing scanner detection semantics.
4. **Add independent detection as an explicit feature.** Give the model bounded
   functions and relevant imports, bindings, and callers, including safe code.
   Use a separate output contract and benchmark. Label AI findings separately from
   rule results; support `insufficient_context` as well as suspected issues and
   no issue found within the supplied scope.
5. **Add patch proposals and verification.** Produce a diff against the exact input
   revision, check syntax, rerun analysis, and test behavior. Test generated code
   only in an isolated environment with resource limits, no credentials, and no
   network. Show the patch for human review before applying it.

For stage 1, the existing commands are:

```bash
python -m app.ai_evaluate run --limit 3
python -m app.ai_evaluate run --ai --case python_eval_positive --limit 1
```

The first command is offline. The second calls local Ollama and saves a development
artifact under `.cache/ai-evaluation`; it is not a training command.

## Model and training method

Use the instruction checkpoint
[`Qwen/Qwen2.5-Coder-3B-Instruct`](https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct)
with its tokenizer/chat template and a pinned repository revision. Its model card
lists the Qwen Research license; retain the exact
[license](https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct/blob/main/LICENSE)
with experiment records. Record the installed Ollama model digest separately;
do not assume its tag establishes identical training weights or tokenizer.

LoRA trains added adapter parameters while leaving the base frozen. QLoRA combines
this with a quantized base to reduce training memory. Hugging Face's
[PEFT quantization guide](https://huggingface.co/docs/peft/developer_guides/quantization)
documents 4-bit loading, NF4, preparation for training, and LoRA targeting linear layers.
Use a separate training environment so PyTorch and training libraries do not change
the scanner's runtime dependencies.

Proposed initial settings below are experiment choices, not proven optimal values:

| Setting | Starting choice |
| --- | --- |
| Method | Supervised fine-tuning with LoRA; QLoRA if supported by the training hardware |
| LoRA | Rank 8, alpha 16, dropout 0.05, `target_modules="all-linear"` |
| Learning rate | `5e-5` |
| Training budget | At most one pass through the training split for the first experiment |
| Batch | Microbatch 1, gradient accumulation 8 |
| Sequence limit | 2,048 tokens including input and answer; reject overlength records |
| Memory | Gradient checkpointing; supported compute dtype after hardware verification |
| Loss | Completion tokens only for a prompt/completion dataset |
| Validation | Every 5 optimizer steps and at the end; evaluate before training too |
| Artifacts | Save matching checkpoints, validation results, dataset hashes, seed, and dependency versions |

Use [TRL's SFT trainer](https://huggingface.co/docs/trl/sft_trainer) with a conversational
prompt/completion dataset and completion-only loss. Verify token masking on an actual
record before a run. Assistant-only masking has chat-template requirements; do not
assume the Qwen 2.5 template supplies them. Keep the system prompt and JSON contract
aligned with the runtime. A small dataset may produce fewer than five optimizer
steps, so end-of-run validation is essential.

The inspected development machine reports about 29 GiB RAM and an AMD Navi 23
Radeon GPU; no `nvidia-smi` executable was found. GPU training compatibility and
VRAM have not been verified. Confirm the PyTorch/backend/quantization combination
with a one-batch smoke test before choosing a training stack. An Ollama model running
locally does not establish that this machine supports a given fine-tuning backend.

## Dataset contents and separation

Prefer project-authored Python examples first. For each example, store:

- Stable ID, language, task, and family/group ID linking vulnerable and fixed variants.
- Source, relevant context, expected label, CWE where applicable, evidence lines,
  brief rationale, minimal fixed code or diff, and behavior/security checks.
- Source origin, author or source URL/revision, license or permission record,
  reviewer ID, review date, and review status.
- Screening status for secrets and personal data, source hash, dataset version,
  and assigned split. Only approved records become training inputs.

For explanation training, derive the prompt from the same bounded finding fields
the runtime provides, and write a reviewed response in its existing JSON schema.
Avoid answers requiring context withheld from the prompt. Detection and patch
training need separate task records with the additional code context they require.
Do not train the current explanation interface on a different detection schema.

Use safe counterexamples that are structurally similar to vulnerable examples:
parameterized SQL, constant queries, overwritten unsafe values, and missing input
origins. A fixed version is not automatically safe if it changes intended behavior
or leaves another unsafe path. Review the actual security conditions.

Assign approximately 70% of independent families to training, 15% to validation,
and 15% to a frozen test set. Keep each vulnerable/fixed pair, paraphrase, rename,
and derived variant in one split. Deduplicate exact and structural near-duplicates
before assignment; use separate projects where possible for a later external test.
The tiny pilot's test counts will be too small for strong accuracy claims.
Public examples may already be in base-model pretraining, so split separation alone
does not establish absence of pretraining contamination.

Do not copy the current evaluation corpus or its model-generated explanations into
training. Never automatically harvest uploads, `.env`, review comments, or AI output.
New records need source permission, screening, and human review.

For later research, [PrimeVul](https://github.com/DLVulDet/PrimeVul) offers paired
vulnerable/benign functions, deduplication, and chronological splitting. It is a
C/C++ corpus, so it is not the first training source for this Python-focused pilot.
Record permissions for underlying source examples separately from a dataset
repository's license. CVE descriptions and Exploit-DB metadata are not labeled
source-and-fix training pairs.

## Gradual updates without overfitting

Add 10–20 new reviewed families at a time, then version the cumulative training
set. For this small project, train each candidate from the same frozen base with
a fresh adapter on that cumulative set. This makes comparisons easier and avoids
silently accumulating many training passes on old examples. A resumed experiment
must record its previous exposures and replay older approved examples to check
forgetting. Reducing batch size alone does not prevent overfitting.

Watch for decreasing training loss alongside increasing validation loss, worse
safe-code performance, memorized wording, and regressions on earlier categories.
Use early stopping after two validation checks without improvement and retain the
best checkpoint; [Transformers callbacks](https://huggingface.co/docs/transformers/main_classes/callback)
support validation-based early stopping. A one-pass pilot may finish before that
rule triggers. Do not add more epochs merely because the training score is high.

Use validation results for checkpoint and parameter choices. Keep the test set
sealed until a release candidate; repeated tuning on test results turns it into
development data. Compare base and adapter using identical inputs and inference
settings. Reject a candidate that introduces an unsafe fix in the reviewed
validation suite, even if average explanation scores improve.

Measure each capability separately:

- Explanations: correctness, evidence, safe remediation, JSON validity, latency,
  and failures using the existing human review rubric.
- Independent detection: TP/FP/TN/FN, precision, recall, F1, false-positive rate,
  and abstention coverage on both vulnerable and safe code. Report counts per CWE;
  do not exclude abstentions silently or count them as correct safe predictions.
- Patches: syntax validity, security checks, behavior preservation, and human
  acceptance. A clean scanner result alone does not prove a repair is correct.
- Deployment: peak memory, model artifact size, and latency on the target machine.

## Context and thinking

Start by supplying relevant function boundaries, line numbers, imports, and local
value flow within a fixed token budget. Ask for a brief evidence-based rationale,
assumptions, and verification steps. Longer answers do not establish better analysis.

Do not assume a `think=true` flag gives Qwen 2.5 Coder a new reasoning capability.
[Ollama thinking controls](https://docs.ollama.com/capabilities/thinking) depend on
model support. Test any optional second verification pass against its added latency;
keep a bounded number of calls. Training is not a substitute for missing code context.

## Deployment and next implementation work

After a candidate passes validation, preserve its adapter, base revision, tokenizer,
and run manifest. Verify the installed serving stack supports the exact architecture
and import path. One route is to merge the adapter into the original base outside
the app, convert/quantize with compatible tooling, and import the resulting GGUF.
[Ollama's import guide](https://docs.ollama.com/import) documents GGUF import;
conversion and quantization must happen beforehand. Reevaluate the served artifact
because quantization can change its outputs. Keep the previous model for rollback.

The next implementation batch should create a reviewed-record schema, a dataset
validator, stable family-based split manifests, and a separately pinned training
environment after the hardware smoke test. Then run the single-topic pilot and
record the base-versus-adapter comparison. Broaden to shell commands and unsafe
deserialization only after the first topic has measurable validation results.
