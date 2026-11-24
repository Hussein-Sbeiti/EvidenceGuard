"""Opt-in, local-only LoRA runner. Check/dry-run never load model weights."""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import re

from app.training_data import (DEFAULT_DATASET, ROOT, SPLIT_VERSION, doctor, explanation_example,
                               sha256, split_for, validate_dataset)
from app.ai import PROMPT_VERSION, SYSTEM

MODEL = 'Qwen/Qwen2.5-Coder-3B-Instruct'
PACKAGES = ('torch', 'transformers', 'peft', 'accelerate')


def readiness(dataset=DEFAULT_DATASET):
    data = validate_dataset(dataset)
    inventory = doctor()
    pending = sum(r['review']['status'] != 'approved' or r['screening']['status'] != 'approved'
                  for r in data['records'])
    missing = [name for name in PACKAGES if not _installed(name)]
    return {'training_performed': False, 'unapproved_records': pending, 'missing_packages': missing,
            'device_nodes_visible': inventory['device_nodes_visible'],
            'gpu_verified': False, 'data_and_packages_ready': pending == 0 and not missing,
            'notice': 'Package presence is not a GPU test. Run smoke only after export and backend setup.'}


def _installed(name):
    try:
        importlib.metadata.version(name)
        return True
    except importlib.metadata.PackageNotFoundError:
        return False


def load_export(dataset, directory):
    """Reconstruct approved examples and verify the manifest and bytes before training."""
    dataset, directory = Path(dataset), Path(directory)
    before = dataset.read_bytes()
    data = validate_dataset(dataset)
    if dataset.read_bytes() != before:
        raise ValueError('Dataset changed during validation.')
    if any(r['review']['status'] != 'approved' or r['screening']['status'] != 'approved' for r in data['records']):
        raise ValueError('Training requires approved review and screening for every dataset record.')
    manifest = json.loads((directory / 'manifest.json').read_text())
    if (manifest.get('schema_version') != 1 or manifest.get('dataset_sha256') != hashlib.sha256(before).hexdigest()
            or manifest.get('dataset_version') != data['version'] or manifest.get('split_version') != SPLIT_VERSION
            or manifest.get('prompt_version') != PROMPT_VERSION or manifest.get('system_sha256') != sha256(SYSTEM)):
        raise ValueError('Stale or incompatible export; prepare a new export from the current reviewed dataset.')
    for name in ('training_data.py', 'ai.py', 'scanner.py', 'sql_analysis.py'):
        actual = hashlib.sha256((ROOT / 'app' / name).read_bytes()).hexdigest()
        if manifest.get('implementation_sha256', {}).get(name) != actual:
            raise ValueError('Implementation changed since export; prepare a new export.')
    expected, splits, prompt_splits = {'train': [], 'validation': []}, {s: [] for s in ('train', 'validation', 'test')}, {}
    for record in sorted(data['records'], key=lambda r: r['id']):
        split = split_for(record['family'])
        splits[split].append(record['id'])
        if record['label'] == 'vulnerable':
            example = explanation_example(record)
            key = sha256(json.dumps(example['prompt'], sort_keys=True))
            if key in prompt_splits and prompt_splits[key] != split:
                raise ValueError('Identical bounded prompts cross dataset splits.')
            prompt_splits[key] = split
            if split != 'test':
                expected[split].append(example)
    if manifest.get('splits') != splits or any(not ids for ids in splits.values()):
        raise ValueError('Invalid split manifest.')
    for split, examples in expected.items():
        name = f'explanation.{split}.jsonl'
        raw = (directory / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != manifest.get('file_sha256', {}).get(name):
            raise ValueError('Export file hash mismatch: ' + name)
        if not examples or [json.loads(line) for line in raw.decode('utf-8').splitlines()] != examples:
            raise ValueError('Export differs from approved records: ' + name)
    return manifest, expected


def tokenize_examples(examples, tokenizer, max_length=2048):
    """Explicit completion-only labels; fail instead of silently truncating the answer."""
    result = []
    for index, example in enumerate(examples):
        prefix = tokenizer.apply_chat_template(example['prompt'], tokenize=True, add_generation_prompt=True)
        full = tokenizer.apply_chat_template(example['prompt'] + example['completion'],
                                             tokenize=True, add_generation_prompt=False)
        if not prefix or full[:len(prefix)] != prefix or len(full) <= len(prefix):
            raise ValueError(f'Example {index}: chat template does not preserve the assistant prefix.')
        if len(full) > max_length:
            raise ValueError(f'Example {index}: {len(full)} tokens exceeds {max_length}; shorten and re-review it.')
        result.append({'input_ids': full, 'attention_mask': [1] * len(full),
                       'labels': [-100] * len(prefix) + full[len(prefix):]})
    return result


def run(dataset, directory, output, revision, smoke=False, four_bit=False):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Use an immutable 40-character Hugging Face model commit revision, not main or a tag.')
    manifest, examples = load_export(dataset, directory)
    output = Path(output)
    if output.exists():
        raise ValueError('Output directory already exists; use a new run directory.')
    missing = [name for name in PACKAGES if not _installed(name)]
    if missing:
        raise ValueError('Install training dependencies in a separate environment: ' + ', '.join(missing))
    # No telemetry, remote experiment tracking, auto-upload, or implicit weight downloads.
    os.environ['HF_HUB_OFFLINE'] = '1'
    os.environ['HF_HUB_DISABLE_TELEMETRY'] = '1'
    os.environ['WANDB_DISABLED'] = 'true'
    os.environ.setdefault('HF_HOME', str(ROOT / '.cache' / 'huggingface'))
    import torch
    from transformers import (AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig,
                              DataCollatorForSeq2Seq, EarlyStoppingCallback, Trainer, TrainingArguments, set_seed)
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

    if not torch.cuda.is_available():
        raise ValueError('No CUDA/ROCm GPU available to PyTorch. Resolve backend access before smoke training.')
    if four_bit and (torch.version.hip or not _installed('bitsandbytes')):
        raise ValueError('This runner supports optional 4-bit loading only on CUDA with bitsandbytes installed.')
    set_seed(733)
    tokenizer = AutoTokenizer.from_pretrained(MODEL, revision=revision, local_files_only=True, trust_remote_code=False)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenized = {split: tokenize_examples(rows, tokenizer) for split, rows in examples.items()}
    dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float32
    kwargs = {'revision': revision, 'local_files_only': True, 'trust_remote_code': False,
              'torch_dtype': dtype, 'device_map': {'': 0}, 'attn_implementation': 'eager'}
    if four_bit:
        kwargs['quantization_config'] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type='nf4',
                                                          bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=dtype)
    model = AutoModelForCausalLM.from_pretrained(MODEL, **kwargs)
    model.config.use_cache = False
    if four_bit:
        model = prepare_model_for_kbit_training(model)
    else:
        model.enable_input_require_grads()
    model = get_peft_model(model, LoraConfig(r=8, lora_alpha=16, lora_dropout=0.05,
                                            target_modules='all-linear', task_type='CAUSAL_LM', bias='none'))
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    config = dict(output_dir=str(output / 'checkpoints'), num_train_epochs=1,
                  max_steps=1 if smoke else -1, learning_rate=5e-5, per_device_train_batch_size=1,
                  per_device_eval_batch_size=1, gradient_accumulation_steps=1 if smoke else 8,
                  gradient_checkpointing=True, gradient_checkpointing_kwargs={'use_reentrant': False},
                  bf16=dtype == torch.bfloat16, fp16=False, optim='adamw_torch', seed=733, data_seed=733,
                  eval_strategy='steps', eval_steps=5, save_strategy='steps', save_steps=5,
                  save_total_limit=2, load_best_model_at_end=not smoke,
                  metric_for_best_model='eval_loss', greater_is_better=False,
                  report_to='none', push_to_hub=False, logging_steps=1)
    trainer = Trainer(model=model, args=TrainingArguments(**config),
                      train_dataset=tokenized['train'], eval_dataset=tokenized['validation'],
                      data_collator=DataCollatorForSeq2Seq(tokenizer, label_pad_token_id=-100, pad_to_multiple_of=8),
                      callbacks=[] if smoke else [EarlyStoppingCallback(early_stopping_patience=2)])
    run_info = {'schema_version': 1, 'status': 'initializing', 'training_started': False,
                'created_at': datetime.now(timezone.utc).isoformat(), 'model': MODEL, 'revision': revision,
                'mode': 'smoke' if smoke else 'one_epoch', 'four_bit': four_bit,
                'export_manifest_sha256': hashlib.sha256((Path(directory) / 'manifest.json').read_bytes()).hexdigest(),
                'dataset_sha256': manifest['dataset_sha256'], 'settings': config,
                'versions': {name: importlib.metadata.version(name) for name in PACKAGES},
                'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'device': torch.cuda.get_device_name(0), 'hip': torch.version.hip,
                'token_lengths': {split: [len(row['input_ids']) for row in rows] for split, rows in tokenized.items()}}
    def save_run():
        (output / 'run.json').write_text(json.dumps(run_info, indent=2) + '\n')
    save_run()
    try:
        run_info['baseline'] = trainer.evaluate()
        if not math.isfinite(run_info['baseline']['eval_loss']):
            raise ValueError('Non-finite baseline loss; training has not started.')
        run_info.update(status='training', training_started=True)
        save_run()
        trainer.train()
        run_info['candidate'] = trainer.evaluate()
        trainer.save_model(str(output / 'adapter'))
        tokenizer.save_pretrained(output / 'adapter')
        initial = run_info['baseline']['eval_loss']
        final = run_info['candidate']['eval_loss']
        if not math.isfinite(initial) or not math.isfinite(final):
            raise ValueError('Non-finite validation loss; candidate is unusable.')
        run_info.update(status='complete', validation_loss_improved=final < initial,
                        deployment_approved=False, peak_allocated_bytes=torch.cuda.max_memory_allocated(),
                        notice='Validation loss is not security accuracy. Smoke output is diagnostic only. Human remediation review is required.')
        save_run()
    except BaseException:
        run_info['status'] = 'failed_or_interrupted'
        save_run()
        raise
    return run_info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('check', 'dry-run', 'smoke', 'train'))
    parser.add_argument('--dataset', type=Path, default=DEFAULT_DATASET)
    parser.add_argument('--export', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--revision', default='')
    parser.add_argument('--four-bit', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'check':
            result = readiness(args.dataset)
        else:
            if args.export is None:
                raise ValueError('--export is required.')
            if args.command == 'dry-run':
                _, examples = load_export(args.dataset, args.export)
                result = {'training_performed': False, 'export_verified': True,
                          'counts': {split: len(rows) for split, rows in examples.items()},
                          'notice': 'No weights loaded; tokenizer and GPU have not been tested.'}
            else:
                if args.output is None:
                    raise ValueError('--output is required.')
                result = run(args.dataset, args.export, args.output, args.revision,
                             smoke=args.command == 'smoke', four_bit=args.four_bit)
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, TypeError, KeyError, ImportError, RuntimeError) as error:
        parser.exit(1, f'Training error: {error}\n')


if __name__ == '__main__':
    main()
