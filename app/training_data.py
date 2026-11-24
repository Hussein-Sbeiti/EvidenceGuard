"""Validate reviewed SQL pilot records and prepare reproducible, grouped splits.

Never executes snippets, trains a model, downloads weights, or ingests uploads.
"""

import argparse
import ast
from collections import Counter
from datetime import date
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from app.ai import PROMPT_VERSION, SYSTEM
from app.scanner import scan_source

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = ROOT / 'training' / 'sql_pilot.json'
SPLIT_VERSION = 'family-sha256-v1'
LABELS = {'vulnerable', 'safe', 'insufficient_context'}


def sha256(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def fingerprint(source):
    """Catch formatting/comment changes and simple identifier renames, not all clones."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            node.id = '_'
        elif isinstance(node, ast.arg):
            node.arg = '_'
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node.name = '_'
    return sha256(ast.dump(tree, include_attributes=False))


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def record_digest(record):
    """Bind approvals to code, annotations, provenance, and bounded response targets."""
    payload = {k: v for k, v in record.items() if k not in {'review', 'screening'}}
    return sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True))


def validate_dataset(path=DEFAULT_DATASET, evaluation_path=ROOT / 'evaluation' / 'cases.json'):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data, dict) or data.get('schema_version') != 1 or not nonempty(data.get('version')):
        raise ValueError('Expected dataset schema_version 1 and a version.')
    records = data.get('records')
    if not isinstance(records, list) or not records:
        raise ValueError('Dataset must contain records.')
    # Exclude development fixtures even when only whitespace or local names changed.
    reserved = set()
    for case in json.loads(Path(evaluation_path).read_text(encoding='utf-8'))['cases']:
        if case['filename'].endswith('.py'):
            try:
                reserved.add(fingerprint(case['source']))
            except SyntaxError:
                pass  # Incomplete-parser fixtures are not eligible Python training records.
    ids, fingerprints, family_by_code = set(), {}, {}
    required = ('id', 'family', 'source', 'rationale', 'remediation', 'limitation', 'author')
    for record in records:
        if not isinstance(record, dict) or any(not nonempty(record.get(k)) for k in required):
            raise ValueError('Each record needs nonempty ' + ', '.join(required) + '.')
        name = record['id']
        if name in ids:
            raise ValueError(f'{name}: duplicate record ID.')
        ids.add(name)
        if record.get('label') not in LABELS or record.get('language') != 'python' or record.get('cwe') != 'CWE-89':
            raise ValueError(f'{name}: expected a Python CWE-89 pilot label.')
        if record['label'] == 'vulnerable':
            target = record.get('explanation_target')
            if (not isinstance(target, dict) or set(target) != {'explanation', 'remediation', 'limitation'}
                    or any(not nonempty(v) or len(v) > 4000 for v in target.values())):
                raise ValueError(f'{name}: expected a bounded explanation_target matching the runtime schema.')
        if len(record['source']) > 16000 or record.get('source_sha256') != sha256(record['source']):
            raise ValueError(f'{name}: source too large or source_sha256 mismatch.')
        try:
            key = fingerprint(record['source'])
            if record['label'] == 'vulnerable':
                if not nonempty(record.get('fixed_source')):
                    raise ValueError(f'{name}: vulnerable records need fixed_source.')
                ast.parse(record['fixed_source'])
        except (SyntaxError, RecursionError) as error:
            raise ValueError(f'{name}: invalid Python source or fix.') from error
        if key in reserved:
            raise ValueError(f'{name}: overlaps the development evaluation corpus.')
        code_keys = [key]
        if record['label'] == 'vulnerable':
            code_keys.append(fingerprint(record['fixed_source']))
        for code_key in code_keys:
            if code_key in reserved:
                raise ValueError(f'{name}: source or fix overlaps the development evaluation corpus.')
            if code_key in family_by_code and family_by_code[code_key] != record['family']:
                raise ValueError(f'{name}: source or fix is a structural duplicate in another family.')
            family_by_code[code_key] = record['family']
        previous = fingerprints.get(key)
        if previous and previous['family'] != record['family']:
            raise ValueError(f'{name}: structural duplicate belongs to another family; group these records together.')
        if previous and previous['label'] != record['label']:
            raise ValueError(f'{name}: structural duplicate has conflicting labels.')
        fingerprints[key] = record
        lines = record.get('evidence_lines')
        if (not isinstance(lines, list) or any(type(n) is not int or not 1 <= n <= len(record['source'].splitlines()) for n in lines)
                or len(set(lines)) != len(lines) or (record['label'] == 'vulnerable' and not lines)):
            raise ValueError(f'{name}: invalid evidence_lines.')
        origin = record.get('provenance')
        if (not isinstance(origin, dict) or origin.get('kind') != 'project_authored'
                or not nonempty(origin.get('origin')) or not nonempty(origin.get('permission'))):
            raise ValueError(f'{name}: documented project authorship and permission are required.')
        review, screening = record.get('review'), record.get('screening')
        if (not isinstance(review, dict) or review.get('status') not in {'pending', 'approved', 'rejected'}
                or not isinstance(screening, dict) or screening.get('status') not in {'pending', 'approved', 'rejected'}):
            raise ValueError(f'{name}: explicit review and screening statuses are required.')
        for state in (review, screening):
            if state['status'] == 'approved' and any(not nonempty(state.get(k)) for k in ('reviewer', 'date', 'rationale')):
                raise ValueError(f'{name}: approval needs reviewer, date, and rationale.')
            if state['status'] == 'approved' and state.get('record_sha256') != record_digest(record):
                raise ValueError(f'{name}: approval is stale; review the current record hash.')
            if state['status'] == 'approved':
                try:
                    date.fromisoformat(state['date'])
                except ValueError as error:
                    raise ValueError(f'{name}: approval date must be YYYY-MM-DD.') from error
        if review['status'] == 'approved' and review['reviewer'] == record['author']:
            raise ValueError(f'{name}: label approval needs a reviewer other than the author.')
    return data


def split_for(family):
    # Fixed salt; adding families never reassigns earlier ones. Never search seeds for scores.
    bucket = int(sha256(SPLIT_VERSION + ':' + family), 16) % 100
    return 'train' if bucket < 70 else 'validation' if bucket < 85 else 'test'


def describe(data):
    records = data['records']
    return {'version': data['version'], 'records': len(records),
            'families': len({r['family'] for r in records}),
            'labels': dict(Counter(r['label'] for r in records)),
            'review_statuses': dict(Counter(r['review']['status'] for r in records)),
            'screening_statuses': dict(Counter(r['screening']['status'] for r in records)),
            'family_splits': dict(Counter(split_for(f) for f in {r['family'] for r in records})),
            'training_performed': False}


def explanation_example(record):
    """Mirror LocalAI's single-finding input and output contract; never include full source."""
    findings = [f for f in scan_source('pilot.py', record['source'])
                if f.rule_id == 'PY-SQL-INJECTION' and f.line in record['evidence_lines']]
    if len(findings) != 1:
        raise ValueError(record['id'] + ': explanation export needs exactly one matching SQL finding.')
    finding = findings[0]
    content = json.dumps([{'id': 0, 'rule_id': finding.rule_id, 'line': finding.line,
                          'cwe': finding.cwe, 'description': finding.description,
                          'recommendation': finding.recommendation, 'evidence': finding.evidence[:300]}], ensure_ascii=True)
    # Human target must be reviewed against this bounded prompt, not just the full source.
    response = {'explanations': [{'id': 0, **record['explanation_target']}]}
    if any(len(value) > 4000 for value in response['explanations'][0].values() if isinstance(value, str)):
        raise ValueError(record['id'] + ': explanation exceeds runtime response limits.')
    return {'prompt': [{'role': 'system', 'content': SYSTEM}, {'role': 'user', 'content': content}],
            'completion': [{'role': 'assistant', 'content': json.dumps(response, ensure_ascii=True)}]}


def prepare(path, output):
    """Export only approved records. Refuse incomplete review rather than silently select it."""
    path, output = Path(path), Path(output)
    original = path.read_bytes()
    data = validate_dataset(path)
    if path.read_bytes() != original:
        raise ValueError('Dataset changed during validation; retry on a stable file.')
    if any(r['review']['status'] != 'approved' or r['screening']['status'] != 'approved' for r in data['records']):
        raise ValueError('All records need approved independent label review and data screening before export.')
    splits = {key: [] for key in ('train', 'validation', 'test')}
    examples = {'train': [], 'validation': []}
    for record in sorted(data['records'], key=lambda r: r['id']):
        split = split_for(record['family'])
        splits[split].append(record['id'])
        if record['label'] == 'vulnerable' and split != 'test':
            examples[split].append(explanation_example(record))
    if any(not ids for ids in splits.values()) or any(not values for values in examples.values()):
        raise ValueError('Need nonempty family splits and vulnerable train/validation examples; collect more families.')
    # Complete validation before creating any files. Test answers are deliberately not exported.
    files = {f'explanation.{key}.jsonl': ''.join(json.dumps(row, ensure_ascii=True) + '\n' for row in rows)
             for key, rows in examples.items()}
    manifest = {'schema_version': 1, 'dataset_version': data['version'],
                'dataset_sha256': hashlib.sha256(original).hexdigest(), 'split_version': SPLIT_VERSION,
                'prompt_version': PROMPT_VERSION, 'system_sha256': sha256(SYSTEM),
                'implementation_sha256': {name: hashlib.sha256((ROOT / 'app' / name).read_bytes()).hexdigest()
                                           for name in ('training_data.py', 'ai.py', 'scanner.py', 'sql_analysis.py')},
                'splits': splits, 'family_splits': {r['family']: split_for(r['family']) for r in data['records']},
                'file_sha256': {name: sha256(value) for name, value in files.items()},
                'explanation_counts': {key: len(rows) for key, rows in examples.items()},
                'notice': 'Safe and insufficient-context records remain in split manifests for future detection evaluation. '
                          'Only vulnerable train/validation examples are exported for explanation SFT. '
                          'No test completions, token-length verification, training, or model accuracy are provided.'}
    files['manifest.json'] = json.dumps(manifest, indent=2) + '\n'
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name, value in files.items():
        with (output / name).open('x', encoding='utf-8') as stream:
            stream.write(value)
    return manifest


def doctor():
    return {'python': sys.version.split()[0],
            'packages_in_this_interpreter': {name: importlib.util.find_spec(name) is not None
                                             for name in ('torch', 'transformers', 'peft', 'trl', 'bitsandbytes')},
            'device_nodes_visible': {name: Path(name).exists() for name in ('/dev/kfd', '/dev/dri')},
            'training_performed': False,
            'notice': 'Inventory only, not a GPU compatibility or allocation test. No weights or packages downloaded.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('doctor', help='Inspect packages and visible AMD device nodes without loading weights.')
    validate = commands.add_parser('validate', help='Check schema/leakage; report pending review without exporting.')
    validate.add_argument('--dataset', type=Path, default=DEFAULT_DATASET)
    preview = commands.add_parser('preview', help='Show a draft bounded training prompt/target and approval hash; never export a batch.')
    preview.add_argument('--dataset', type=Path, default=DEFAULT_DATASET)
    preview.add_argument('--record', required=True)
    export = commands.add_parser('prepare', help='Export approved explanation data and grouped manifests; never train.')
    export.add_argument('--dataset', type=Path, default=DEFAULT_DATASET)
    export.add_argument('--output', type=Path, required=True, help='New local directory, usually under .cache/training/.')
    args = parser.parse_args()
    try:
        if args.command == 'doctor':
            result = doctor()
        elif args.command == 'validate':
            result = describe(validate_dataset(args.dataset))
        elif args.command == 'preview':
            records = validate_dataset(args.dataset)['records']
            record = next((r for r in records if r['id'] == args.record), None)
            if record is None or record['label'] != 'vulnerable':
                raise ValueError('Preview needs an existing vulnerable record ID.')
            result = {'record_id': record['id'], 'record_sha256': record_digest(record),
                      'draft': True, 'example': explanation_example(record)}
        else:
            result = prepare(args.dataset, args.output)
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f'Dataset error: {error}\n')


if __name__ == '__main__':
    main()
