"""Evaluate the explanation agent on existing synthetic fixtures; never train or execute code."""

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.ai import LocalAI, PROMPT_VERSION, SYSTEM
from app.evaluate import DEFAULT_CASES, ROOT, evaluate_cases, load_cases
from app.scanner import scan_source

RUBRIC_VERSION = "explanation-review-v1"
CRITERIA = ("correctness", "evidence", "remediation")


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_new(path, data):
    """Create a new artifact with restrictive POSIX permissions; never overwrite."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path, 'x', encoding='utf-8', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def run_evaluation(case_ids=(), limit=3, ai_enabled=False, ai=None):
    cases = load_cases(DEFAULT_CASES)
    if case_ids:
        unknown = set(case_ids) - {case['id'] for case in cases}
        if unknown:
            raise ValueError('Unknown case IDs: ' + ', '.join(sorted(unknown)))
        cases = [case for case in cases if case['id'] in case_ids]
    if not 1 <= limit <= len(load_cases(DEFAULT_CASES)):
        raise ValueError('Limit must be between 1 and the corpus size.')
    cases = cases[:limit]
    ai = ai or LocalAI()
    status = ai.status() if ai_enabled else {"status": "not_checked"}
    report = {
        'schema_version': 1, 'run_id': str(uuid4()), 'created_at': now(),
        'task': 'Explain existing rule findings and suggest defensive fixes for human review.',
        'training_performed': False, 'ai_enabled': ai_enabled,
        'dataset': {'path': 'evaluation/cases.json', 'sha256': digest(DEFAULT_CASES),
                    'provenance': 'Repository-authored synthetic fixtures; independent review pending.'},
        'implementation_sha256': {name: digest(ROOT / 'app' / name) for name in
                                  ('scanner.py', 'python_analysis.py', 'sql_analysis.py',
                                   'javascript_parser.py', 'ai.py', 'ai_evaluate.py')},
        'prompt_version': PROMPT_VERSION, 'system_prompt_sha256': hashlib.sha256(SYSTEM.encode()).hexdigest(),
        'requested_model': ai.model, 'model_check_before_run': status,
        'baseline': evaluate_cases(cases), 'cases': [],
        'rubric_version': RUBRIC_VERSION,
        'notice': 'Detection labels and TP/FP/FN/TN belong to deterministic rules, not the explanation agent. '
                  'Labels are provisional until independent review. AI explanation quality requires human ratings. '
                  'This is a development evaluation, not held-out accuracy or model training.',
    }
    for case in cases:
        findings = scan_source(case['filename'], case['source'])
        if ai_enabled and status['status'] != 'ready':
            output = {'status': 'unavailable', 'explanations': [],
                      'warning': status.get('message', 'Local model is not ready; generation skipped.')}
        else:
            output = ai.explain(findings, ai_enabled)
        report['cases'].append({
            'case_id': case['id'], 'filename': case['filename'],
            'source_sha256': hashlib.sha256(case['source'].encode()).hexdigest(),
            'label_review_status': case.get('review_status', 'pending_independent_review'),
            'label_reviewer': case.get('reviewer'), 'label_rationale': case['review'],
            'rule_findings': [{'rule_id': f.rule_id, 'line': f.line, 'recommendation': f.recommendation} for f in findings],
            'ai': output,
        })
    report['completed_at'] = now()
    return report


def score_review(ratings):
    if set(ratings) != set(CRITERIA) or any(type(value) is not int or value not in (0, 1, 2) for value in ratings.values()):
        raise ValueError('Rate correctness, evidence, and remediation using integers 0, 1, or 2.')
    # Unsafe or irrelevant remediation cannot earn a passing overall score.
    return 0.0 if ratings['remediation'] == 0 else round(sum(ratings.values()) / 6 * 100, 2)


def load_report(path):
    report = json.loads(Path(path).read_text(encoding='utf-8'))
    if report.get('schema_version') != 1 or report.get('rubric_version') != RUBRIC_VERSION:
        raise ValueError('Unsupported evaluation report.')
    return report


def target(report, case_id, finding_index):
    for case in report['cases']:
        if case['case_id'] == case_id:
            for entry in case['ai'].get('explanations', []):
                if entry['finding_index'] == finding_index:
                    return entry
    raise ValueError('Review must reference an existing AI explanation in this report.')


def review_directory(path):
    path = Path(path)
    return path.parent / (path.stem + '.reviews')


def add_review(path, case_id, finding_index, reviewer, ratings, rationale):
    report = load_report(path)
    entry = target(report, case_id, finding_index)
    if not reviewer.strip() or len(reviewer) > 200 or not rationale.strip() or len(rationale) > 4000:
        raise ValueError('Provide a reviewer identifier (up to 200 characters) and rationale (up to 4000 characters).')
    review = {'review_id': str(uuid4()), 'run_id': report['run_id'], 'report_sha256': digest(path),
              'case_id': case_id, 'finding_index': finding_index, 'rule_id': entry['rule_id'],
              'reviewer': reviewer.strip(), 'created_at': now(), 'rubric_version': RUBRIC_VERSION,
              'ratings': ratings, 'score': score_review(ratings), 'rationale': rationale.strip()}
    destination = review_directory(path) / (review['review_id'] + '.json')
    write_new(destination, review)
    return destination


def summarize(path):
    report = load_report(path)
    latest = {}
    history_count = 0
    for review_path in sorted(review_directory(path).glob('*.json')):
        review = json.loads(review_path.read_text(encoding='utf-8'))
        if review.get('report_sha256') != digest(path) or review.get('run_id') != report['run_id']:
            raise ValueError('Review refers to a different or modified report: ' + review_path.name)
        entry = target(report, review['case_id'], review['finding_index'])
        if review.get('rubric_version') != RUBRIC_VERSION or review.get('rule_id') != entry['rule_id'] or review['score'] != score_review(review['ratings']):
            raise ValueError('Invalid review rubric, reference, or score: ' + review_path.name)
        key = (review['case_id'], review['finding_index'])
        if key not in latest or (review['created_at'], review['review_id']) > (latest[key]['created_at'], latest[key]['review_id']):
            latest[key] = review
        history_count += 1
    total = sum(len(case['ai'].get('explanations', [])) for case in report['cases'])
    return {'run_id': report['run_id'], 'ai_enabled': report['ai_enabled'], 'explanations': total,
            'reviewed_explanations': len(latest), 'pending_reviews': total - len(latest),
            'review_history_entries': history_count,
            'mean_latest_human_score': round(sum(r['score'] for r in latest.values()) / len(latest), 2) if latest else None,
            'ai_statuses': {case['case_id']: case['ai']['status'] for case in report['cases']},
            'baseline_counts': report['baseline']['counts'],
            'baseline_precision': report['baseline']['precision'], 'baseline_recall': report['baseline']['recall'],
            'notice': report['notice']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run', help='Save a development evaluation; AI is opt-in.')
    run.add_argument('--ai', action='store_true')
    run.add_argument('--case', action='append', default=[], dest='case_ids')
    run.add_argument('--limit', type=int, default=3)
    run.add_argument('--output-dir', type=Path, default=Path('.cache/ai-evaluation'))
    review = commands.add_parser('review', help='Save a new human review; prior reviews are preserved.')
    review.add_argument('report', type=Path)
    review.add_argument('--case', required=True, dest='case_id')
    review.add_argument('--finding-index', required=True, type=int)
    review.add_argument('--reviewer', required=True)
    for criterion in CRITERIA:
        review.add_argument('--' + criterion, required=True, type=int, choices=(0, 1, 2))
    review.add_argument('--rationale', required=True)
    summary = commands.add_parser('summary', help='Summarize latest reviews and rule baseline; never infer an AI score.')
    summary.add_argument('report', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'run':
            report = run_evaluation(args.case_ids, args.limit, args.ai)
            destination = args.output_dir / (report['run_id'] + '.json')
            write_new(destination, report)
            print(f'Report: {destination}')
            print(json.dumps(summarize(destination), indent=2))
        elif args.command == 'review':
            ratings = {criterion: getattr(args, criterion) for criterion in CRITERIA}
            print('Review: ' + str(add_review(args.report, args.case_id, args.finding_index, args.reviewer, ratings, args.rationale)))
        else:
            print(json.dumps(summarize(args.report), indent=2))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f'Evaluation error: {error}\n')


if __name__ == '__main__':
    main()
