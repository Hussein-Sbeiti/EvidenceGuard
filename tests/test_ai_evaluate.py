import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from urllib.error import URLError

from app.ai import LocalAI
from app.ai_evaluate import add_review, run_evaluation, score_review, summarize, write_new


class EvaluationTests(unittest.TestCase):
    def fake_ai(self):
        ai = Mock(model='fixture:1')
        ai.status.return_value = {'status': 'ready', 'model_digest': 'a' * 64}
        def explain(findings, enabled=False):
            return {'status': ('complete' if findings else 'no_findings') if enabled else 'disabled',
                    'explanations': [{'finding_index': i, 'rule_id': f.rule_id, 'line': f.line,
                                      'explanation': 'Review input flow.', 'remediation': 'Parse data.',
                                      'limitation': 'Unknown input origin.'} for i, f in enumerate(findings)] if enabled else []}
        ai.explain.side_effect = explain
        return ai

    def test_offline_baseline_does_not_check_model_or_invent_scores(self):
        ai = self.fake_ai()
        report = run_evaluation(limit=2, ai=ai)
        ai.status.assert_not_called()
        self.assertFalse(report['training_performed'])
        self.assertEqual(report['baseline']['matching_cases'], 2)
        self.assertEqual({case['ai']['status'] for case in report['cases']}, {'disabled'})
        self.assertNotIn('source', report['cases'][0])
        self.assertEqual(len(report['dataset']['sha256']), 64)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'run.json'
            write_new(path, report)
            summary = summarize(path)
            self.assertIsNone(summary['mean_latest_human_score'])
            self.assertEqual(summary['reviewed_explanations'], 0)
            with self.assertRaises(FileExistsError):
                write_new(path, report)

    def test_ai_run_records_versioned_baseline_input_references_and_output(self):
        report = run_evaluation(['python_eval_positive', 'python_eval_negative'], 2, True, self.fake_ai())
        self.assertEqual(report['model_check_before_run']['model_digest'], 'a' * 64)
        self.assertEqual(len(report['implementation_sha256']), 6)
        self.assertEqual(report['cases'][0]['ai']['explanations'][0]['rule_id'], 'PY-EVAL')
        self.assertEqual(report['cases'][1]['ai']['status'], 'no_findings')
        self.assertIn('not the explanation agent', report['notice'])

    def test_missing_runtime_skips_generation_but_retains_baseline(self):
        ai = self.fake_ai()
        ai.status.return_value = {'status': 'unavailable', 'message': 'Start Ollama.'}
        report = run_evaluation(limit=2, ai_enabled=True, ai=ai)
        ai.explain.assert_not_called()
        self.assertEqual(report['baseline']['matching_cases'], 2)
        self.assertEqual(report['cases'][0]['ai']['status'], 'unavailable')

    def test_reviewer_history_is_preserved_latest_score_used_and_tamper_detected(self):
        report = run_evaluation(['python_eval_positive'], 1, True, self.fake_ai())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'run.json'
            write_new(path, report)
            before = path.read_bytes()
            ratings = {'correctness': 1, 'evidence': 1, 'remediation': 1}
            first = add_review(path, 'python_eval_positive', 0, 'reviewer-A', ratings, 'Needs clearer evidence.')
            second = add_review(path, 'python_eval_positive', 0, 'reviewer-A', {key: 2 for key in ratings}, 'Corrected review after checking the line.')
            self.assertNotEqual(first, second)
            self.assertTrue(first.exists())
            self.assertEqual(path.read_bytes(), before)
            summary = summarize(path)
            self.assertEqual(summary['review_history_entries'], 2)
            self.assertEqual(summary['reviewed_explanations'], 1)
            self.assertEqual(summary['pending_reviews'], 0)
            self.assertEqual(summary['mean_latest_human_score'], 100)
            path.write_text(json.dumps({**report, 'requested_model': 'changed'}))
            with self.assertRaisesRegex(ValueError, 'modified report'):
                summarize(path)

    def test_invalid_review_references_and_empty_rationale_are_rejected(self):
        report = run_evaluation(['python_eval_positive'], 1, True, self.fake_ai())
        ratings = {'correctness': 2, 'evidence': 2, 'remediation': 2}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'run.json'
            write_new(path, report)
            for case, index, reviewer, rationale in [('missing', 0, 'A', 'Checked.'),
                                                     ('python_eval_positive', 8, 'A', 'Checked.'),
                                                     ('python_eval_positive', 0, '', 'Checked.'),
                                                     ('python_eval_positive', 0, 'A', '')]:
                with self.subTest(case=case, index=index, reviewer=reviewer):
                    with self.assertRaises(ValueError):
                        add_review(path, case, index, reviewer, ratings, rationale)

    def test_scoring_requires_manual_integers_and_has_remediation_gate(self):
        self.assertEqual(score_review({'correctness': 2, 'evidence': 2, 'remediation': 0}), 0)
        self.assertEqual(score_review({'correctness': 2, 'evidence': 1, 'remediation': 2}), 83.33)
        for ratings in ({}, {'correctness': True, 'evidence': 2, 'remediation': 2},
                        {'correctness': 3, 'evidence': 2, 'remediation': 2}):
            with self.assertRaises(ValueError):
                score_review(ratings)

    def test_unknown_case_and_invalid_budget_do_not_call_model(self):
        ai = self.fake_ai()
        for ids, limit in [(['unknown'], 1), ([], 0), ([], 100)]:
            with self.assertRaises(ValueError):
                run_evaluation(ids, limit, True, ai)
        ai.status.assert_not_called()


class ModelStatusTests(unittest.TestCase):
    def test_ready_returns_observed_model_digest_without_inference(self):
        opener = Mock(return_value=io.BytesIO(json.dumps({'models': [{'name': 'local:1', 'digest': 'a' * 64}]}).encode()))
        result = LocalAI(model='local:1', opener=opener).status()
        self.assertEqual(result['status'], 'ready')
        self.assertEqual(result['model_digest'], 'a' * 64)
        self.assertEqual(opener.call_args.args[0].full_url, 'http://127.0.0.1:11434/api/tags')
        self.assertIsNone(opener.call_args.args[0].data)

    def test_missing_unavailable_and_invalid_statuses_are_clear(self):
        for data, expected in [(b'{"models": []}', 'model_missing'), (b'{}', 'unavailable'),
                               (b'{"models": [{"name": "local:1", "digest": "bad"}]}', 'unavailable')]:
            result = LocalAI(model='local:1', opener=Mock(return_value=io.BytesIO(data))).status()
            self.assertEqual(result['status'], expected)
        result = LocalAI(opener=Mock(side_effect=URLError('private-detail'))).status()
        self.assertEqual(result['status'], 'unavailable')
        self.assertNotIn('private-detail', json.dumps(result))


class StatusEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_status_endpoint_checks_runtime_without_inference(self):
        from unittest.mock import patch
        from test_web_boundaries import request
        with patch('app.main.local_ai.status', return_value={'status': 'ready', 'model': 'local:1'}) as check, patch('app.main.local_ai.explain') as generate:
            status, data, _, headers = await request(path='/api/ai/status')
        self.assertEqual(status, 200)
        self.assertEqual(data['status'], 'ready')
        self.assertEqual(headers[b'cache-control'], b'no-store')
        check.assert_called_once()
        generate.assert_not_called()
