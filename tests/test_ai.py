import copy
import io
import json
import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError

from app.ai import LocalAI, MAX_AI_FINDINGS, MAX_RESPONSE_BYTES
from app.scanner import scan_source
from test_web_boundaries import multipart, request


def response(entries=None, **extra):
    if entries is None:
        entries = [{"id": 0, "explanation": "Dynamic execution may process untrusted input.",
                    "remediation": "Use a data parser.", "limitation": "Verify where input originates."}]
    return io.BytesIO(json.dumps({"model": "test:1", "done": True,
                                 "message": {"content": json.dumps({"explanations": entries})}, **extra}).encode())


class LocalAITests(unittest.TestCase):
    def setUp(self):
        self.findings = scan_source('demo.py', 'eval(user_input)')

    def test_disabled_and_no_findings_do_not_contact_ollama(self):
        opener = Mock()
        ai = LocalAI(opener=opener)
        self.assertEqual(ai.explain(self.findings)['status'], 'disabled')
        self.assertEqual(ai.explain([], True)['status'], 'no_findings')
        opener.assert_not_called()

    def test_success_has_traceable_output_and_preserves_findings(self):
        opener = Mock(return_value=response())
        before = copy.deepcopy(self.findings)
        result = LocalAI(model='test:1', opener=opener).explain(self.findings, True)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['explanations'][0]['rule_id'], 'PY-EVAL')
        self.assertEqual(result['explanations'][0]['file'], 'demo.py')
        self.assertEqual(result['model'], 'test:1')
        self.assertEqual(len(result['input_sha256']), 64)
        self.assertTrue(result['generated_at'])
        self.assertEqual(before, self.findings)
        req = opener.call_args.args[0]
        self.assertEqual(req.full_url, 'http://127.0.0.1:11434/api/chat')
        payload = json.loads(req.data)
        self.assertFalse(payload['stream'])
        self.assertEqual(payload['format'], 'json')
        self.assertEqual(opener.call_args.kwargs['timeout'], 60)

    def test_credentials_withheld_and_only_bounded_findings_sent(self):
        findings = scan_source('secrets.py', 'password = "private-test-value"') * (MAX_AI_FINDINGS + 2)
        entries = [{"id": i, "explanation": "Review.", "remediation": "Use environment configuration.", "limitation": "Verify use."} for i in range(MAX_AI_FINDINGS)]
        opener = Mock(return_value=response(entries))
        result = LocalAI(opener=opener).explain(findings, True)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['omitted_findings'], 2)
        self.assertNotIn('private-test-value', opener.call_args.args[0].data.decode())

    def test_failures_invalid_ids_incomplete_and_oversize_are_isolated(self):
        bad = [io.BytesIO(b'not json'), io.BytesIO(b'x' * (MAX_RESPONSE_BYTES + 1)),
               response([], done=False), response(done_reason='length'), response([]),
               response([{"id": 5}]), response([{"id": True}]),
               response([{"id": 0, "explanation": [], "remediation": "x", "limitation": "x"}])]
        for data in bad:
            with self.subTest(data=data):
                result = LocalAI(opener=Mock(return_value=data)).explain(self.findings, True)
                self.assertEqual(result['status'], 'unavailable')
                self.assertEqual(result['explanations'], [])
        opener = Mock(side_effect=URLError('sensitive detail'))
        result = LocalAI(opener=opener).explain(self.findings, True)
        self.assertEqual(result['status'], 'unavailable')
        self.assertNotIn('sensitive detail', json.dumps(result))

    def test_busy_model_skips_without_waiting(self):
        opener = Mock()
        ai = LocalAI(opener=opener)
        ai.lock.acquire()
        try:
            self.assertEqual(ai.explain(self.findings, True)['status'], 'unavailable')
            opener.assert_not_called()
        finally:
            ai.lock.release()


class AIEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_opt_in_reaches_model_and_exports_separate_output(self):
        body = multipart([('demo.py', b'eval(user_input)')], [('online_lookup', 'false'), ('dependency_lookup', 'false'), ('ai_explain', 'true')])
        with patch('app.main.local_ai.opener', return_value=response()) as opener:
            status, data, _, _ = await request(body)
        self.assertEqual(status, 200)
        self.assertEqual(data['summary']['findings'], 1)
        self.assertEqual(data['ai']['status'], 'complete')
        opener.assert_called_once()

    async def test_default_off_and_unavailable_model_keep_rule_results(self):
        body = multipart([('demo.py', b'eval(user_input)')])
        with patch('app.main.local_ai.opener') as opener:
            status, data, _, _ = await request(body)
        self.assertEqual(data['ai']['status'], 'disabled')
        opener.assert_not_called()
        with patch('app.main.local_ai.opener', side_effect=URLError('offline')):
            status, data, _, _ = await request(multipart([('demo.py', b'eval(user_input)')], [('ai_explain', 'true')]))
        self.assertEqual(status, 200)
        self.assertEqual(data['ai']['status'], 'unavailable')
        self.assertEqual(data['findings'][0]['rule_id'], 'PY-EVAL')

    async def test_bad_and_duplicate_ai_flags_rejected(self):
        for fields in [[('ai_explain', 'maybe')], [('ai_explain', 'true'), ('ai_explain', 'false')]]:
            status, _, _, _ = await request(multipart([('demo.py', b'pass')], fields))
            self.assertEqual(status, 400)


class BrowserAssetTests(unittest.IsolatedAsyncioTestCase):
    async def test_html_and_javascript_do_not_cache_old_ai_controls(self):
        from app.main import app
        for path in ('/', '/static/app.js', '/static/ui-utils.mjs'):
            output = []
            scope = {'type': 'http', 'asgi': {'version': '3.0', 'spec_version': '2.4'}, 'http_version': '1.1',
                     'method': 'GET', 'scheme': 'http', 'path': path, 'query_string': b'',
                     'headers': [(b'host', b'127.0.0.1:8001')],
                     'server': ('127.0.0.1', 8001), 'client': ('127.0.0.1', 1234), 'root_path': ''}
            async def receive():
                return {'type': 'http.request', 'body': b'', 'more_body': False}
            async def send(message):
                output.append(message)
            await app(scope, receive, send)
            self.assertEqual(output[0]['status'], 200)
            self.assertEqual(dict(output[0]['headers'])[b'cache-control'], b'no-store')
            if path == '/':
                body = b''.join(message.get('body', b'') for message in output)
                self.assertIn(b'/static/app.js?v=ollama-2', body)
