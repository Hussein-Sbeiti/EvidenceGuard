import json
import unittest
from unittest.mock import patch

from starlette.formparsers import SpooledTemporaryFile

from app.main import app
from app.uploads import MAX_BODY_BYTES, MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES


BOUNDARY = 'ScannerBoundaryTest'


def multipart(files=(), fields=(), complete=True):
    parts = []
    for name, value in fields:
        parts.append(f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    for name, content in files:
        parts.append(f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="files"; filename="{name}"\r\nContent-Type: text/plain\r\n\r\n'.encode() + content + b'\r\n')
    if complete:
        parts.append(f'--{BOUNDARY}--\r\n'.encode())
    return b''.join(parts)


async def request(body=b'', path='/api/scan', headers=(), peer='127.0.0.1', chunk_size=8192):
    base = {b'host': b'127.0.0.1:8001', b'content-type': f'multipart/form-data; boundary={BOUNDARY}'.encode()}
    base.update(dict(headers))
    scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': 'POST' if path == '/api/scan' else 'GET',
             'scheme': 'http', 'path': path, 'query_string': b'', 'headers': list(base.items()),
             'server': ('127.0.0.1', 8001), 'client': (peer, 1234), 'root_path': ''}
    output = []
    consumed = 0
    async def receive():
        nonlocal consumed
        chunk = body[consumed:consumed + chunk_size]
        consumed += len(chunk)
        return {'type': 'http.request', 'body': chunk, 'more_body': consumed < len(body)}
    async def send(message):
        output.append(message)
    await app(scope, receive, send)
    return output[0]['status'], json.loads(b''.join(item.get('body', b'') for item in output)), consumed, dict(output[0]['headers'])


class WebBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_dependency_opt_in_is_parsed_separately_and_defaults_off(self):
        body = multipart([('requirements.txt', b'requests==2.0.0')], [('online_lookup', 'false'), ('dependency_lookup', 'false')])
        with patch('app.main.intelligence.request_json') as network:
            status, data, _, _ = await request(body)
        self.assertEqual(status, 200)
        self.assertFalse(data['dependency_lookup'])
        network.assert_not_called()
        self.assertEqual(data['dependencies'][0]['version'], '2.0.0')
        body = multipart([('requirements.txt', b'requests==2.0.0')], [('dependency_lookup', 'true')])
        with patch('app.main.dependency_intelligence.lookup_many', return_value=[]) as lookup:
            status, _, _, _ = await request(body)
        self.assertEqual(status, 200)
        self.assertTrue(lookup.call_args.args[1])

    async def test_exact_per_file_limit_stays_in_memory_and_closes_buffer(self):
        buffers = []
        def buffer(*args, **kwargs):
            result = SpooledTemporaryFile(*args, **kwargs)
            buffers.append(result)
            return result
        with patch('starlette.formparsers.SpooledTemporaryFile', side_effect=buffer):
            status, data, _, headers = await request(multipart([('safe.py', b' ' * MAX_FILE_BYTES)]))
        self.assertEqual(status, 200)
        self.assertEqual(data['summary']['files_scanned'], 1)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertTrue(all(item.closed and not item._rolled for item in buffers))

    async def test_oversized_file_rejected_during_stream_before_analysis_or_disk_rollover(self):
        body = multipart([('large.py', b'x' * (MAX_FILE_BYTES + 100000))])
        buffers = []
        def buffer(*args, **kwargs):
            result = SpooledTemporaryFile(*args, **kwargs)
            buffers.append(result)
            return result
        with patch('starlette.formparsers.SpooledTemporaryFile', side_effect=buffer), patch('app.main.analyze_source') as analyze:
            status, data, consumed, _ = await request(body)
        self.assertEqual(status, 413)
        self.assertIn('512 KB', data['detail'])
        self.assertLess(consumed, len(body))
        analyze.assert_not_called()
        self.assertTrue(buffers)
        self.assertTrue(all(item.closed and not item._rolled for item in buffers))

    async def test_total_limit_includes_unsupported_files(self):
        files = [(f'file{i}.bin', b'x' * MAX_FILE_BYTES) for i in range(MAX_TOTAL_BYTES // MAX_FILE_BYTES)]
        files.append(('last.py', b'x'))
        status, _, _, _ = await request(multipart(files))
        self.assertEqual(status, 413)

    async def test_exact_total_limit_allowed(self):
        files = [(f'file{i}.py', b' ' * MAX_FILE_BYTES) for i in range(MAX_TOTAL_BYTES // MAX_FILE_BYTES)]
        status, data, _, _ = await request(multipart(files))
        self.assertEqual(status, 200)
        self.assertEqual(data['summary']['files_scanned'], 10)

    async def test_file_count_limit(self):
        status, _, _, _ = await request(multipart([(f'file{i}.py', b'') for i in range(MAX_FILES + 1)]))
        self.assertEqual(status, 413)

    async def test_raw_body_limit_is_checked_with_and_without_content_length(self):
        status, _, consumed, _ = await request(b'', headers=[(b'content-length', str(MAX_BODY_BYTES + 1).encode())])
        self.assertEqual((status, consumed), (413, 0))
        status, _, _, _ = await request(b'x' * (MAX_BODY_BYTES + 1), chunk_size=MAX_BODY_BYTES + 1)
        self.assertEqual(status, 413)

    async def test_invalid_utf8_returns_explained_skip_or_clear_error(self):
        status, data, _, _ = await request(multipart([('valid.py', b'pass'), ('invalid.py', b'\xff')]))
        self.assertEqual(status, 200)
        self.assertEqual(data['skipped_files'][0]['reason'], 'Not valid UTF-8 text')
        status, data, _, _ = await request(multipart([('invalid.py', b'\xff')]))
        self.assertEqual(status, 400)
        self.assertEqual(data['detail']['skipped_files'][0]['file'], 'invalid.py')

    async def test_invalid_form_options_and_wrong_content_type(self):
        status, _, _, _ = await request(b'{}', headers=[(b'content-type', b'application/json')])
        self.assertEqual(status, 415)
        for fields in ([('online_lookup', 'maybe')], [('online_lookup', 'true'), ('online_lookup', 'false')], [('unknown', 'value')]):
            with self.subTest(fields=fields):
                status, _, _, _ = await request(multipart([('safe.py', b'pass')], fields))
                self.assertEqual(status, 400)

    async def test_truncated_multipart_and_excessive_headers_are_rejected(self):
        status, _, _, _ = await request(multipart([('safe.py', b'pass')], complete=False))
        self.assertEqual(status, 400)
        status, _, _, _ = await request(multipart([('x' * 4100 + '.py', b'pass')]))
        self.assertEqual(status, 413)
        # python-multipart may reject even larger headers before callbacks run.
        status, _, _, _ = await request(multipart([('x' * 5000 + '.py', b'pass')]))
        self.assertIn(status, {400, 413})

    async def test_remote_peer_untrusted_host_and_cross_origin_rejected_before_body_read(self):
        cases = [([], '192.0.2.1', 403), ([(b'host', b'attacker.example')], '127.0.0.1', 400),
                 ([(b'origin', b'https://attacker.example')], '127.0.0.1', 403),
                 ([(b'origin', b'http://127.0.0.1:8002')], '127.0.0.1', 403),
                 ([(b'origin', b'http://[')], '127.0.0.1', 403),
                 ([(b'sec-fetch-site', b'cross-site')], '127.0.0.1', 403)]
        for headers, peer, expected in cases:
            with self.subTest(headers=headers, peer=peer):
                status, _, consumed, _ = await request(multipart([('safe.py', b'pass')]), headers=headers, peer=peer)
                self.assertEqual(status, expected)
                self.assertEqual(consumed, 0)

    async def test_same_origin_scan_defaults_to_offline(self):
        with patch('app.main.intelligence.lookup') as lookup:
            status, data, _, _ = await request(multipart([('safe.py', b'# CVE-2021-44228\npass')]), headers=[(b'origin', b'http://127.0.0.1:8001')])
        self.assertEqual(status, 200)
        self.assertFalse(data['online_lookup'])
        lookup.assert_not_called()


if __name__ == '__main__':
    unittest.main()
