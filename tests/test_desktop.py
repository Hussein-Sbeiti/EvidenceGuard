import asyncio
import copy
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

from app.desktop import (DesktopSetup, extract_runtime, find_executable, inside,
                         load_release, platform_key, user_directory)
from app.desktop_launcher import InstanceLock
from app.ai import LocalAI
from app.scanner import scan_source
from app.main import STATIC_DIRECTORY, app


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.release = load_release()
        self.manager = DesktopSetup(self.release, self.root)

    def test_release_names_real_base_model_and_pins_every_runtime(self):
        self.assertFalse(self.release['model']['trained'])
        self.assertEqual(self.release['model']['name'], 'qwen2.5-coder:3b')
        self.assertEqual(len(self.release['model']['digest']), 64)
        self.assertEqual(set(self.release['runtime']['assets']),
                         {'linux-x86_64', 'windows-x86_64', 'darwin-arm64', 'darwin-x86_64'})
        for asset in self.release['runtime']['assets'].values():
            self.assertEqual(len(asset['sha256']), 64)
            self.assertGreater(asset['bytes'], 0)

    def test_per_user_directories_and_architecture_aliases(self):
        self.assertEqual(user_directory('Linux', {}, self.root), self.root / '.local/share/vuln-ai-scanner')
        self.assertEqual(user_directory('Darwin', {}, self.root), self.root / 'Library/Application Support/VulnAIScanner')
        self.assertEqual(user_directory('Windows', {'LOCALAPPDATA': str(self.root)}, self.root), self.root / 'VulnAIScanner')
        self.assertEqual(platform_key('Windows', 'AMD64'), 'windows-x86_64')
        self.assertEqual(platform_key('Darwin', 'aarch64'), 'darwin-arm64')

    def test_explicit_data_directory_is_supported_but_must_be_absolute(self):
        self.assertEqual(user_directory('Linux', {'VULN_SCANNER_DATA_DIR': str(self.root)}, self.root), self.root)
        with self.assertRaises(ValueError):
            user_directory('Linux', {'VULN_SCANNER_DATA_DIR': 'relative'}, self.root)

    def test_installed_matching_model_makes_no_download_or_process(self):
        self.manager.ai.status = Mock(return_value={'status': 'ready', 'model_digest': self.release['model']['digest']})
        with patch.object(self.manager, 'install_runtime') as runtime, patch.object(self.manager, 'pull_model') as pull:
            self.manager._run()
        self.assertEqual(self.manager.snapshot()['status'], 'ready')
        runtime.assert_not_called()
        pull.assert_not_called()

    def test_existing_runtime_missing_model_only_pulls_model(self):
        self.manager.ai.status = Mock(side_effect=[{'status': 'model_missing'},
                                                   {'status': 'ready', 'model_digest': self.release['model']['digest']}])
        with patch.object(self.manager, 'install_runtime') as runtime, patch.object(self.manager, 'pull_model') as pull:
            self.manager._run()
        runtime.assert_not_called()
        pull.assert_called_once()
        self.assertEqual(self.manager.snapshot()['status'], 'ready')

    def test_first_run_installs_runtime_starts_it_and_downloads_model(self):
        self.manager.ai.status = Mock(side_effect=[{'status': 'unavailable'}, {'status': 'model_missing'},
                                                   {'status': 'ready', 'model_digest': self.release['model']['digest']}])
        with patch.object(self.manager, 'install_runtime', return_value=Path('/fake/ollama')) as runtime, \
                patch.object(self.manager, 'start_runtime') as start, patch.object(self.manager, 'pull_model') as pull:
            self.manager._run()
        runtime.assert_called_once()
        start.assert_called_once_with(Path('/fake/ollama'))
        pull.assert_called_once()
        self.assertEqual(self.manager.snapshot()['status'], 'ready')

    def test_digest_mismatch_is_visible_and_does_not_replace_an_existing_model(self):
        self.manager.ai.status = Mock(return_value={'status': 'ready', 'model_digest': '0' * 64})
        with patch.object(self.manager, 'pull_model') as pull, patch('logging.Logger.exception'):
            self.manager._run()
        pull.assert_not_called()
        self.assertEqual(self.manager.snapshot()['status'], 'error')
        self.assertIn('does not match', self.manager.snapshot()['message'])

    def test_pinned_client_rejects_wrong_model_before_sending_source(self):
        payload = json.dumps({'models': [{'name': 'qwen2.5-coder:3b', 'digest': '0' * 64}]}).encode()
        opener = Mock(side_effect=lambda *a, **k: io.BytesIO(payload))
        ai = LocalAI(opener=opener, expected_digest='a' * 64)
        self.assertEqual(ai.status()['status'], 'model_mismatch')
        result = ai.explain(scan_source('source.py', 'eval(user_input)'), enabled=True)
        self.assertEqual(result['status'], 'unavailable')
        self.assertTrue(all(call.args[0].full_url.endswith('/api/tags') for call in opener.call_args_list))

    def test_pin_does_not_contact_model_when_ai_disabled_or_no_findings(self):
        opener = Mock()
        ai = LocalAI(opener=opener, expected_digest='a' * 64)
        self.assertEqual(ai.explain([], enabled=True)['status'], 'no_findings')
        self.assertEqual(ai.explain(scan_source('a.py', 'eval(x)'), enabled=False)['status'], 'disabled')
        opener.assert_not_called()

    def test_failed_download_cannot_report_ready(self):
        self.manager.ai.status = Mock(return_value={'status': 'model_missing'})
        with patch.object(self.manager, 'pull_model', side_effect=ValueError('Download incomplete')), patch('logging.Logger.exception'):
            self.manager._run()
        self.assertEqual(self.manager.snapshot()['status'], 'error')

    def test_unsupported_architecture_does_not_download_a_wrong_runtime(self):
        with patch('app.desktop.platform_key', return_value='linux-arm64'):
            with self.assertRaisesRegex(ValueError, 'not yet packaged'):
                self.manager.install_runtime()

    def test_downloaded_runtime_checksum_is_checked_before_extracting(self):
        key = platform_key()
        asset = self.manager.release['runtime']['assets'][key]
        asset['bytes'] = 3
        with patch('app.desktop.shutil.disk_usage', return_value=Mock(free=30 * 1024 ** 3)), \
                patch('app.desktop.build_opener') as opener, patch('app.desktop.extract_runtime') as extract:
            opener.return_value.open.return_value = io.BytesIO(b'bad')
            # This test does not need the desktop-only certifi dependency installed.
            with patch.dict('sys.modules', {'certifi': Mock(where=Mock(return_value=None))}):
                with self.assertRaisesRegex(ValueError, 'failed verification'):
                    self.manager.install_runtime()
        extract.assert_not_called()

    def test_zip_traversal_and_absolute_windows_paths_are_rejected(self):
        for name in ('../outside', '/tmp/outside', 'C:\\outside', '..\\outside'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                inside(self.root, name)
        archive = self.root / 'unsafe.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr('../outside', 'bad')
        with self.assertRaises(ValueError):
            extract_runtime(archive, self.root / 'unpacked')
        self.assertFalse((self.root / 'outside').exists())

    def test_tar_symlink_cannot_escape_destination(self):
        archive = self.root / 'unsafe.tgz'
        with tarfile.open(archive, 'w:gz') as output:
            entry = tarfile.TarInfo('link')
            entry.type, entry.linkname = tarfile.SYMTYPE, '../../outside'
            output.addfile(entry)
        with self.assertRaises((ValueError, tarfile.FilterError)):
            extract_runtime(archive, self.root / 'unpacked')

    def test_runtime_layout_and_cached_install(self):
        key = platform_key()
        target = self.root / 'runtime' / self.release['runtime']['version']
        target.mkdir(parents=True)
        name = 'ollama.exe' if os.name == 'nt' else 'ollama'
        (target / name).write_bytes(b'fixture')
        marker = {'sha256': self.release['runtime']['assets'][key]['sha256'], 'platform': key}
        (target / '.verified.json').write_text(json.dumps(marker))
        self.assertEqual(self.manager.install_runtime(), target / name)

    def test_successful_stream_pull_tracks_progress_without_source(self):
        stream = io.BytesIO(b'{"status":"pulling","total":100,"completed":30}\n{"status":"success"}\n')
        with patch('app.desktop.build_opener') as opener:
            opener.return_value.open.return_value = stream
            self.manager.pull_model()
        request = opener.return_value.open.call_args.args[0]
        self.assertEqual(json.loads(request.data), {'model': 'qwen2.5-coder:3b', 'stream': True})
        self.assertEqual(request.full_url, 'http://127.0.0.1:11434/api/pull')

    def test_incomplete_pull_and_oversized_events_fail(self):
        for data in (b'{"status":"pulling"}\n', b'x' * 65537):
            with self.subTest(length=len(data)), patch('app.desktop.build_opener') as opener:
                opener.return_value.open.return_value = io.BytesIO(data)
                with self.assertRaises(ValueError):
                    self.manager.pull_model()

    def test_only_process_started_by_app_is_stopped(self):
        process = Mock()
        process.poll.return_value = None
        self.manager.process = process
        self.manager.stop()
        process.terminate.assert_called_once()
        process.wait.assert_called_once()
        other = DesktopSetup(self.release, self.root)
        other.stop()
        self.assertIsNone(other.process)

    def test_double_click_lock_reopens_url_without_corrupting_it(self):
        first, second = InstanceLock(self.root), None
        try:
            self.assertTrue(first.acquire())
            first.write_url('http://127.0.0.1:12345/setup')
            second = InstanceLock(self.root)
            self.assertFalse(second.acquire())
            self.assertEqual(second.existing_url(), 'http://127.0.0.1:12345/setup')
        finally:
            if second:
                second.close()
            first.close()
        final = InstanceLock(self.root)
        try:
            self.assertTrue(final.acquire())
        finally:
            final.close()


class DesktopEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def call(self, path, method='GET', headers=()):
        events = []
        scope = {'type': 'http', 'asgi': {'version': '3.0', 'spec_version': '2.4'},
                 'http_version': '1.1', 'method': method, 'scheme': 'http', 'path': path,
                 'query_string': b'', 'headers': [(b'host', b'127.0.0.1:4567'), *headers],
                 'server': ('127.0.0.1', 4567), 'client': ('127.0.0.1', 1234), 'root_path': ''}
        async def receive():
            return {'type': 'http.request', 'body': b'', 'more_body': False}
        async def send(event):
            events.append(event)
        await app(scope, receive, send)
        return events[0]['status'], b''.join(e.get('body', b'') for e in events)

    async def test_plain_web_server_has_no_desktop_control(self):
        for path in ('/setup', '/api/desktop/setup', '/api/desktop/quit'):
            status, _ = await self.call(path, 'POST' if path.endswith('quit') else 'GET')
            self.assertEqual(status, 404)

    async def test_desktop_setup_page_status_retry_and_quit(self):
        manager = Mock()
        manager.snapshot.return_value = {'status': 'ready', 'message': 'Ready'}
        app.state.desktop_setup = manager
        try:
            status, body = await self.call('/setup')
            self.assertEqual(status, 200)
            self.assertIn(b'Open scanner', body)
            status, body = await self.call('/api/desktop/setup')
            self.assertEqual(json.loads(body)['status'], 'ready')
            self.assertEqual((await self.call('/api/desktop/setup', 'POST'))[0], 403)
            headers = [(b'x-scanner-desktop', b'1')]
            self.assertEqual((await self.call('/api/desktop/setup', 'POST', headers))[0], 200)
            manager.start.assert_called_once()
            self.assertEqual((await self.call('/api/desktop/quit', 'POST', headers))[0], 200)
            manager.shutdown_callback.assert_called_once()
            cross = [*headers, (b'origin', b'https://outside.example')]
            self.assertEqual((await self.call('/api/desktop/quit', 'POST', cross))[0], 403)
            manager.shutdown_callback.assert_called_once()
        finally:
            del app.state.desktop_setup

    async def test_static_resources_work_outside_repository_cwd(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as folder:
            try:
                os.chdir(folder)
                status, body = await self.call('/')
                self.assertEqual(status, 200)
                self.assertIn(b'<html', body)
            finally:
                os.chdir(previous)


if __name__ == '__main__':
    unittest.main()
