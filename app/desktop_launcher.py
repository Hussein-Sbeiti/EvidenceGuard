"""Start the frozen local web app and first-run setup in the user's browser."""

import argparse
import html
import json
import logging
import os
from pathlib import Path
import platform
import re
import socket
import sys
import threading
import time
import webbrowser

from app.desktop import DesktopSetup, load_release, user_directory


class InstanceLock:
    """OS lock released on process exit; a second click opens the running instance."""
    def __init__(self, directory):
        descriptor = os.open(Path(directory) / 'launcher.lock', os.O_RDWR | os.O_CREAT, 0o600)
        self.file = os.fdopen(descriptor, 'r+b')
        if self.file.seek(0, os.SEEK_END) == 0:
            self.file.write(b'\0')
            self.file.flush()
        self.file.seek(0)
        self.owned = False

    def acquire(self):
        try:
            if platform.system() == 'Windows':
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.owned = True
            return True
        except OSError:
            return False

    def write_url(self, url):
        self.file.seek(1)
        self.file.truncate()
        self.file.write(json.dumps({'url': url}).encode())
        self.file.flush()

    def existing_url(self):
        for _ in range(100):
            try:
                self.file.seek(1)
                url = json.loads(self.file.read())['url']
                if re.fullmatch(r'http://127\.0\.0\.1:[0-9]{1,5}/setup', url):
                    return url
            except (ValueError, KeyError):
                pass
            time.sleep(0.05)
        raise ValueError('Another scanner instance is still starting. Try again shortly.')

    def close(self):
        self.file.close()


def main():
    parser = argparse.ArgumentParser(description='Run the local scanner desktop preview.')
    parser.add_argument('--no-browser', action='store_true', help='Developer check: do not open a browser.')
    parser.add_argument('--no-ai-setup', action='store_true', help='Developer check: do not start AI setup automatically.')
    parser.add_argument('--self-test', action='store_true', help='Check bundled resources/imports and exit without networking.')
    args = parser.parse_args()
    if args.self_test:
        from app.main import STATIC_DIRECTORY
        from app.scanner import scan_source
        import certifi
        import zstandard
        release = load_release()
        if not (STATIC_DIRECTORY / 'index.html').is_file() or not (STATIC_DIRECTORY / 'setup.html').is_file():
            raise RuntimeError('Packaged website resources are missing.')
        if not scan_source('check.py', 'eval(user_input)') or not release['model']['digest']:
            raise RuntimeError('Packaged scanner check failed.')
        return
    directory = user_directory()
    directory.mkdir(parents=True, exist_ok=True)
    # A windowed frozen executable has no terminal streams. Keep diagnostics local.
    stream = (directory / 'launcher.log').open('a', encoding='utf-8', buffering=1)
    if sys.stdout is None:
        sys.stdout = stream
    if sys.stderr is None:
        sys.stderr = stream
    logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler(stream)])
    manager, instance = None, None
    try:
        instance = InstanceLock(directory)
        if not instance.acquire():
            url = instance.existing_url()
            if not args.no_browser:
                webbrowser.open(url)
            return
        release = load_release()
        # Set before importing app.main, which constructs the clients. The release
        # never reads or copies a developer .env or uses the installation directory.
        os.environ['OLLAMA_MODEL'] = release['model']['name']
        os.environ['VULN_CACHE_PATH'] = str(directory / 'intelligence.sqlite3')
        os.environ['EXPLOITDB_CSV'] = str(directory / 'files_exploits.csv')
        manager = DesktopSetup(release, directory)
        from app import main as scanner_module
        import uvicorn
        app = scanner_module.app
        scanner_module.local_ai = manager.ai
        app.state.desktop_setup = manager
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(128)
            port = listener.getsockname()[1]
            url = f'http://127.0.0.1:{port}/setup'
            instance.write_url(url)
            server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=port,
                                                    loop='asyncio', http='h11', ws='none',
                                                    access_log=False, timeout_graceful_shutdown=15))
            manager.shutdown_callback = lambda: setattr(server, 'should_exit', True)
            def open_when_ready():
                while not server.started and not server.should_exit:
                    time.sleep(0.1)
                if server.started:
                    if not args.no_ai_setup:
                        manager.start()
                    if not args.no_browser:
                        webbrowser.open(url)
            threading.Thread(target=open_when_ready, daemon=True).start()
            server.run(sockets=[listener])
    except Exception as error:
        logging.exception('Desktop launcher failed')
        page = directory / 'startup-error.html'
        page.write_text('<!doctype html><meta charset="utf-8"><title>Scanner startup</title>'
                        '<h1>The scanner could not start</h1><p>' + html.escape(str(error)) +
                        '</p><p>Details are in launcher.log in this folder.</p>', encoding='utf-8')
        if not args.no_browser:
            webbrowser.open(page.as_uri())
        raise SystemExit(1)
    finally:
        if manager:
            manager.stop()
        if instance:
            instance.close()


if __name__ == '__main__':
    main()
