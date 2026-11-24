"""Per-user desktop bootstrap; no system Python, driver, or service installation."""

import hashlib
import json
import ntpath
import os
from pathlib import Path
import platform
import shutil
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
import zipfile

from app.ai import LocalAI, NoRedirect

MAX_UNPACKED_BYTES = 12 * 1024 ** 3


def resource_root():
    return Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent.parent))


def user_directory(system=None, environ=None, home=None):
    system, environ, home = system or platform.system(), os.environ if environ is None else environ, Path.home() if home is None else Path(home)
    if environ.get('VULN_SCANNER_DATA_DIR'):
        location = Path(environ['VULN_SCANNER_DATA_DIR'])
        if not location.is_absolute():
            raise ValueError('VULN_SCANNER_DATA_DIR must be an absolute path.')
        return location
    if system == 'Windows':
        return Path(environ.get('LOCALAPPDATA') or home / 'AppData' / 'Local') / 'VulnAIScanner'
    if system == 'Darwin':
        return home / 'Library' / 'Application Support' / 'VulnAIScanner'
    return Path(environ.get('XDG_DATA_HOME') or home / '.local' / 'share') / 'vuln-ai-scanner'


def load_release(path=None):
    release = json.loads(Path(path or resource_root() / 'desktop' / 'release.json').read_text())
    model = release['model']
    if release['schema_version'] != 1 or not isinstance(model['trained'], bool):
        raise ValueError('Invalid release configuration.')
    if not model['name'] or ':cloud' in model['name'] or not valid_digest(model['digest']):
        raise ValueError('Release must name a local model and its immutable digest.')
    return release


def valid_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def platform_key(system=None, machine=None):
    system, machine = (system or platform.system()).lower(), (machine or platform.machine()).lower()
    machine = {'amd64': 'x86_64', 'aarch64': 'arm64'}.get(machine, machine)
    return f'{system}-{machine}'


def inside(root, name):
    # Reject Windows absolute paths even when inspecting an archive on Linux/macOS.
    if ntpath.splitdrive(name)[0] or name.startswith(('/', '\\')):
        raise ValueError('Archive contains an absolute path.')
    target = (root / name.replace('\\', '/')).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError('Archive path escapes the installation directory.')
    return target


def extract_runtime(archive, destination):
    """Extract only after checksum verification by the caller; bound size and paths."""
    destination = Path(destination)
    if str(archive).endswith('.zip'):
        with zipfile.ZipFile(archive) as source:
            total = 0
            for entry in source.infolist():
                target = inside(destination, entry.filename)
                if stat.S_ISLNK(entry.external_attr >> 16):
                    raise ValueError('ZIP symlinks are not supported.')
                total += entry.file_size
                if total > MAX_UNPACKED_BYTES:
                    raise ValueError('Runtime archive exceeds the unpacked size limit.')
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with source.open(entry) as incoming, target.open('xb') as outgoing:
                        shutil.copyfileobj(incoming, outgoing)
    else:
        def unpack(source):
            total = 0
            for entry in source:
                inside(destination, entry.name)
                total += entry.size
                if total > MAX_UNPACKED_BYTES:
                    raise ValueError('Runtime archive exceeds the unpacked size limit.')
                source.extract(entry, destination, filter='data')
        if str(archive).endswith('.tar.zst'):
            import zstandard
            with open(archive, 'rb') as incoming, zstandard.ZstdDecompressor().stream_reader(incoming) as reader:
                with tarfile.open(fileobj=reader, mode='r|') as source:
                    unpack(source)
        else:
            with tarfile.open(archive, 'r:gz') as source:
                unpack(source)


def find_executable(directory):
    name = 'ollama.exe' if platform.system() == 'Windows' else 'ollama'
    candidates = [Path(directory) / name, Path(directory) / 'bin' / name]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ValueError('The verified runtime archive has no supported Ollama executable.')


class DesktopSetup:
    def __init__(self, release=None, directory=None):
        self.release = release or load_release()
        self.directory = Path(directory or user_directory())
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ai = LocalAI(model=self.release['model']['name'], expected_digest=self.release['model']['digest'])
        self.state_lock, self.start_lock = threading.Lock(), threading.Lock()
        self.stop_event = threading.Event()
        self.process = None
        self.process_log = None
        self.thread = None
        self.shutdown_callback = lambda: None
        self.state = {'status': 'waiting', 'message': 'Preparing local AI.', 'completed': 0, 'total': 0,
                      'model': self.ai.model, 'trained_model': self.release['model']['trained']}

    def update(self, **values):
        with self.state_lock:
            self.state.update(values)

    def snapshot(self):
        with self.state_lock:
            return dict(self.state)

    def start(self):
        with self.start_lock:
            if self.stop_event.is_set() or self.thread and self.thread.is_alive():
                return False
            if self.snapshot()['status'] == 'ready':
                return False
            self.update(status='starting', message='Checking local AI.', completed=0, total=0)
            self.thread = threading.Thread(target=self._run, name='desktop-setup', daemon=True)
            self.thread.start()
            return True

    def _run(self):
        try:
            status = self.ai.status()
            if status['status'] == 'unavailable':
                executable = self.install_runtime()
                self.start_runtime(executable)
                status = self.ai.status()
            if status['status'] == 'model_mismatch' or status['status'] == 'ready' and status.get('model_digest') != self.release['model']['digest']:
                raise ValueError('The existing model does not match this release. Update the app or review the local model before continuing.')
            if status['status'] != 'ready':
                self.pull_model()
                status = self.ai.status()
            if status['status'] != 'ready' or status.get('model_digest') != self.release['model']['digest']:
                raise ValueError('Installed model does not match this release. A new app release may be needed.')
            self.update(status='ready', message='Local AI is ready. You can open the scanner.', completed=0, total=0)
        except Exception as error:
            # Errors contain setup paths/download details, never uploaded source or API keys.
            import logging
            logging.getLogger(__name__).exception('Desktop setup failed')
            message = str(error) if isinstance(error, ValueError) else 'Setup could not finish. Check your connection, free disk space, and the setup log, then retry.'
            self.update(status='error', message=message, completed=0, total=0)

    def install_runtime(self):
        runtime = self.release['runtime']
        key = platform_key()
        asset = runtime['assets'].get(key)
        if asset is None:
            raise ValueError('Automatic AI setup is not yet packaged for this operating system and processor.')
        if not valid_digest(asset['sha256']) or '/' in asset['name'] or '\\' in asset['name']:
            raise ValueError('Invalid runtime release configuration.')
        target = self.directory / 'runtime' / runtime['version']
        if (target / '.verified.json').is_file():
            marker = json.loads((target / '.verified.json').read_text())
            if marker == {'sha256': asset['sha256'], 'platform': key}:
                return find_executable(target)
        self.update(status='runtime_download', message='Downloading the local AI runtime. This happens once.', completed=0, total=asset['bytes'])
        if shutil.disk_usage(self.directory).free < asset['bytes'] + 8 * 1024 ** 3:
            raise ValueError('Local AI setup needs at least 10 GB of free disk space. Free space and retry.')
        url = f"https://github.com/ollama/ollama/releases/download/{runtime['version']}/{asset['name']}"
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='download-', dir=target.parent) as temporary:
            staging = Path(temporary)
            archive = staging / asset['name']
            digest, received = hashlib.sha256(), 0
            # HTTPS redirects are needed for GitHub release CDN assets. The pinned SHA256
            # is checked before any extracted executable is used.
            import certifi
            context = ssl.create_default_context(cafile=certifi.where())
            with build_opener(ProxyHandler({}), HTTPSHandler(context=context)).open(Request(url, headers={'User-Agent': 'VulnAIScanner/0.1'}), timeout=60) as response, archive.open('xb') as output:
                while chunk := response.read(1024 * 1024):
                    if self.stop_event.is_set():
                        raise ValueError('Setup stopped.')
                    received += len(chunk)
                    if received > asset['bytes']:
                        raise ValueError('Runtime download exceeded its expected size.')
                    digest.update(chunk)
                    output.write(chunk)
                    self.update(completed=received)
            if received != asset['bytes'] or digest.hexdigest() != asset['sha256']:
                raise ValueError('Runtime download failed verification. Retry the download.')
            self.update(status='runtime_install', message='Installing the verified local AI runtime.', completed=0, total=0)
            extracted = staging / 'unpacked'
            extracted.mkdir()
            extract_runtime(archive, extracted)
            executable = find_executable(extracted)
            if platform.system() != 'Windows':
                executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            (extracted / '.verified.json').write_text(json.dumps({'sha256': asset['sha256'], 'platform': key}))
            if target.exists():
                raise ValueError('An incomplete runtime install exists. Check the runtime folder before retrying.')
            extracted.rename(target)
        return find_executable(target)

    def start_runtime(self, executable):
        # Reuse a service that started during installation. Never stop a pre-existing service.
        if self.ai.status()['status'] != 'unavailable':
            return
        if self.process is not None and self.process.poll() is None:
            raise ValueError('The local AI runtime is still starting. Retry shortly.')
        self.update(status='runtime_start', message='Starting local AI.', completed=0, total=0)
        env = dict(os.environ, OLLAMA_HOST='127.0.0.1:11434', OLLAMA_MODELS=str(self.directory / 'models'), OLLAMA_NO_CLOUD='1')
        self.process_log = (self.directory / 'ollama.log').open('ab')
        self.process = subprocess.Popen([str(executable), 'serve'], env=env, stdin=subprocess.DEVNULL,
                                        stdout=self.process_log, stderr=subprocess.STDOUT,
                                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for _ in range(60):
            if self.stop_event.wait(0.5):
                raise ValueError('Setup stopped.')
            if self.ai.status()['status'] != 'unavailable':
                return
            if self.process.poll() is not None:
                raise ValueError('The local AI runtime could not start. Check ollama.log for details.')
        raise ValueError('The local AI runtime is taking too long to start. Retry shortly.')

    def pull_model(self):
        self.update(status='model_download', message='Downloading the model. The download can resume after a connection failure.', completed=0, total=0)
        request = Request('http://127.0.0.1:11434/api/pull',
                          data=json.dumps({'model': self.ai.model, 'stream': True}).encode(),
                          headers={'Content-Type': 'application/json'}, method='POST')
        opener = build_opener(ProxyHandler({}), NoRedirect()).open
        success = False
        with opener(request, timeout=90) as response:
            while not self.stop_event.is_set():
                line = response.readline(65537)
                if not line:
                    break
                if len(line) > 65536:
                    raise ValueError('Local AI returned an oversized download message.')
                event = json.loads(line)
                if event.get('error'):
                    raise ValueError('Model download failed. Check the connection and retry.')
                total, completed = event.get('total', 0), event.get('completed', 0)
                if type(total) is int and type(completed) is int and 0 <= completed <= total:
                    self.update(total=total, completed=completed)
                if event.get('status') == 'success':
                    success = True
        if not success:
            raise ValueError('Model download did not finish. Retry to resume it.')

    def stop(self):
        self.stop_event.set()
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.process_log is not None:
            self.process_log.close()
