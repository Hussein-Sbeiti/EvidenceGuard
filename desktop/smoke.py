"""Check the frozen server from another working directory, with no model downloads."""

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parent.parent


def default_executable():
    dist = ROOT / '.cache' / 'desktop-build' / 'dist'
    if platform.system() == 'Darwin':
        return dist / 'VulnAI-Scanner.app' / 'Contents' / 'MacOS' / 'VulnAI-Scanner'
    return dist / 'VulnAI-Scanner' / ('VulnAI-Scanner.exe' if os.name == 'nt' else 'VulnAI-Scanner')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, default=default_executable())
    args = parser.parse_args()
    executable = args.executable.resolve()
    opener = build_opener(ProxyHandler({})).open
    with tempfile.TemporaryDirectory(prefix='scanner-desktop-smoke-') as folder:
        directory = Path(folder)
        data = directory / 'app-data'
        process = subprocess.Popen([str(executable), '--no-browser', '--no-ai-setup'], cwd=directory,
                                   env=dict(os.environ, VULN_SCANNER_DATA_DIR=str(data)),
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            url = None
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('Frozen launcher exited: ' + process.stdout.read().decode(errors='replace'))
                try:
                    url = json.loads((data / 'launcher.lock').read_bytes()[1:])['url']
                    if urlsplit(url).hostname != '127.0.0.1':
                        raise ValueError('Launcher did not bind to loopback.')
                    base = url.removesuffix('/setup')
                    with opener(base + '/api/health', timeout=1) as response:
                        if json.load(response) == {'status': 'ok'}:
                            break
                except (OSError, ValueError, KeyError):
                    pass
                time.sleep(0.1)
            else:
                log = (data / 'launcher.log').read_text(errors='replace') if (data / 'launcher.log').exists() else ''
                raise RuntimeError('Frozen local server did not become ready: ' + log)
            for path, expected in (('/setup', b'Open scanner'), ('/', b'<html'), ('/static/app.js', b'fetch')):
                with opener(base + path, timeout=5) as response:
                    if expected not in response.read():
                        raise RuntimeError('Missing packaged route/resource: ' + path)
            body = (b'--SmokeBoundary\r\nContent-Disposition: form-data; name="files"; filename="sample.py"\r\n'
                    b'Content-Type: text/plain\r\n\r\neval(user_input)\n\r\n--SmokeBoundary--\r\n')
            request = Request(base + '/api/scan', data=body,
                              headers={'Content-Type': 'multipart/form-data; boundary=SmokeBoundary'}, method='POST')
            with opener(request, timeout=15) as response:
                result = json.load(response)
            if result['ai']['status'] != 'disabled' or result['findings'][0]['rule_id'] != 'PY-EVAL':
                raise RuntimeError('Frozen scanner result did not match the defensive fixture.')
            with opener(Request(base + '/api/desktop/quit', data=b'',
                                headers={'X-Scanner-Desktop': '1'}, method='POST'), timeout=5) as response:
                if json.load(response)['status'] != 'stopping':
                    raise RuntimeError('Frozen launcher could not stop.')
            process.wait(timeout=20)
            if process.returncode != 0:
                raise RuntimeError('Frozen launcher failed during shutdown.')
            print(json.dumps({'frozen_live_smoke': 'passed', 'platform': platform.system(),
                              'checked': ['loopback startup', 'setup page', 'website assets', 'source scan', 'quit'],
                              'model_downloaded': False, 'training_performed': False}, indent=2))
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process.stdout.close()


if __name__ == '__main__':
    main()
