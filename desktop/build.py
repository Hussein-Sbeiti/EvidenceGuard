"""Build and check a native desktop preview; never publish or include developer data."""

import importlib.metadata
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def main():
    build = ROOT / '.cache' / 'desktop-build'
    dist = build / 'dist'
    subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
                    '--distpath', str(dist), '--workpath', str(build / 'work'),
                    str(ROOT / 'desktop' / 'Scanner.spec')], cwd=ROOT, check=True,
                   env=dict(os.environ, PYINSTALLER_CONFIG_DIR=str(build / 'config')))
    system, arch = platform.system().lower(), platform.machine().lower()
    arch = {'amd64': 'x86_64', 'aarch64': 'arm64'}.get(arch, arch)
    if system == 'darwin':
        bundle = dist / 'VulnAI-Scanner.app'
        executable = bundle / 'Contents' / 'MacOS' / 'VulnAI-Scanner'
    else:
        bundle = dist / 'VulnAI-Scanner'
        executable = bundle / ('VulnAI-Scanner.exe' if system == 'windows' else 'VulnAI-Scanner')
    subprocess.run([str(executable), '--self-test'], cwd=build, check=True, timeout=60)
    versions = sorted(({'name': d.metadata['Name'], 'version': d.version}
                       for d in importlib.metadata.distributions()), key=lambda d: d['name'].lower())
    metadata = {'platform': system, 'architecture': arch, 'packages': versions,
                'release': json.loads((ROOT / 'desktop' / 'release.json').read_text()),
                'verification': 'Frozen resource/parser self-test passed; full first-run and browser QA still required.'}
    commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True, check=True)
    dirty = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT, capture_output=True, text=True, check=True)
    metadata.update(source_commit=commit.stdout.strip(), source_tree_dirty=bool(dirty.stdout.strip()))
    notes = bundle / ('Contents/Resources' if system == 'darwin' else '') / 'build-info.json'
    notes.write_text(json.dumps(metadata, indent=2) + '\n')
    if system == 'darwin':
        # Re-sign after adding build metadata. This is ad-hoc signing for previews,
        # not Developer ID signing or Apple notarization.
        subprocess.run(['codesign', '--force', '--deep', '--sign', '-', str(bundle)], check=True)
        subprocess.run(['codesign', '--verify', '--deep', '--strict', '--verbose=2', str(bundle)], check=True)
        subprocess.run([str(executable), '--self-test'], cwd=build, check=True, timeout=60)
    # Explicit PyInstaller inputs exclude .env, uploads, training data, caches, and weights.
    for path in bundle.rglob('*'):
        if path.name == '.env' or path.name in {'sql_pilot.json', 'training', '.venv'}:
            raise RuntimeError('Developer-only file found in package: ' + str(path))
    archives = ROOT / '.cache' / 'desktop-artifacts'
    archives.mkdir(parents=True, exist_ok=True)
    name = f'VulnAI-Scanner-{system}-{arch}'
    if system == 'darwin':
        archive = archives / (name + '.zip')
        subprocess.run(['ditto', '-c', '-k', '--keepParent', str(bundle), str(archive)], check=True)
    else:
        archive = shutil.make_archive(str(archives / name), 'zip' if system == 'windows' else 'gztar',
                                      root_dir=dist, base_dir=bundle.name)
    archive = Path(archive)
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    archive.with_name(archive.name + '.sha256').write_text(digest + '  ' + archive.name + '\n')
    print('Native preview package:', archive)


if __name__ == '__main__':
    main()
