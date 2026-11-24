"""Validate both native Mac packages and attach them to an existing GitHub release."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile


def verified_files(directory, tag):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?', tag):
        raise ValueError('Use a versioned existing release tag, such as v0.1.0-preview.')
    directory = Path(directory)
    files = []
    commits = set()
    for arch in ('arm64', 'x86_64'):
        archive = directory / f'VulnAI-Scanner-darwin-{arch}.zip'
        checksum = archive.with_name(archive.name + '.sha256')
        fields = checksum.read_text().split()
        with archive.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if fields != [actual, archive.name]:
            raise ValueError('Package checksum mismatch: ' + archive.name)
        with zipfile.ZipFile(archive) as source:
            metadata = json.loads(source.read('VulnAI-Scanner.app/Contents/Resources/build-info.json'))
            if 'VulnAI-Scanner.app/Contents/MacOS/VulnAI-Scanner' not in source.namelist():
                raise ValueError('Mac app executable missing: ' + archive.name)
        if metadata.get('platform') != 'darwin' or metadata.get('architecture') != arch:
            raise ValueError('Mac package architecture does not match its filename.')
        if metadata.get('release', {}).get('app_version') != tag[1:]:
            raise ValueError('Package version does not match the selected release tag.')
        commit = metadata.get('source_commit', '')
        if not re.fullmatch(r'[0-9a-f]{40}', commit) or metadata.get('source_tree_dirty') is not False:
            raise ValueError('Publish clean, committed native builds only.')
        commits.add(commit)
        files.extend((archive, checksum))
    if len(commits) != 1:
        raise ValueError('Both Mac architectures must be built from the same commit.')
    return files


def publish(directory, tag, repo, check_only=False):
    files = verified_files(directory, tag)
    if check_only:
        return {'verified_files': [p.name for p in files], 'published': False}
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('Use a repository in OWNER/REPO form.')
    response = subprocess.run(['gh', 'release', 'view', tag, '--repo', repo, '--json', 'assets'],
                              check=True, capture_output=True, text=True)
    existing = {item['name'] for item in json.loads(response.stdout)['assets']}
    if existing.intersection(p.name for p in files):
        raise ValueError('Mac assets already exist on this release. Existing files will not be overwritten.')
    subprocess.run(['gh', 'release', 'upload', tag, *map(str, files), '--repo', repo], check=True)
    return {'published': True, 'release': tag, 'files': [p.name for p in files]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--repo', default='')
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(publish(args.directory, args.tag, args.repo, args.check_only), indent=2))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Mac release error: {error}\n')


if __name__ == '__main__':
    main()
