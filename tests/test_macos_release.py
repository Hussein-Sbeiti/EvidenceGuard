import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

from desktop.publish_macos import publish, verified_files


class MacReleaseTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        for arch in ('arm64', 'x86_64'):
            self.package(arch)

    def package(self, arch, **changes):
        metadata = {'platform': 'darwin', 'architecture': arch, 'release': {'app_version': '0.1.0-preview'},
                    'source_commit': 'a' * 40, 'source_tree_dirty': False, **changes}
        path = self.root / f'VulnAI-Scanner-darwin-{arch}.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('VulnAI-Scanner.app/Contents/Resources/build-info.json', json.dumps(metadata))
            archive.writestr('VulnAI-Scanner.app/Contents/MacOS/VulnAI-Scanner', b'test executable placeholder')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        path.with_name(path.name + '.sha256').write_text(digest + '  ' + path.name + '\n')
        return path

    def test_both_architectures_and_checksums_required(self):
        files = verified_files(self.root, 'v0.1.0-preview')
        self.assertEqual(len(files), 4)
        files[-1].unlink()
        with self.assertRaises(FileNotFoundError):
            verified_files(self.root, 'v0.1.0-preview')

    def test_check_only_never_contacts_github(self):
        with patch('desktop.publish_macos.subprocess.run') as command:
            result = publish(self.root, 'v0.1.0-preview', '', check_only=True)
        command.assert_not_called()
        self.assertFalse(result['published'])
        self.assertEqual(len(result['verified_files']), 4)

    def test_modified_archive_or_wrong_checksum_filename_rejected(self):
        path = self.root / 'VulnAI-Scanner-darwin-arm64.zip'
        path.write_bytes(path.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            verified_files(self.root, 'v0.1.0-preview')
        self.package('arm64')
        checksum = path.with_name(path.name + '.sha256')
        checksum.write_text(checksum.read_text().replace(path.name, 'different.zip'))
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            verified_files(self.root, 'v0.1.0-preview')

    def test_architecture_version_and_dirty_source_are_checked(self):
        for changes in ({'architecture': 'x86_64'}, {'release': {'app_version': '0.2.0'}},
                        {'source_tree_dirty': True}, {'source_commit': 'main'}):
            with self.subTest(changes=changes):
                self.package('arm64', **changes)
                with self.assertRaises(ValueError):
                    verified_files(self.root, 'v0.1.0-preview')

    def test_architectures_must_share_source_commit(self):
        self.package('arm64', source_commit='b' * 40)
        with self.assertRaisesRegex(ValueError, 'same commit'):
            verified_files(self.root, 'v0.1.0-preview')

    def test_upload_adds_only_mac_files_without_overwriting_linux_assets(self):
        response = Mock(stdout=json.dumps({'assets': [{'name': 'VulnAI-Scanner-linux-x86_64.tar.gz'}]}))
        with patch('desktop.publish_macos.subprocess.run', return_value=response) as command:
            result = publish(self.root, 'v0.1.0-preview', 'owner/repo')
        self.assertTrue(result['published'])
        self.assertEqual(command.call_count, 2)
        upload = command.call_args_list[-1].args[0]
        self.assertEqual(upload[:4], ['gh', 'release', 'upload', 'v0.1.0-preview'])
        self.assertNotIn('--clobber', upload)
        self.assertNotIn('delete', upload)
        self.assertTrue(all('darwin-' in name for name in result['files']))

    def test_existing_mac_asset_prevents_any_upload(self):
        response = Mock(stdout=json.dumps({'assets': [{'name': 'VulnAI-Scanner-darwin-arm64.zip'}]}))
        with patch('desktop.publish_macos.subprocess.run', return_value=response) as command:
            with self.assertRaisesRegex(ValueError, 'already exist'):
                publish(self.root, 'v0.1.0-preview', 'owner/repo')
        command.assert_called_once()

    def test_missing_release_is_not_created_implicitly(self):
        with patch('desktop.publish_macos.subprocess.run', side_effect=subprocess.CalledProcessError(1, 'gh')) as command:
            with self.assertRaises(subprocess.CalledProcessError):
                publish(self.root, 'v0.1.0-preview', 'owner/repo')
        command.assert_called_once()

    def test_invalid_tag_or_repository_never_calls_github(self):
        for tag, repo in (('--help', 'owner/repo'), ('v0.1.0-preview', '--help')):
            with self.subTest(tag=tag, repo=repo), patch('desktop.publish_macos.subprocess.run') as command:
                with self.assertRaises(ValueError):
                    publish(self.root, tag, repo)
                command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
