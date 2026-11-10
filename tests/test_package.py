#!/usr/bin/env python3
"""Ensure runtime archives exclude host metadata and normalize archive headers."""
import json
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare_release', ROOT / 'tools/prepare_release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class PackageTests(unittest.TestCase):
    def test_allowlist_and_reproducible_anonymous_headers(self):
        evidence = ROOT / 'evidence'
        evidence.mkdir(exist_ok=True)
        fixture = evidence / 'package-test-private-fixture.json'
        with fixture.open('x') as stream:
            json.dump({'hostname': 'synthetic-host-fixture', 'private_path': 'synthetic-private-path'}, stream)
        try:
            with tempfile.TemporaryDirectory(prefix='anonymous-package-', dir=ROOT / 'dist') as temporary:
                first = Path(temporary) / 'first.tar.gz'
                second = Path(temporary) / 'different-name.tar.gz'
                for output in [first, second]:
                    subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/build_supply.py'),
                                    '--binary', str(ROOT / 'bin/silverbullet'), '--output', str(output)],
                                   check=True, stdout=subprocess.DEVNULL)
                self.assertEqual(first.read_bytes(), second.read_bytes())
                with tarfile.open(first) as archive:
                    legal_files = sum(1 for p in (ROOT / 'licenses').rglob('*') if p.is_file())
                    self.assertEqual(len(archive.getmembers()), 28 + legal_files)
                    for entry in archive.getmembers():
                        parts = Path(entry.name).parts
                        self.assertEqual(entry.uid, 0)
                        self.assertEqual(entry.gid, 0)
                        self.assertEqual(entry.uname, '')
                        self.assertEqual(entry.gname, '')
                        self.assertEqual(entry.mtime, 0)
                        self.assertTrue(entry.isfile())
                        self.assertNotIn(parts[1], ['evidence', 'tests', 'data', 'state', 'releases'])
                        self.assertNotIn('build_supply.py', parts)
                        if not entry.name.endswith('/bin/silverbullet'):
                            content = archive.extractfile(entry).read()
                            self.assertNotIn(b'synthetic-host-fixture', content)
                            self.assertNotIn(b'synthetic-private-path', content)
                    manifest = json.load(archive.extractfile('silverbullet-offline/manifest.json'))
                    self.assertEqual(manifest['target_profile'], 'Linux x86_64, Python >=3.9, systemd --user; system Git >=2.34 for history')
                    config = json.load(archive.extractfile('silverbullet-offline/config/service.example.json'))
                    for key in ['public_url', 'backend_port', 'listen_host', 'listen_port', 'gateway_socket', 'admin_username', 'data_directory']:
                        self.assertIsNone(config[key], key)
                    for name in ['agent.md', 'INSTALL.md', 'MCP-GIT.md', 'RELEASING.md', 'LICENSE', 'LICENSE.silverbullet.md', 'THIRD_PARTY_NOTICES.md', 'LICENSING.md',
                                 'licenses/sources/option-ext-0.2.0.crate', 'licenses/sources/htmlescape-0.3.1.crate',
                                 'licenses/fonts/Inter-OFL-1.1.txt']:
                        self.assertIn('silverbullet-offline/' + name, archive.getnames())
                notes = Path(temporary) / 'notes.txt'
                notes.write_text('Synthetic release: package checks only; no target acceptance.', encoding='utf-8')
                assets = Path(temporary) / 'release assets'
                subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/prepare_release.py'),
                                '--archive', str(first), '--output', str(assets),
                                '--repository', 'example/second-brain', '--notes-file', str(notes)],
                               check=True, stdout=subprocess.DEVNULL)
                with tarfile.open(first) as archive:
                    for name in release.DOCUMENTS:
                        self.assertEqual((assets / name).read_bytes(),
                                         archive.extractfile('silverbullet-offline/' + name).read())
                for line in (assets / 'SHA256SUMS').read_text().splitlines():
                    checksum, name = line.split('  ', 1)
                    self.assertEqual(release.digest(assets / name), checksum)
                text = (assets / 'RELEASE_NOTES.md').read_text(encoding='utf-8')
                tag = json.loads((ROOT / 'manifest.json').read_text())['supply_revision']
                for name in ['agent.md', 'INSTALL.md']:
                    self.assertIn('https://github.com/example/second-brain/blob/' + tag + '/' + name,
                                  text.split('\n\n', 1)[0])
                self.assertNotIn('/blob/main/', text)
                self.assertTrue(text.endswith(notes.read_text() + '\n'))
        finally:
            fixture.unlink()

    def check_invalid_instruction(self, name, data, message):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'invalid.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                for document in release.DOCUMENTS:
                    content = data if document == name else (ROOT / document).read_bytes()
                    if content is not None:
                        info = tarfile.TarInfo('silverbullet-offline/' + document)
                        info.size = len(content)
                        archive.addfile(info, io.BytesIO(content))
            with self.assertRaisesRegex(RuntimeError, message):
                release.read_package(path)

    def test_release_without_agent_instruction_is_blocked(self):
        for name in ['agent.md', 'INSTALL.md']:
            with self.subTest(instruction=name):
                self.check_invalid_instruction(name, None, 'Required payload file missing: ' + name)

    def test_release_with_empty_agent_instruction_is_blocked(self):
        for name in ['agent.md', 'INSTALL.md']:
            with self.subTest(instruction=name):
                self.check_invalid_instruction(name, b' \n', 'Required document is empty: ' + name)

    def test_release_with_different_agent_instruction_is_blocked(self):
        for name in ['agent.md', 'INSTALL.md']:
            with self.subTest(instruction=name):
                self.check_invalid_instruction(name, b'Obsolete instruction from another version',
                                               'Document differs from this checkout: ' + name)


if __name__ == '__main__':
    (ROOT / 'dist').mkdir(exist_ok=True)
    unittest.main()
