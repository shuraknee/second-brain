#!/usr/bin/env python3
"""Ensure runtime archives exclude host metadata and normalize archive headers."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


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
                    self.assertEqual(len(archive.getmembers()), 21 + legal_files)
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
                    self.assertEqual(manifest['target_profile'], 'Linux x86_64, Python >=3.9, systemd --user')
                    config = json.load(archive.extractfile('silverbullet-offline/config/service.example.json'))
                    for key in ['public_url', 'backend_port', 'listen_host', 'listen_port', 'gateway_socket', 'admin_username', 'data_directory']:
                        self.assertIsNone(config[key], key)
                    for name in ['LICENSE', 'LICENSE.silverbullet.md', 'THIRD_PARTY_NOTICES.md', 'LICENSING.md',
                                 'licenses/sources/option-ext-0.2.0.crate', 'licenses/sources/htmlescape-0.3.1.crate',
                                 'licenses/fonts/Inter-OFL-1.1.txt']:
                        self.assertIn('silverbullet-offline/' + name, archive.getnames())
        finally:
            fixture.unlink()


if __name__ == '__main__':
    (ROOT / 'dist').mkdir(exist_ok=True)
    unittest.main()
