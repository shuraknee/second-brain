#!/usr/bin/env python3
"""Wrapper repair preservation and refusal checks; systemd is mocked here."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('wrapper_repair', str(ROOT / 'tools/repair.py'))
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='repair-test-', dir=ROOT / 'dist')
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        self.target = self.base / 'existing путь % $'
        for name in ['agent.md', 'manifest.json', 'tools/install.py', 'tools/service.py',
                     'tools/egress_guard.py', 'tools/proxy.py', 'tools/ingress.py',
                     'tools/git_support.py', 'tools/repair.py',
                     'templates/silverbullet.service.in', 'templates/silverbullet-ingress.service.in']:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, path)
        binary = self.source / 'bin/silverbullet'
        binary.parent.mkdir()
        binary.write_bytes(b'never executed: synthetic unchanged core')
        manifest = json.loads((self.source / 'manifest.json').read_text())
        manifest['binary_sha256'] = repair.install.digest(binary)
        (self.source / 'manifest.json').write_text(json.dumps(manifest))
        self.sums(self.source)
        shutil.copytree(self.source, self.target)
        (self.target / 'tools/repair.py').unlink()
        manifest['supply_revision'] = 'offline-ipv4-only-20261110'
        (self.target / 'manifest.json').write_text(json.dumps(manifest))
        for name in ['silverbullet.service.in', 'silverbullet-ingress.service.in']:
            path = self.target / 'templates' / name
            path.write_text(path.read_text().replace('Type=simple', 'Type=simple\nCapabilityBoundingSet='))
        self.sums(self.target)
        self.unit_dir = self.base / 'config/systemd/user'
        self.unit_dir.mkdir(parents=True)
        self.name = 'second-brain-' + hashlib.sha256(os.fsencode(self.target)).hexdigest()[:16]
        self.old_units = repair.install.render_units(self.target, Path(sys.executable).resolve(), self.name, source=self.target)
        state = {'target': str(self.target), 'uid': os.getuid(), 'unit_directory': str(self.unit_dir), 'units': {}}
        for name, text in self.old_units.items():
            path = self.unit_dir / name
            path.write_text(text)
            state['units'][name] = repair.install.digest(path)
        (self.target / '.install-state.json').write_text(json.dumps(state))
        (self.target / 'config').mkdir(exist_ok=True)
        config = {'status': 'target-approved', 'namespace_required': True,
                  'data_directory': str(self.target / 'data'), 'runtime_directory': str(self.base / 'runtime'),
                  'listen_host': '127.0.0.1', 'listen_port': 32991, 'backend_port': 32992,
                  'history_mode': 'disabled', 'public_url': 'http://127.0.0.1:32991'}
        (self.target / 'config/service.json').write_text(json.dumps(config))
        self.data = {'data/users.json': b'synthetic account', 'data/initial-credentials.json': b'synthetic password',
                     'data/spaces/notes/Note.md': b'preserve note', 'data/spaces/notes/.git/HEAD': b'preserve history'}
        for name, data in self.data.items():
            path = self.target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.commands = []
        self.patches = [patch.object(repair.install, 'SOURCE', self.source),
                        patch.dict(os.environ, {'XDG_CONFIG_HOME': str(self.base / 'config')}),
                        patch.object(repair.install, 'call', side_effect=self.call),
                        patch.object(repair.install, 'preflight', return_value={}),
                        patch.object(repair.install, 'check_port')]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def sums(self, root):
        files = sorted(p for p in root.rglob('*') if p.is_file() and p != root / 'SHA256SUMS')
        (root / 'SHA256SUMS').write_text(''.join(repair.install.digest(p) + '  ' + str(p.relative_to(root)) + '\n' for p in files))

    def call(self, args, **kwargs):
        self.commands.append(args)
        output = str(self.unit_dir / args[3]) + '\n' if '--property=FragmentPath' in args else ''
        return subprocess.CompletedProcess(args, 0, output)

    def plan(self, backup=None):
        return repair.make_plan(argparse.Namespace(target=str(self.target), backup=str(backup or self.base / 'backup'),
            output=self.base / 'repair.plan.json', no_start=True))

    def apply(self, plan):
        path = self.base / 'repair.plan.json'
        path.write_text(json.dumps(plan))
        repair.apply(argparse.Namespace(plan=path, sha256=repair.install.digest(path)))

    def no_stops(self):
        self.assertFalse(any('stop' in args for args in self.commands))

    def test_plan_keeps_exact_managed_unit_names(self):
        plan = self.plan()
        self.assertEqual(set(plan['units']), set(self.old_units))
        self.assertFalse((self.base / 'backup').exists())
        self.no_stops()

    def test_repair_preserves_data_and_backs_up_old_wrapper(self):
        self.apply(self.plan())
        for name, data in self.data.items():
            self.assertEqual((self.target / name).read_bytes(), data)
        backup = self.base / 'backup'
        self.assertFalse((backup / 'payload/data').exists())
        self.assertEqual(json.loads((backup / 'repair.json').read_text())['phase'], 'completed')
        config = json.loads((self.target / 'config/service.json').read_text())
        self.assertFalse(config['namespace_required'])
        self.assertEqual(config['network_policy'], 'seccomp-no-connect')
        for name, text in self.old_units.items():
            self.assertEqual((backup / 'units' / name).read_text(), text)
            self.assertNotIn('CapabilityBoundingSet=', (self.unit_dir / name).read_text())

    def test_foreign_or_changed_unit_is_rejected_before_stop(self):
        path = self.unit_dir / next(iter(self.old_units))
        path.write_text(path.read_text() + '\n# changed by operator\n')
        with self.assertRaisesRegex(RuntimeError, 'ownership/content changed'):
            self.plan()
        self.no_stops()

    def test_payload_change_after_plan_is_rejected(self):
        plan = self.plan()
        (self.source / 'tools/service.py').write_text('changed')
        with self.assertRaisesRegex(RuntimeError, 'checksum/path mismatch'):
            self.apply(plan)
        self.no_stops()

    def test_config_change_after_plan_is_rejected(self):
        plan = self.plan()
        path = self.target / 'config/service.json'
        config = json.loads(path.read_text())
        config['backend_port'] += 1
        path.write_text(json.dumps(config))
        with self.assertRaisesRegex(RuntimeError, 'inputs changed'):
            self.apply(plan)
        self.no_stops()

    def test_modified_plan_unit_is_rejected_even_with_new_plan_hash(self):
        plan = self.plan()
        plan['units'][next(iter(plan['units']))] += '\nExecStartPost=/bin/false\n'
        with self.assertRaisesRegex(RuntimeError, 'inputs changed'):
            self.apply(plan)
        self.no_stops()

    def test_backup_inside_data_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'outside target'):
            self.plan(self.target / 'data/backup')
        self.no_stops()

    def test_unrecognized_old_release_is_rejected(self):
        path = self.target / 'manifest.json'
        manifest = json.loads(path.read_text())
        manifest['supply_revision'] = 'unrecognized-release'
        path.write_text(json.dumps(manifest))
        self.sums(self.target)
        with self.assertRaisesRegex(RuntimeError, 'recorded local-Git/IPv4-only'):
            self.plan()
        self.no_stops()


if __name__ == '__main__':
    unittest.main()
