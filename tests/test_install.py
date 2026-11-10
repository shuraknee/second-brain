#!/usr/bin/env python3
"""Portable installation tests; systemd writes are confined to a fake XDG root."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REAL_CONFIG = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
spec = importlib.util.spec_from_file_location('installer', str(ROOT / 'tools/install.py'))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='portable-', dir=ROOT / 'dist')
        self.base = Path(self.temp.name)
        self.runtime_temp = tempfile.TemporaryDirectory(prefix='sbi-', dir=os.environ['XDG_RUNTIME_DIR'])
        self.runtime = Path(self.runtime_temp.name)
        self.source = self.base / 'source with пробелы % $'
        self.source.mkdir()
        names = ['agent.md', 'manifest.json', 'tools/install.py', 'tools/service.py',
                 'tools/proxy.py', 'tools/ingress.py', 'tools/egress_guard.py', 'tools/git_support.py',
                 'templates/silverbullet.service.in', 'templates/silverbullet-ingress.service.in']
        for name in names:
            destination = self.source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        binary = self.source / 'bin/silverbullet'
        binary.parent.mkdir()
        binary.write_bytes(b'never executed in mocked installation tests')
        manifest = json.loads((self.source / 'manifest.json').read_text())
        manifest['binary_sha256'] = installer.digest(binary)
        (self.source / 'manifest.json').write_text(json.dumps(manifest))
        entries = sorted(p for p in self.source.rglob('*') if p.is_file())
        (self.source / 'SHA256SUMS').write_text(''.join(installer.digest(p) + '  ' + str(p.relative_to(self.source)) + '\n' for p in entries))
        self.env = patch.dict(os.environ, {'XDG_CONFIG_HOME': str(self.base / 'config with % $'),
                                           'XDG_RUNTIME_DIR': str(self.runtime)})
        self.env.start()
        self.root_patch = patch.object(installer, 'SOURCE', self.source)
        self.root_patch.start()

    def tearDown(self):
        self.root_patch.stop()
        self.env.stop()
        self.runtime_temp.cleanup()
        self.temp.cleanup()

    def arguments(self, target=None):
        return argparse.Namespace(target=str(target or (self.base / 'arbitrary путь % $ " \\')),
            port=32831, backend_port=32832, public_url='http://LOCALHOST:32831/',
            listen_host='127.0.0.1', runtime_dir=None, admin_user='chosen-admin',
            space_name='Chosen Space', no_start=True, enable=False,
            output=self.base / 'install.plan.json')

    def plan(self, args=None):
        with patch.object(installer, 'preflight', return_value={}), \
             patch.object(installer, 'fresh_units'), patch.object(installer, 'check_port'):
            return installer.make_plan(args or self.arguments())

    def fake_call(self, args, **kwargs):
        return subprocess.CompletedProcess(args, 0, 'not-found\n' if '--property=LoadState' in args else '')

    def test_arbitrary_target_and_safe_unit_arguments(self):
        plan = self.plan()
        target = Path(plan['target'])
        self.assertEqual(plan['config']['data_directory'], str(target / 'data'))
        self.assertEqual(plan['config']['public_url'], 'http://localhost:32831')
        unit = next(iter(plan['units'].values()))
        self.assertIn('%%', unit)
        self.assertIn('$$', unit)
        self.assertIn('\\"', unit)
        self.assertIn('\\\\', unit)
        self.assertNotIn('WorkingDirectory=', unit)

    def test_long_target_uses_short_runtime_socket(self):
        target = self.base / ('long каталог ' * 10) / ('another ' * 15)
        plan = self.plan(self.arguments(target))
        self.assertGreater(len(os.fsencode(target)), 104)
        self.assertLess(len(os.fsencode(plan['config']['gateway_socket'])), 104)
        self.assertFalse(str(plan['config']['gateway_socket']).startswith(str(target)))

    def test_no_start_apply_writes_only_selected_paths(self):
        plan = self.plan()
        path = self.base / 'apply.plan.json'
        path.write_text(json.dumps(plan))
        args = argparse.Namespace(plan=path, sha256=installer.digest(path))
        with patch.object(installer, 'preflight', return_value={}), \
             patch.object(installer, 'call', side_effect=self.fake_call), patch.object(installer, 'check_port'):
            installer.apply_plan(args)
        target = Path(plan['target'])
        self.assertTrue((target / 'tools/service.py').exists())
        self.assertFalse((target / 'data').exists())
        self.assertEqual(json.loads((target / 'config/service.json').read_text()), plan['config'])
        for name, text in plan['units'].items():
            self.assertEqual((Path(plan['unit_directory']) / name).read_text(), text)

    def test_existing_user_data_unchanged(self):
        target = self.base / 'existing'
        target.mkdir()
        note = target / 'note.txt'
        note.write_text('preserve this')
        with self.assertRaisesRegex(RuntimeError, 'not empty'):
            self.plan(self.arguments(target))
        self.assertEqual(note.read_text(), 'preserve this')

    def test_changed_plan_is_rejected_before_write(self):
        plan = self.plan()
        path = self.base / 'changed.plan.json'
        path.write_text(json.dumps(plan))
        with self.assertRaisesRegex(RuntimeError, 'SHA256 mismatch'):
            installer.apply_plan(argparse.Namespace(plan=path, sha256='0' * 64))
        self.assertFalse(Path(plan['target']).exists())

    def test_changed_payload_is_rejected(self):
        plan = self.plan()
        path = self.base / 'changed-payload.plan.json'
        path.write_text(json.dumps(plan))
        (self.source / 'tools/service.py').write_text('modified')
        with self.assertRaisesRegex(RuntimeError, 'checksum/path mismatch'):
            installer.apply_plan(argparse.Namespace(plan=path, sha256=installer.digest(path)))
        self.assertFalse(Path(plan['target']).exists())

    def test_modified_unit_in_plan_is_rejected_even_with_new_hash(self):
        plan = self.plan()
        first = next(iter(plan['units']))
        plan['units'][first] += '\nExecStartPost=/bin/false\n'
        path = self.base / 'modified-unit.plan.json'
        path.write_text(json.dumps(plan))
        with self.assertRaisesRegex(RuntimeError, 'unit content'):
            installer.apply_plan(argparse.Namespace(plan=path, sha256=installer.digest(path)))
        self.assertFalse(Path(plan['target']).exists())

    def test_failed_seccomp_probe_prevents_plan(self):
        args = self.arguments()
        with patch.object(installer, 'preflight', side_effect=RuntimeError('isolation unavailable')), \
             patch.object(installer, 'fresh_units'), patch.object(installer, 'check_port'):
            with self.assertRaisesRegex(RuntimeError, 'isolation unavailable'):
                installer.make_plan(args)
        self.assertFalse(Path(args.target).exists())

    def test_failed_ingress_start_reports_status_and_stops_own_main(self):
        target = self.base / 'failed-start'
        (target / 'config').mkdir(parents=True)
        (target / 'config/service.json').write_text(json.dumps({'listen_host': '127.0.0.1',
            'listen_port': 32831, 'history_mode': 'disabled'}))
        commands = []
        def invoke(args, **kwargs):
            commands.append(args)
            if 'start' in args:
                raise RuntimeError('systemd start failed')
            return subprocess.CompletedProcess(args, 0, 'ExecMainStatus=218\nResult=exit-code\n')
        with patch.object(installer, 'owned', return_value={'units': {'own-main.service': '', 'own-ingress.service': ''}}), \
             patch.object(installer, 'preflight', return_value={}), \
             patch.object(installer, 'check_port'), patch.object(installer, 'call', side_effect=invoke):
            with self.assertRaisesRegex(RuntimeError, 'ExecMainStatus=218'):
                installer.control(target, 'start')
        self.assertIn(['systemctl', '--user', 'stop', 'own-ingress.service', 'own-main.service'], commands)

    def test_managed_history_requires_preinstalled_git(self):
        with patch.object(installer, 'load_module') as module:
            module.return_value.require_git.side_effect = RuntimeError('preinstalled Git is missing')
            with self.assertRaisesRegex(RuntimeError, 'preinstalled Git is missing'):
                self.plan()
        self.assertFalse(Path(self.arguments().target).exists())

    def test_disabled_history_does_not_require_git(self):
        args = self.arguments()
        args.history_mode = 'disabled'
        with patch.object(installer, 'load_module') as module:
            plan = self.plan(args)
        module.assert_not_called()
        self.assertEqual(plan['config']['history_mode'], 'disabled')

    def test_busy_port_is_never_freed(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            with self.assertRaises(OSError):
                installer.check_port('127.0.0.1', listener.getsockname()[1])
            self.assertGreater(listener.fileno(), -1)

    def test_foreign_unit_is_not_replaced(self):
        directory = self.base / 'units'
        directory.mkdir()
        foreign = directory / 'chosen.service'
        foreign.write_text('foreign')
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            installer.fresh_units(directory, {'chosen.service': 'ours'})
        self.assertEqual(foreign.read_text(), 'foreign')

    def test_plan_output_must_be_outside_target(self):
        args = self.arguments()
        args.output = Path(args.target) / 'plan.json'
        with self.assertRaisesRegex(ValueError, 'outside TARGET'):
            self.plan(args)

    def test_arguments_roundtrip_in_real_user_unit(self):
        name = 'second-brain-argv-test-' + uuid.uuid4().hex + '.service'
        directory = REAL_CONFIG / 'systemd/user'
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        output = self.base / 'argv output % $ " \\ кириллица.json'
        argument = str(self.base / 'chosen path % $ " \\ кириллица')
        script = 'import json,sys; open(sys.argv[1], "w").write(json.dumps(sys.argv[2:]))'
        command = [Path(sys.executable).resolve(), '-I', '-B', '-c', script, output, argument]
        text = '[Service]\nType=oneshot\nExecStart=' + ' '.join(installer.exec_argument(a) for a in command) + '\n'
        try:
            with path.open('x') as stream:
                stream.write(text)
            # These are unique temporary test units, never application units.
            subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', '--user', 'start', name], check=True, timeout=30)
            self.assertEqual(json.loads(output.read_text()), [argument])
        finally:
            subprocess.run(['systemctl', '--user', 'stop', name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if path.exists() and path.read_text() == text:
                path.unlink()
            subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True)


if __name__ == '__main__':
    (ROOT / 'dist').mkdir(exist_ok=True)
    unittest.main()
