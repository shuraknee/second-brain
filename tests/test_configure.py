#!/usr/bin/env python3
"""Direct-endpoint changes preserve data and reject stale or wider plans."""
import argparse
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


fixtures = load('endpoint_fixtures', ROOT / 'tests/test_repair.py')
configure = load('endpoint_configure', ROOT / 'tools/configure.py')
proxy = load('endpoint_proxy', ROOT / 'tools/proxy.py')


class ConfigureTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RepairTests('test_plan_keeps_exact_managed_unit_names')
        self.fixture.setUp()
        self.install_patch = patch.object(configure, 'install', fixtures.repair.install)
        self.repair_patch = patch.object(configure, 'repair', fixtures.repair)
        self.install_patch.start()
        self.repair_patch.start()
        self.target = self.fixture.target
        self.config_path = self.target / 'config/service.json'
        config = json.loads(self.config_path.read_text())
        config.update(namespace_required=False, network_policy='seccomp-no-connect')
        self.config_path.write_text(json.dumps(config))
        self.server_path = self.target / 'data/server.json'
        self.server_path.write_text(json.dumps({'primaryUrl': config['public_url'], 'futureSetting': 'preserve'}))

    def tearDown(self):
        self.repair_patch.stop()
        self.install_patch.stop()
        self.fixture.tearDown()

    def plan(self, **overrides):
        values = dict(target=str(self.target), listen_host='0.0.0.0', port=32993,
                      public_url='http://192.0.2.10:32993', backup=str(self.fixture.base / 'endpoint-backup'),
                      output=self.fixture.base / 'endpoint.plan.json', no_start=True)
        values.update(overrides)
        return configure.make_plan(argparse.Namespace(**values))

    def apply(self, plan):
        path = self.fixture.base / 'endpoint.plan.json'
        path.write_text(json.dumps(plan))
        configure.apply(argparse.Namespace(plan=path, sha256=configure.install.digest(path)))

    def test_changes_both_origins_preserves_accounts_notes_history_units(self):
        before = (self.target / '.install-state.json').read_bytes()
        self.apply(self.plan())
        self.assertEqual(json.loads(self.config_path.read_text())['public_url'], 'http://192.0.2.10:32993')
        server = json.loads(self.server_path.read_text())
        self.assertEqual(server['primaryUrl'], 'http://192.0.2.10:32993')
        self.assertEqual(server['futureSetting'], 'preserve')
        for name, data in self.fixture.data.items():
            self.assertEqual((self.target / name).read_bytes(), data)
        self.assertEqual((self.target / '.install-state.json').read_bytes(), before)
        self.assertTrue((self.fixture.base / 'endpoint-backup/server.json').exists())

    def test_wider_config_change_is_rejected_even_with_new_plan_hash(self):
        plan = self.plan()
        plan['config']['network_policy'] = 'disabled'
        with self.assertRaisesRegex(RuntimeError, 'only browser endpoint'):
            self.apply(plan)
        self.fixture.no_stops()

    def test_changed_server_metadata_is_rejected_before_stop(self):
        plan = self.plan()
        server = json.loads(self.server_path.read_text())
        server['futureSetting'] = 'changed by operator'
        self.server_path.write_text(json.dumps(server))
        with self.assertRaises(RuntimeError):
            self.apply(plan)
        self.fixture.no_stops()

    def test_start_failure_restores_both_files_and_stops_services(self):
        before = [p.read_bytes() for p in [self.config_path, self.server_path]]
        plan = self.plan()
        plan['start'] = True
        actions = []
        def control(target, action):
            actions.append(action)
            if action == 'start':
                raise RuntimeError('synthetic HTTP readiness failure')
        with patch.object(configure.install, 'control', side_effect=control):
            with self.assertRaisesRegex(RuntimeError, 'synthetic HTTP'):
                self.apply(plan)
        self.assertEqual(actions, ['stop', 'start', 'stop'])
        self.assertEqual([p.read_bytes() for p in [self.config_path, self.server_path]], before)

    def test_source_change_after_plan_is_rejected_before_stop(self):
        plan = self.plan()
        (self.fixture.source / 'tools/install.py').write_text('changed')
        with self.assertRaisesRegex(RuntimeError, 'checksum/path mismatch'):
            self.apply(plan)
        self.fixture.no_stops()

    def test_backup_inside_notes_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'outside target'):
            self.plan(backup=str(self.target / 'data/endpoint-backup'))
        self.fixture.no_stops()

    def test_wildcard_or_path_in_public_url_is_rejected(self):
        for url in ['http://0.0.0.0:32993', 'http://[::]:32993', 'http://192.0.2.10:32993/notes', 'http://192.0.2.10:0']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.plan(public_url=url)
        self.fixture.no_stops()

    def test_legacy_namespace_profile_is_not_changed(self):
        config = json.loads(self.config_path.read_text())
        config['namespace_required'] = True
        self.config_path.write_text(json.dumps(config))
        with self.assertRaisesRegex(RuntimeError, 'repair older profiles first'):
            self.plan()
        self.fixture.no_stops()

    def test_browser_port_cannot_replace_backend_port(self):
        with self.assertRaisesRegex(ValueError, 'must differ'):
            self.plan(port=32992)
        self.fixture.no_stops()

    def test_foreign_unit_marker_cannot_select_other_services(self):
        state = json.loads((self.target / '.install-state.json').read_text())
        state['units'] = {'another-project.service': 'synthetic'}
        with patch.object(configure.install, 'owned', return_value=state):
            with self.assertRaisesRegex(RuntimeError, 'Unexpected managed units'):
                self.plan()
        self.fixture.no_stops()

    def test_oauth_redirect_form_policy_is_limited_to_authorization_page(self):
        for path in ['/.login', '/', '/.auth/mcp/authorize-other']:
            self.assertIn("form-action 'self';", proxy.response_csp(path))
            self.assertNotIn('http://127.0.0.1:*', proxy.response_csp(path))
        policy = proxy.response_csp('/.auth/mcp/authorize?client_id=synthetic')
        self.assertIn("connect-src 'self'", policy)
        self.assertIn('http://127.0.0.1:*', policy)
        self.assertNotIn('form-action *', policy)


if __name__ == '__main__':
    unittest.main()
