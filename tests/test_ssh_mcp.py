#!/usr/bin/env python3
"""Credential separation, stdio framing, failure semantics and ingress isolation."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bridge = load('bridge', 'ssh_mcp/bridge.py')
client = load('client', 'ssh_mcp/client.py')
native = load('native_secret_store', 'ssh_mcp/secret_store.py')
proxy = load('ssh_proxy', 'tools/proxy.py')


class MemoryStore:
    def __init__(self): self.values = {}
    def get(self, key): return self.values.get(key)
    def set(self, key, value): self.values[key] = value
    def delete(self, key): self.values.pop(key, None)


class FakeBackend:
    def __init__(self): self.calls = []
    def post(self, operation, payload, token=None):
        self.calls.append((operation, payload, token))
        if operation == 'identity': return [{'ok': True, 'username': 'alice'}]
        if operation == 'rpc':
            if 'id' not in payload: return []
            return [{'jsonrpc':'2.0', 'id':payload['id'], 'result':{'owner':'alice'}}]
        if operation == 'logout': return [{'ok':True}]
        return [{'ok':True, 'username':'alice', 'token':'sbm_FAKE_PERSONAL_SECRET'}]


class SshMcpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.profile = client.configure(self.root, 'opencode', 'ssh-alias', '/tools/bridge.py', '/tools/bridge.json')

    def tearDown(self): self.temp.cleanup()

    def test_config_has_no_credentials_and_target_changes_do_not_reuse_secret(self):
        data = json.loads((self.root/'opencode.json').read_text())
        self.assertNotIn('token', data); self.assertNotIn('password', data)
        a = client.credential_key(data)
        data['ssh_target'] = 'other-host'
        self.assertNotEqual(a, client.credential_key(data))
        with self.assertRaises(FileExistsError):
            client.configure(self.root, 'opencode', 'ssh-alias', '/x', '/y')

    def test_ssh_command_has_no_secrets_no_forwarding_and_no_shell_injection(self):
        profile = dict(self.profile, remote_bridge='/tools/a $name/bridge.py')
        with patch.object(client.shutil, 'which', return_value='/usr/bin/ssh'):
            command = client.ssh_command(profile)
        self.assertIn('StrictHostKeyChecking=yes', command)
        self.assertIn('ClearAllForwardings=yes', command)
        self.assertIn('ForwardAgent=no', command)
        self.assertIn("'/tools/a $name/bridge.py'", command[-1])
        self.assertNotIn('password', ' '.join(command))
        with self.assertRaises(client.ClientError):
            client.validate_target('-oProxyCommand=bad', '/x', '/y')

    def test_setup_registers_both_clis_with_the_verified_command_and_reuses_token(self):
        args = client.argparse.Namespace(ssh_target='ssh-alias', remote_bridge='/tools/bridge.py',
                                        remote_config='/tools/bridge.json', renew=False)
        profile = client.configure(self.root, 'team', args.ssh_target, args.remote_bridge, args.remote_config)
        token_path = self.root / 'personal-token.json'
        with patch.object(client, 'issue_credential', return_value={'username':'me', 'token':'sbm_PRIVATE'}):
            client.issue_token(profile, token_path, 'me', 'test-password')
        with patch('builtins.input', side_effect=['3']), patch.object(client, 'read_password', side_effect=AssertionError), \
             patch.object(client.shutil, 'which', side_effect=lambda name: '/test/' + name), \
             patch.object(client, 'verify_mcp') as probe, patch.object(client.subprocess, 'run') as register:
            register.return_value.returncode = 0
            client.setup_agents(self.root, args)
        runtime = probe.call_args.args[0]
        self.assertEqual(runtime[-2:], ['--token-file', str(token_path)])
        self.assertEqual([call.args[0] for call in register.call_args_list], [
            ['/test/opencode', 'mcp', 'add', 'secondbrain', '--', *runtime],
            ['/test/gigacode', 'mcp', 'add', 'secondbrain', runtime[0], '--transport', 'stdio',
             '--scope', 'user', '--', *runtime[1:]]])


    def test_login_secret_travels_in_stdin_and_token_only_goes_to_store(self):
        store = MemoryStore()
        reply = subprocess.CompletedProcess([], 0, b'{"ok":true,"username":"alice","token":"sbm_PRIVATE"}', b'')
        with patch.object(client.subprocess, 'run', return_value=reply) as run, \
             patch.object(client.shutil, 'which', return_value='/usr/bin/ssh'):
            self.assertEqual(client.login(self.profile, store, 'alice', 'PERSONAL_PASSWORD'), 'alice')
        call = run.call_args
        self.assertNotIn('PERSONAL_PASSWORD', ' '.join(call.args[0]))
        self.assertIn(b'PERSONAL_PASSWORD', call.kwargs['input'])
        self.assertEqual(store.get(client.credential_key(self.profile)), 'sbm_PRIVATE')
        self.assertNotIn('PERSONAL_PASSWORD', (self.root/'opencode.json').read_text())
        self.assertNotIn('sbm_PRIVATE', (self.root/'opencode.json').read_text())

    def test_failed_keychain_save_revokes_issued_token(self):
        store = MemoryStore()
        def denied(key, value): raise native.StoreError('denied')
        store.set = denied
        with patch.object(client, 'exchange', side_effect=[{'ok':True,'username':'alice','token':'sbm_PERSONAL'}, {'ok':True}]) as exchange:
            with self.assertRaisesRegex(client.ClientError, 'was revoked'):
                client.login(self.profile, store, 'alice', 'password')
        self.assertEqual(exchange.call_count, 2)
        self.assertEqual(exchange.call_args.args[1]['action'], 'logout')

    def test_unknown_ssh_outcome_never_retries_and_does_not_echo_output(self):
        result = subprocess.CompletedProcess([], 1, b'password SECRET', b'token SECRET')
        with patch.object(client.subprocess, 'run', return_value=result) as run, \
             patch.object(client.shutil, 'which', return_value='/usr/bin/ssh'):
            with self.assertRaises(client.ClientError) as caught:
                client.exchange(self.profile, {'action':'logout','token':'SECRET'})
        self.assertNotIn('SECRET', str(caught.exception)); self.assertEqual(run.call_count,1)

    def test_bridge_authenticates_once_then_preserves_rpc_and_ignores_notifications(self):
        source = io.BytesIO(b'{"bridge_version":1,"action":"connect","token":"sbm_PERSONAL"}\n'
                            b'{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}\n'
                            b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        output = io.BytesIO(); backend = FakeBackend()
        bridge.serve(backend, source, output)
        messages = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(messages),2)
        self.assertEqual(messages[0]['username'],'alice')
        self.assertEqual(messages[1]['id'],7)
        self.assertNotIn(b'sbm_PERSONAL',output.getvalue())
        self.assertEqual(backend.calls[1][1]['method'],'initialize')
        self.assertEqual(backend.calls[1][2],'sbm_PERSONAL')

    def test_bridge_rejects_arbitrary_backend_and_oversized_preface(self):
        path=self.root/'bridge.json';path.write_text('{"backend_port":3001,"url":"http://external"}')
        with self.assertRaises(bridge.BridgeError): bridge.load_config(path)
        with self.assertRaises(bridge.BridgeError): bridge.read_packet(io.BytesIO(b'x'*17000+b'\n'),16384)

    def test_private_routes_never_pass_public_ingress(self):
        for path in ['/.ssh-mcp/login','/./.ssh-mcp/rpc','/%2essh-mcp/rpc','/a/../.ssh-mcp/identity',
                     '/%252essh-mcp/login','/.ssh-mcp/logout?x=1']:
            self.assertTrue(proxy.private_ssh_path(path),path)
        for path in ['/.mcp','/.auth/register','/index','/Library/Second%20Brain/Правила']:
            self.assertFalse(proxy.private_ssh_path(path),path)

    def test_sse_reply_is_parsed_without_exposing_transport_framing(self):
        body=b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n: heartbeat\n\n'
        self.assertEqual(list(bridge.sse_messages(body)),[{'jsonrpc':'2.0','id':1,'result':{}}])

    def test_linux_secret_service_never_puts_secret_in_argv(self):
        with patch.object(native.shutil,'which',return_value='/usr/bin/secret-tool'):
            store=native.SecretService()
        with patch.object(native.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'',b'')) as run:
            store.set('profile-id','PRIVATE_TOKEN')
        self.assertNotIn('PRIVATE_TOKEN',' '.join(run.call_args.args[0]))
        self.assertEqual(run.call_args.kwargs['input'],b'PRIVATE_TOKEN')

    def test_linux_missing_safe_store_has_no_plaintext_fallback(self):
        with patch.object(native.shutil,'which',return_value=None):
            with self.assertRaises(native.StoreError): native.SecretService()

    def test_login_refuses_echoed_password_fallback(self):
        def insecure_input(*args):
            warnings.warn('not hidden', client.getpass.GetPassWarning)
            raise AssertionError('Password must not be read after warning')
        with patch.object(client.getpass, 'getpass', side_effect=insecure_input):
            with self.assertRaisesRegex(client.ClientError, 'hidden password'):
                client.read_password()

    def test_store_outage_is_not_misreported_as_absent_credential(self):
        with patch.object(native.shutil, 'which', return_value='/usr/bin/secret-tool'):
            store = native.SecretService()
        outcome = subprocess.CompletedProcess([], 1, b'', b'Secret service is not available')
        with patch.object(native.subprocess, 'run', return_value=outcome):
            with self.assertRaises(native.StoreError): store.get('profile-id')

    def test_partial_pipe_writes_do_not_drop_protocol_bytes(self):
        class ShortPipe(io.BytesIO):
            def write(self, data): return super().write(data[:3])
        output = ShortPipe()
        frame = b'{"jsonrpc":"2.0","id":19}\n'
        client.write_all(output, frame)
        self.assertEqual(output.getvalue(), frame)

    def token_environment(self):
        return {client.TOKEN_ENV: 'sbm_PRIVATE_CONFIG_TOKEN',
                client.PROFILE_ENV: client.credential_key(self.profile)}

    def run_cli(self, args, environment=None):
        out, error = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, environment or {}, clear=True), \
                patch.object(client, 'open_native_store', side_effect=AssertionError('Native store must not be used')), \
                patch('sys.stdout', out), patch('sys.stderr', error):
            code = client.main(['--config-dir', str(self.root), *args])
        self.assertNotIn('sbm_PRIVATE_CONFIG_TOKEN', out.getvalue() + error.getvalue())
        return code, out.getvalue(), error.getvalue()

    def test_default_env_mode_never_contacts_native_store(self):
        code, out, error = self.run_cli(['status', '--profile', 'opencode'], self.token_environment())
        self.assertEqual(code, 0, error)
        self.assertIn('token present', out)

    def test_missing_env_fails_without_native_fallback_or_ssh(self):
        with patch.object(client.subprocess, 'Popen', side_effect=AssertionError('SSH must not start')):
            code, out, error = self.run_cli(['mcp', '--profile', 'opencode'])
        self.assertEqual(code, 1)
        self.assertIn('No personal MCP token', error)

    def test_config_token_is_bound_to_profile_before_any_ssh_request(self):
        environment = self.token_environment()
        environment[client.PROFILE_ENV] = 'wrong-server-or-profile'
        with patch.object(client.subprocess, 'Popen', side_effect=AssertionError('SSH must not start')):
            code, out, error = self.run_cli(['mcp', '--profile', 'opencode'], environment)
        self.assertEqual(code, 1)
        self.assertIn('Credential/profile mismatch', error)

    def test_token_environment_is_consumed_and_scrubbed_from_ssh_child(self):
        with patch.dict(os.environ, self.token_environment()):
            store = client.EnvironmentStore(self.profile)
            self.assertNotIn(client.TOKEN_ENV, os.environ)
            self.assertNotIn(client.PROFILE_ENV, os.environ)
            self.assertEqual(store.get(client.credential_key(self.profile)), 'sbm_PRIVATE_CONFIG_TOKEN')
        outcome = subprocess.CompletedProcess([], 0, b'{"ok":true}', b'')
        with patch.dict(os.environ, self.token_environment()), \
                patch.object(client.subprocess, 'run', return_value=outcome) as run, \
                patch.object(client.shutil, 'which', return_value='/usr/bin/ssh'):
            client.exchange(self.profile, {'bridge_version':1, 'action':'logout', 'token':'sbm_PRIVATE_CONFIG_TOKEN'})
        self.assertNotIn(client.TOKEN_ENV, run.call_args.kwargs['env'])
        self.assertNotIn(client.PROFILE_ENV, run.call_args.kwargs['env'])
        self.assertNotIn('sbm_PRIVATE_CONFIG_TOKEN', ' '.join(run.call_args.args[0]))
        self.assertIn(b'sbm_PRIVATE_CONFIG_TOKEN', run.call_args.kwargs['input'])

    def test_issue_export_uses_existing_account_without_os_store_or_stdout_secret(self):
        path = self.root / 'private-export.json'
        reply = {'ok':True, 'username':'alice', 'token':'sbm_PRIVATE_CONFIG_TOKEN', 'expires_in':7776000}
        with patch.object(client, 'exchange', return_value=reply) as exchange, \
                patch.object(client, 'read_password', return_value='HIDDEN_PASSWORD'):
            code, out, error = self.run_cli(['issue-token', '--profile', 'opencode', '--username', 'alice', '--output', str(path)])
        self.assertEqual(code, 0, error)
        data = json.loads(path.read_text())
        self.assertEqual(data['username'], 'alice')
        self.assertEqual(data['environment'], self.token_environment())
        if os.name != 'nt': self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('HIDDEN_PASSWORD', path.read_text() + out + error)
        self.assertEqual(exchange.call_args.args[1]['username'], 'alice')
        self.assertEqual(exchange.call_args.args[1]['action'], 'login')
        self.assertNotIn('sbm_PRIVATE_CONFIG_TOKEN', (self.root/'opencode.json').read_text())
        code, out, error = self.run_cli(['status', '--profile', 'opencode', '--token-file', str(path)])
        self.assertEqual(code, 0, error)

    def test_export_refuses_existing_file_before_token_rotation(self):
        path = self.root / 'do-not-replace.json'
        path.write_text('existing config')
        with patch.object(client, 'exchange', side_effect=AssertionError('No token should be issued')):
            with self.assertRaises(FileExistsError):
                client.issue_token(self.profile, path, 'alice', 'password')
        self.assertEqual(path.read_text(), 'existing config')

    def test_failed_export_revokes_token_and_removes_partial_file(self):
        path = self.root / 'failed-export.json'
        reply = {'ok':True, 'username':'alice', 'token':'sbm_PRIVATE_CONFIG_TOKEN'}
        with patch.object(client, 'exchange', side_effect=[reply, {'ok':True}]) as exchange, \
                patch.object(client.os, 'fsync', side_effect=OSError('synthetic write failure')):
            with self.assertRaisesRegex(client.ClientError, 'was revoked'):
                client.issue_token(self.profile, path, 'alice', 'password')
        self.assertFalse(path.exists())
        self.assertEqual(exchange.call_count, 2)
        self.assertEqual(exchange.call_args.args[1]['action'], 'logout')

    def test_export_logout_revokes_without_editing_config_or_native_store(self):
        path = self.root / 'revoke-export.json'
        reply = {'ok':True, 'username':'alice', 'token':'sbm_PRIVATE_CONFIG_TOKEN'}
        with patch.object(client, 'exchange', return_value=reply):
            client.issue_token(self.profile, path, 'alice', 'password')
        before = path.read_bytes()
        with patch.object(client, 'exchange', return_value={'ok':True}) as exchange:
            code, out, error = self.run_cli(['logout', '--profile', 'opencode', '--token-file', str(path)])
        self.assertEqual(code, 0, error)
        self.assertIn('Credential revoked', out)
        self.assertEqual(exchange.call_args.args[1]['action'], 'logout')
        self.assertEqual(path.read_bytes(), before)

    def test_export_rejects_symlinks_and_public_permissions(self):
        path = self.root / 'token.json'
        with patch.object(client, 'exchange', return_value={'ok':True,'username':'alice','token':'sbm_PRIVATE_CONFIG_TOKEN'}):
            client.issue_token(self.profile, path, 'alice', 'password')
        link = self.root / 'linked-token.json'
        link.symlink_to(path)
        with self.assertRaises(client.ClientError): client.file_store(self.profile, link)
        if os.name != 'nt':
            path.chmod(0o644)
            with self.assertRaises(client.ClientError): client.file_store(self.profile, path)

    def test_old_login_requires_explicit_native_opt_in(self):
        with patch.object(client, 'read_password', side_effect=AssertionError('Password must not be requested')):
            code, out, error = self.run_cli(['login', '--profile', 'opencode'])
        self.assertEqual(code, 1)
        self.assertIn('issue-token', error)

    def test_native_store_is_only_opened_after_explicit_selection(self):
        with patch.object(client, 'open_native_store', return_value=MemoryStore()) as opened, \
                patch('sys.stdout', io.StringIO()):
            code = client.main(['--config-dir', str(self.root), 'status', '--profile', 'opencode', '--credential-source', 'os-store'])
        self.assertEqual(code, 0)
        opened.assert_called_once_with()

    def test_config_mode_runs_without_native_module_present(self):
        standalone = self.root / 'standalone'
        standalone.mkdir()
        script = standalone / 'client.py'
        script.write_bytes((ROOT/'ssh_mcp/client.py').read_bytes())
        environment = dict(os.environ, **self.token_environment())
        result = subprocess.run([sys.executable, '-I', '-B', str(script), '--config-dir', str(self.root),
            'status', '--profile', 'opencode'], env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('token present', result.stdout)
        self.assertNotIn('sbm_PRIVATE_CONFIG_TOKEN', result.stdout+result.stderr)
        self.assertFalse((standalone/'secret_store.py').exists())

    def test_control_characters_in_config_token_are_rejected_before_ssh(self):
        environment = self.token_environment()
        environment[client.TOKEN_ENV] += '\nINJECTED'
        with patch.object(client.subprocess, 'Popen', side_effect=AssertionError('SSH must not start')):
            code, out, error = self.run_cli(['mcp', '--profile', 'opencode'], environment)
        self.assertEqual(code, 1)
        self.assertNotIn('INJECTED', error)


if __name__=='__main__': unittest.main()
