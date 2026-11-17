#!/usr/bin/env python3
"""Credential separation, stdio framing, failure semantics and ingress isolation."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
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
        def denied(key, value): raise client.secrets.StoreError('denied')
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
        with patch.object(client.secrets.shutil,'which',return_value='/usr/bin/secret-tool'):
            store=client.secrets.SecretService()
        with patch.object(client.secrets.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'',b'')) as run:
            store.set('profile-id','PRIVATE_TOKEN')
        self.assertNotIn('PRIVATE_TOKEN',' '.join(run.call_args.args[0]))
        self.assertEqual(run.call_args.kwargs['input'],b'PRIVATE_TOKEN')

    def test_linux_missing_safe_store_has_no_plaintext_fallback(self):
        with patch.object(client.secrets.shutil,'which',return_value=None):
            with self.assertRaises(client.secrets.StoreError): client.secrets.SecretService()

    def test_login_refuses_echoed_password_fallback(self):
        def insecure_input(*args):
            warnings.warn('not hidden', client.getpass.GetPassWarning)
            raise AssertionError('Password must not be read after warning')
        with patch.object(client.getpass, 'getpass', side_effect=insecure_input):
            with self.assertRaisesRegex(client.ClientError, 'hidden password'):
                client.read_password()

    def test_store_outage_is_not_misreported_as_absent_credential(self):
        with patch.object(client.secrets.shutil, 'which', return_value='/usr/bin/secret-tool'):
            store = client.secrets.SecretService()
        outcome = subprocess.CompletedProcess([], 1, b'', b'Secret service is not available')
        with patch.object(client.secrets.subprocess, 'run', return_value=outcome):
            with self.assertRaises(client.secrets.StoreError): store.get('profile-id')

    def test_partial_pipe_writes_do_not_drop_protocol_bytes(self):
        class ShortPipe(io.BytesIO):
            def write(self, data): return super().write(data[:3])
        output = ShortPipe()
        frame = b'{"jsonrpc":"2.0","id":19}\n'
        client.write_all(output, frame)
        self.assertEqual(output.getvalue(), frame)


if __name__=='__main__': unittest.main()
