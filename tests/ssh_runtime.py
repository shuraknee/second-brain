#!/usr/bin/env python3
"""Owned loopback-only SSH integration; never reads real client/server configuration.

Requires existing sshd, ssh-keygen and strace on the test host. The credential
store is an in-memory test double: native desktop stores need OS acceptance.
"""
import getpass
import http.cookiejar
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ssh_client_fixture', ROOT / 'ssh_mcp/client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class MemoryStore:
    def __init__(self): self.data = {}
    def get(self, key): return self.data.get(key)
    def set(self, key, value): self.data[key] = value
    def delete(self, key): self.data.pop(key, None)


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    report = {'passed': False, 'checks': {}, 'scope': 'owned local loopback SSH and Linux server; native credential store replaced by memory; no corporate acceptance',
        'binary_sha256': json.loads((ROOT / 'manifest.json').read_text())['binary_sha256']}
    with tempfile.TemporaryDirectory(prefix='sb-ssh-', dir=os.environ['XDG_RUNTIME_DIR']) as temporary:
        work = Path(temporary)
        public, backend, ssh_port = port(), port(), port()
        assert len({public, backend, ssh_port}) == 3
        origin = 'http://127.0.0.1:' + str(public)
        data, runtime = work / 'data', work / 'r'
        config = work / 'service.json'
        config.write_text(json.dumps({'status': 'target-approved', 'namespace_required': False,
            'network_policy': 'seccomp-no-connect', 'public_url': origin,
            'backend_port': backend, 'listen_host': '127.0.0.1', 'listen_port': public,
            'gateway_socket': str(runtime / 'g.sock'), 'runtime_directory': str(runtime),
            'admin_username': 'fixture-admin', 'space_name': 'Synthetic runtime test',
            'data_directory': str(data), 'history_mode': 'managed'}))
        bridge_config = work / 'bridge.json'
        bridge_config.write_text(json.dumps({'backend_port': backend}))
        bridge_config.chmod(0o600)
        processes = []
        log = (work / 'server.log').open('w+')
        trace = work / 'network.trace'
        def start(command):
            process = subprocess.Popen([str(a) for a in command], stdout=log, stderr=log, start_new_session=True)
            processes.append(process)
            return process
        try:
            start(['strace', '-f', '-qq', '-s', '128', '-e',
                'trace=connect,socket,sendto,sendmsg,sendmmsg,clone,clone3,fork,vfork',
                '-e', 'raw=sendto,sendmsg,sendmmsg', '-o', trace,
                sys.executable, '-I', '-B', ROOT / 'tools/service.py', '--config', config])
            start([sys.executable, '-I', '-B', ROOT / 'tools/ingress.py', '--config', config])
            jar = http.cookiejar.CookieJar()
            web = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
            def request(path, body=None, method=None, headers=None):
                payload = None if body is None else json.dumps(body).encode()
                req = urllib.request.Request(origin + path, data=payload, method=method,
                    headers={'Content-Type': 'application/json', **(headers or {})})
                try:
                    with web.open(req, timeout=15) as response:
                        raw = response.read()
                        return response.status, json.loads(raw) if raw else None
                except urllib.error.HTTPError as error:
                    return error.code, None
            for unused in range(150):
                assert all(p.poll() is None for p in processes), 'Fixture process exited'
                try:
                    if request('/.well-known/oauth-authorization-server')[0] == 200: break
                except (OSError, ValueError): pass
                time.sleep(.1)
            else: raise AssertionError('Fixture readiness failed')
            credentials = json.loads((data / 'initial-credentials.json').read_text())
            assert request('/.dashboard/api/login', credentials)[1]['status'] == 'ok'
            passwords = {name: secrets.token_urlsafe(24) for name in ['alice', 'bob']}
            for name, password in passwords.items():
                assert request('/.dashboard/api/admin/users', {'username': name, 'password': password})[0] == 200
            spaces = json.loads((data / 'spaces.json').read_text())
            space_id, settings = next(iter(spaces.items()))
            assert request('/.dashboard/api/admin/spaces/' + space_id,
                {'members': {name: {'role': 'write'} for name in passwords}}, 'PATCH')[0] == 200
            for path in ['/.ssh-mcp/login', '/%2essh-mcp/rpc', '/./.ssh-mcp/identity']:
                assert request(path, {})[0] == 404
            report['checks']['public_ingress_blocks_private_authentication'] = True

            for filename in ['host', 'shared']:
                subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(work / filename)], check=True)
            bridge_command = shlex.join([sys.executable, '-I', '-B', str(ROOT / 'ssh_mcp/bridge.py'), '--config', str(bridge_config)])
            authorized = work / 'authorized_keys'
            authorized.write_text('restrict,command="' + bridge_command.replace('"', '\\"') + '" ' + (work / 'shared.pub').read_text())
            authorized.chmod(0o600)
            sshd_config = work / 'sshd_config'
            sshd_config.write_text('\n'.join(['ListenAddress 127.0.0.1', 'Port ' + str(ssh_port),
                'HostKey ' + str(work / 'host'), 'PidFile ' + str(work / 'sshd.pid'),
                'AuthorizedKeysFile ' + str(authorized), 'PasswordAuthentication no',
                'KbdInteractiveAuthentication no', 'UsePAM no', 'StrictModes no',
                'AllowUsers ' + getpass.getuser(), 'LogLevel ERROR']) + '\n')
            start(['/usr/sbin/sshd', '-D', '-e', '-f', sshd_config])
            known = work / 'known_hosts'
            known.write_text('[127.0.0.1]:' + str(ssh_port) + ' ' + (work / 'host.pub').read_text())
            ssh_config = work / 'ssh_config'
            ssh_config.write_text('\n'.join(['Host synthetic-secondbrain', ' HostName 127.0.0.1',
                ' Port ' + str(ssh_port), ' User ' + getpass.getuser(), ' IdentityFile ' + str(work / 'shared'),
                ' IdentitiesOnly yes', ' UserKnownHostsFile ' + str(known)]) + '\n')
            # No scans: wait for the local sshd's bind, using its own /proc fd.
            for unused in range(100):
                assert processes[-1].poll() is None, 'Temporary sshd failed'
                if (work / 'sshd.pid').exists(): break
                time.sleep(.05)
            else: raise AssertionError('sshd readiness failed')
            original_command = client.ssh_command
            def command(profile):
                args = original_command(profile)
                return [args[0], '-F', str(ssh_config)] + args[1:]
            store = MemoryStore()
            profiles = {name: client.configure(work / name, 'test', 'synthetic-secondbrain',
                str(ROOT / 'ssh_mcp/bridge.py'), str(bridge_config)) for name in passwords}
            with patch.object(client, 'ssh_command', side_effect=command):
                for name in passwords:
                    assert client.login(profiles[name], store, name, passwords[name]) == name
                alice_token = store.get(client.credential_key(profiles['alice']))
                bob_token = store.get(client.credential_key(profiles['bob']))
                assert alice_token != bob_token
                users = (data / 'users.json').read_text()
                assert alice_token not in users and bob_token not in users
                report['checks']['one_shared_ssh_key_two_personal_hashed_tokens'] = True

                counter = 0
                def rpc(name, method, params=None):
                    nonlocal counter
                    counter += 1
                    # A fresh stdio process is intentional: credentials persist on the client,
                    # whereas JSON-RPC identity is established again on every SSH session.
                    packet = {'jsonrpc': '2.0', 'id': counter, 'method': method, 'params': params or {}}
                    output = io.BytesIO()
                    streams = SimpleNamespace(stdin=SimpleNamespace(buffer=io.BytesIO((json.dumps(packet)+'\n').encode())),
                        stdout=SimpleNamespace(buffer=output), stderr=log)
                    with patch.object(client, 'sys', streams):
                        assert client.mcp(profiles[name], store) == 0
                    replies = [json.loads(line) for line in output.getvalue().splitlines()]
                    assert len(replies) == 1 and replies[0]['id'] == counter
                    assert 'error' not in replies[0], replies[0]
                    return replies[0]['result']
                def call(name, tool, args): return rpc(name, 'tools/call', {'name': tool, 'arguments': args})
                for name in passwords:
                    assert rpc(name, 'initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                        'clientInfo': {'name': 'synthetic-cli', 'version': '1'}})['serverInfo']
                    assert rpc(name, 'tools/list')['tools']
                common = {'space': 'Synthetic runtime test'}
                help_text = json.dumps(call('alice', 'help', {}), ensure_ascii=False)
                assert 'vault-note-creation' in help_text
                for name in passwords:
                    page = name + ' note'
                    text = '# ' + name + '\n\nPERSONALMCPMARKER [[index]]\n'
                    assert not call(name, 'write', {**common, 'page': page, 'content': text}).get('isError')
                    saved = call(name, 'read', {**common, 'page': page})['structuredContent']
                    assert saved['revision']
                    assert not call(name, 'edit', {**common, 'page': page, 'ifRevision': saved['revision'],
                        'edits': [{'oldText': 'PERSONALMCPMARKER', 'newText': 'UPDATEDMCPMARKER'}]}).get('isError')
                    assert call(name, 'write', {**common, 'page': page, 'content': 'stale',
                        'ifRevision': saved['revision']}).get('isError')
                    assert not call(name, 'git_commit', {**common, 'message': name + ' checkpoint'}).get('isError')
                assert 'alice note' in json.dumps(call('bob', 'search', {**common, 'text': 'UPDATEDMCPMARKER', 'mode': 'words'}))
                assert call('bob', 'write', {**common, 'page': 'Library/Forbidden', 'content': 'forbidden'}).get('isError')
                assert call('bob', 'lua', {**common, 'code': 'return 1'}).get('isError')
                report['checks']['stdio_initialize_help_read_write_edit_search_stale_guard_and_rule_protection'] = True
                folder = settings.get('folder') or 'spaces/' + space_id
                space_path = Path(folder) if Path(folder).is_absolute() else data / folder
                history = subprocess.run(['git', '-C', str(space_path), 'log', '--format=%an'], check=True,
                    capture_output=True, text=True).stdout.splitlines()
                assert 'alice' in history and 'bob' in history
                messages = subprocess.run(['git', '-C', str(space_path), 'log', '--format=%B'], check=True,
                    capture_output=True, text=True).stdout
                for name in passwords:
                    assert 'SecondBrain-User: ' + name in messages
                    assert 'SecondBrain-Connection: SSH MCP test ' + profiles[name]['id'] in messages
                assert call('bob', 'git_commit', {**common, 'message': 'Impersonation\n\nSecondBrain-User: alice'}).get('isError')
                report['checks']['git_checkpoint_authors_are_server_authenticated_users'] = True
                report['checks']['checkpoint_records_authenticated_login_and_connection_without_caller_override'] = True
                # Personal credentials must not open general or administrative APIs.
                jar.clear()
                assert request('/.dashboard/api/admin/users', headers={'Authorization': 'Bearer ' + bob_token})[0] in [401, 403]
                assert request('/.mcp', {}, headers={'Authorization': 'Bearer ' + bob_token})[0] == 401
                report['checks']['personal_tokens_cannot_access_admin_or_public_oauth_mcp'] = True
                client.logout(profiles['alice'], store)
                assert not store.get(client.credential_key(profiles['alice']))
                try: client.exchange(profiles['alice'], {'bridge_version': 1, 'action': 'connect', 'token': alice_token})
                except client.ClientError: pass
                else: raise AssertionError('Revoked credential accepted')
                assert call('bob', 'read', {**common, 'page': 'alice note'})['structuredContent']
                report['checks']['revocation_is_personal_and_other_user_still_works'] = True
                client.logout(profiles['bob'], store)
            report['passed'] = True
        finally:
            for process in reversed(processes):
                if process.poll() is None: os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=20)
            log.close()
            if report['passed']:
                pids = set(re.findall(r'SERVER_GUARD: .* pid=(\d+)', (work / 'server.log').read_text()))
                lines = trace.read_text().splitlines()
                roots = len(pids)
                edges = []
                for line in lines:
                    parent, child = re.match(r'^(\d+)\s+', line), re.search(r'=\s*(\d+)\s*$', line)
                    if parent and child and re.search(r'\b(?:clone3?|fork|vfork)(?:\(| resumed>)', line):
                        edges.append((parent[1], child[1]))
                while True:
                    descendants = {child for parent, child in edges if parent in pids}
                    if descendants <= pids: break
                    pids |= descendants
                core = [line for line in lines if line.split() and line.split()[0] in pids]
                assert roots == 2 and core
                for line in core:
                    assert not any(word in line for word in ['connect(', 'SOCK_DGRAM', 'SOCK_RAW', 'sendmsg(', 'sendmmsg(']), line
                    if 'sendto(' in line:
                        args = line.split('sendto(', 1)[1].split(')', 1)[0].split(',')
                        assert len(args) == 6 and args[4].strip() in ['0', '0x0', 'NULL']
                report['checks']['traced_core_threads_and_git_descendants_no_outbound_attempts'] = True
                report['trace_coverage'] = {'core_processes': roots, 'tasks_including_threads_and_children': len(pids), 'connect_attempts': 0}
    (ROOT / 'evidence/ssh-runtime.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__': main()
