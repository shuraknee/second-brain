#!/usr/bin/env python3
"""Fixed-loopback stdio/HTTP bridge. Secrets arrive only in the SSH stdin preface."""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys

LIMIT = 16 * 1024 * 1024
PREFIX = '/.ssh-mcp/'


class BridgeError(Exception):
    pass


def read_packet(stream, limit):
    raw = stream.readline(limit + 1)
    if not raw:
        return None
    if len(raw) > limit or not raw.endswith(b'\n'):
        raise BridgeError('Message exceeds the allowed size or is incomplete')
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise BridgeError('Invalid JSON message') from None
    if not isinstance(value, dict):
        raise BridgeError('A JSON object is required')
    return value


def write_packet(value, stream=None):
    stream = stream or sys.stdout.buffer
    stream.write(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8') + b'\n')
    stream.flush()


def sse_messages(body):
    data = []
    for line in body.decode('utf-8').splitlines() + ['']:
        if not line:
            if data:
                yield json.loads('\n'.join(data))
                data = []
        elif line.startswith('data:'):
            data.append(line[5:].lstrip(' '))


class Backend:
    def __init__(self, port):
        self.port = port
        self.session = None

    def post(self, operation, payload, token=None):
        if operation not in ['login', 'identity', 'logout', 'rpc']:
            raise BridgeError('Operation is not permitted')
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=120)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
        if token:
            if not isinstance(token, str) or len(token) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in token):
                raise BridgeError('Invalid credential format')
            headers['Authorization'] = 'Bearer ' + token
        if self.session and operation == 'rpc':
            headers['Mcp-Session-Id'] = self.session
        if operation == 'rpc':
            headers['MCP-Protocol-Version'] = '2025-11-25'
        try:
            connection.request('POST', PREFIX + operation, json.dumps(payload).encode('utf-8'), headers)
            response = connection.getresponse()
            if response.status == 401:
                raise BridgeError('Credential rejected or expired; renew the personal token with client issue-token')
            if response.status == 404:
                raise BridgeError('Private MCP service is disabled or this server version does not support it')
            if response.status == 429:
                raise BridgeError('Sign-in temporarily locked; do not repeat attempts')
            if response.status < 200 or response.status >= 300:
                raise BridgeError('Server rejected the operation (HTTP %d)' % response.status)
            session = response.getheader('Mcp-Session-Id')
            if session:
                if len(session) > 256 or any(ord(c) < 33 or ord(c) > 126 for c in session):
                    raise BridgeError('Invalid server session identifier')
                self.session = session
            body = response.read(LIMIT + 1)
            if len(body) > LIMIT:
                raise BridgeError('Server reply exceeds allowed size')
            if not body or response.status in [202, 204]:
                return []
            if response.getheader('Content-Type', '').split(';')[0].strip() == 'text/event-stream':
                return list(sse_messages(body))
            return [json.loads(body)]
        except (OSError, http.client.HTTPException, ValueError, UnicodeError):
            # Never echo request/reply bodies, passwords or bearer credentials.
            raise BridgeError('Backend request failed; outcome may be unknown. No automatic retry was made') from None
        finally:
            connection.close()


def load_config(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise BridgeError('Use a regular operator-owned bridge config')
    info = path.stat()
    if info.st_uid not in [0, os.getuid()] or stat.S_IMODE(info.st_mode) & 0o022:
        raise BridgeError('Bridge config must not be writable by other users')
    data = json.loads(path.read_text(encoding='utf-8'))
    port = data.get('backend_port')
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise BridgeError('Configure one explicit backend_port in 1024..65535')
    if set(data) != {'backend_port'}:
        raise BridgeError('Bridge config supports only backend_port; no arbitrary target URLs')
    return port


def serve(backend, incoming=None, outgoing=None):
    incoming = incoming or sys.stdin.buffer
    outgoing = outgoing or sys.stdout.buffer
    first = read_packet(incoming, 16 * 1024)
    if not first or first.get('bridge_version') != 1:
        raise BridgeError('Missing bridge authentication preface')
    action = first.get('action')
    if action == 'login':
        if set(first) != {'bridge_version', 'action', 'username', 'password', 'label'}:
            raise BridgeError('Invalid login preface')
        payload = {k: first[k] for k in ['username', 'password', 'label']}
        result = backend.post('login', payload)
        first.clear()
        if len(result) != 1 or not result[0].get('token'):
            raise BridgeError('Invalid login reply')
        write_packet(result[0], outgoing)
        return
    if action not in ['connect', 'logout'] or set(first) != {'bridge_version', 'action', 'token'}:
        raise BridgeError('Invalid connection preface')
    token = first['token']
    first.clear()
    identity = backend.post('identity', {}, token)
    if len(identity) != 1 or identity[0].get('ok') is not True:
        raise BridgeError('Identity could not be verified')
    if action == 'logout':
        result = backend.post('logout', {}, token)
        write_packet(result[0], outgoing)
        return
    write_packet(identity[0], outgoing)  # Consumed by the local connector, never by the model.
    while True:
        packet = read_packet(incoming, LIMIT)
        if packet is None:
            return
        for message in backend.post('rpc', packet, token):
            write_packet(message, outgoing)


def prepare(target):
    bridge = Path(__file__).resolve()
    directory = target.resolve() / 'config'
    service = json.loads((directory / 'service.json').read_bytes())
    port = service['backend_port']
    if type(port) is not int or not 1024 <= port <= 65535:
        raise BridgeError('Invalid backend_port in the service configuration')
    config = directory / 'ssh-mcp.json'
    if not config.exists():
        with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as f:
            json.dump({'backend_port': port}, f)
            f.write('\n')
    if load_config(config) != port:
        raise BridgeError('Existing ssh-mcp.json specifies a different backend port')
    command = shlex.join([sys.executable, '-I', '-B', str(bridge), '--config', str(config)])
    if any(ord(c) < 32 for c in command):
        raise BridgeError('Unsupported control character in a server path')
    quoted = command.replace(chr(92), chr(92) * 2).replace('"', chr(92) + '"')
    print('restrict,command="' + quoted + '" PUBLIC_KEY')


def release_file(name):
    path = Path(__file__).resolve().with_name(name)
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o022:
        raise BridgeError('Expected an operator-controlled release file: ' + name)
    return path.read_bytes()


def install_commands(alias, installer_hash, client_hash):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,254}', alias):
        raise BridgeError('Specify a single SSH host alias or user@host')
    # Use Python for byte-exact transfer on Windows PowerShell 5 as well as POSIX.
    # Only fixed ASCII source inside the outer quotes; all variable data is argv.
    download = (
        "import hashlib,pathlib,subprocess as s,sys,tempfile; "
        "host,installer,client=sys.argv[1:4]; "
        "data=s.check_output(['ssh','-nT','-oBatchMode=yes','-oStrictHostKeyChecking=yes',"
        "'-oClearAllForwardings=yes','-oForwardAgent=no','-oPermitLocalCommand=no',"
        "'-oConnectTimeout=20',host,'secondbrain-installer-v1'],timeout=45); "
        "hashlib.sha256(data).hexdigest()==installer or sys.exit('Installer SHA256 mismatch'); "
        "d=tempfile.TemporaryDirectory(); p=pathlib.Path(d.name)/'connect.py'; p.write_bytes(data); "
        "rc=s.call([sys.executable,'-I','-B',str(p),host,'--sha256',client,*sys.argv[4:]]); "
        "d.cleanup(); sys.exit(rc)"
    )
    arguments = f'-I -B -c "{download}" {alias} {installer_hash} {client_hash}'
    return 'python ' + arguments, 'python3 ' + arguments


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', type=Path, metavar='TARGET', help='Prepare the installed bridge and print its forced command')
    mode.add_argument('--config', type=Path)
    parser.add_argument('--ssh-alias', metavar='HOST', help='With --prepare, print commands for employees')
    args = parser.parse_args()
    if args.ssh_alias is not None and args.prepare is None:
        parser.error('--ssh-alias requires --prepare')
    try:
        if args.prepare:
            prepare(args.prepare)
            if args.ssh_alias is not None:
                hashes = [hashlib.sha256(release_file(name)).hexdigest() for name in ('connect.py', 'client.py')]
                windows, unix = install_commands(args.ssh_alias, *hashes)
                print('Windows (PowerShell)', windows, 'macOS / Linux', unix, sep='\n')
            return 0
        port = load_config(args.config)
        request = os.environ.get('SSH_ORIGINAL_COMMAND')
        if request == 'secondbrain-installer-v1':
            sys.stdout.buffer.write(release_file('connect.py'))
            return 0
        if request == 'secondbrain-client-v1':
            bridge = Path(__file__).resolve()
            code = release_file('client.py')
            write_packet({'format': 1, 'bridge': str(bridge), 'config': str(args.config.resolve()),
                          'sha256': hashlib.sha256(code).hexdigest(),
                          'client': base64.b64encode(code).decode('ascii')})
            return 0
        serve(Backend(port))
        return 0
    except BridgeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, AttributeError):
        # A protocol error is not an invitation to forward private diagnostics.
        print('Second Brain bridge failed. Check server configuration, account access or sign in again. No request was retried.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
