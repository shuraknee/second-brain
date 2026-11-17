#!/usr/bin/env python3
"""Fixed-loopback stdio/HTTP bridge. Secrets arrive only in the SSH stdin preface."""
import argparse
import http.client
import json
import os
from pathlib import Path
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
                raise BridgeError('Credential rejected or expired; run client login again')
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    try:
        serve(Backend(load_config(args.config)))
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
