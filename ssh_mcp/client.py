#!/usr/bin/env python3
"""Second Brain SSH MCP connector. Profiles contain no passwords or tokens."""
import argparse
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import threading
import uuid
import warnings

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('secondbrain_secret_store', ROOT / 'secret_store.py')
secrets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(secrets)


class ClientError(Exception):
    pass


def config_root():
    if os.name == 'nt':
        base = Path(os.environ.get('APPDATA', Path.home() / 'AppData/Roaming'))
        return base / 'SecondBrainMCP'
    if sys.platform == 'darwin':
        return Path.home() / 'Library/Application Support/SecondBrainMCP'
    return Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'secondbrain-mcp'


def profile_path(root, name):
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name):
        raise ClientError('Use a short alphanumeric profile name')
    return Path(root) / (name + '.json')


def load_profile(root, name):
    path = profile_path(root, name)
    if path.is_symlink():
        raise ClientError('Profile must not be a symlink')
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise ClientError('Profile is missing or invalid; run configure first') from None
    if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('id'), str) or not re.fullmatch('[a-f0-9]{32}', data['id']):
        raise ClientError('Invalid profile version or identifier')
    if set(data) != {'version', 'id', 'name', 'ssh_target', 'remote_bridge', 'remote_config'} or data.get('name') != name:
        raise ClientError('Invalid non-secret connector profile')
    validate_target(data['ssh_target'], data['remote_bridge'], data['remote_config'])
    return data


def validate_target(target, bridge, config):
    if not isinstance(target, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@:-]{0,254}', target):
        raise ClientError('Use a normal SSH alias or user@host; options are not accepted here')
    for value in [bridge, config]:
        if not isinstance(value, str) or not value.startswith('/') or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ClientError('Remote bridge and config must be absolute POSIX paths without control characters')


def configure(root, name, target, bridge, config):
    validate_target(target, bridge, config)
    path = profile_path(root, name)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise ClientError('Profile directory must not be a symlink')
    data = {'version': 1, 'id': uuid.uuid4().hex, 'name': name, 'ssh_target': target,
            'remote_bridge': bridge, 'remote_config': config}
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    return data


def credential_key(profile):
    # A changed target cannot reuse a saved secret for another server.
    encoded = json.dumps({k: profile[k] for k in ['id', 'ssh_target', 'remote_bridge', 'remote_config']},
                         sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def ssh_command(profile):
    executable = shutil.which('ssh')
    if not executable:
        raise ClientError('An installed OpenSSH client is required')
    remote = shlex.join(['python3', profile['remote_bridge'], '--config', profile['remote_config']])
    return [executable, '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ClearAllForwardings=yes', '-o', 'ForwardAgent=no', '-o', 'PermitLocalCommand=no',
            '-o', 'ConnectTimeout=20', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3',
            profile['ssh_target'], remote]


def exchange(profile, packet):
    try:
        result = subprocess.run(ssh_command(profile), input=(json.dumps(packet) + '\n').encode('utf-8'),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=150, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ClientError('SSH operation failed or timed out; no automatic retry was made') from None
    if result.returncode or len(result.stdout) > 32 * 1024:
        raise ClientError('SSH bridge rejected the operation; check access and server support. Do not repeat password attempts blindly')
    try:
        response = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise ClientError('SSH bridge did not return a valid authentication reply') from None
    if not isinstance(response, dict) or response.get('ok') is not True:
        raise ClientError('Operation was not confirmed by the server')
    return response


def login(profile, store, username, password):
    key = credential_key(profile)
    response = exchange(profile, {'bridge_version': 1, 'action': 'login', 'username': username,
        'password': password, 'label': 'SSH MCP ' + profile.get('name', 'client') + ' ' + profile['id']})
    token = response.get('token')
    if not isinstance(token, str) or not token.startswith('sbm_') or len(token) > 1024:
        raise ClientError('Server returned an invalid personal token')
    try:
        store.set(key, token)
        if store.get(key) != token:
            raise secrets.StoreError('Native store did not confirm the saved credential')
    except Exception:
        # Compensate a failed local save, but never claim revocation after a lost connection.
        try:
            exchange(profile, {'bridge_version': 1, 'action': 'logout', 'token': token})
        except Exception:
            raise ClientError('Credential was issued but could not be stored or revocation confirmed; ask the administrator to revoke its connection label') from None
        raise ClientError('Credential could not be saved; the issued credential was revoked') from None
    return response['username']


def logout(profile, store):
    key = credential_key(profile)
    token = store.get(key)
    if not token:
        return
    exchange(profile, {'bridge_version': 1, 'action': 'logout', 'token': token})
    store.delete(key)


def read_password():
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        try:
            return getpass.getpass('Second Brain password: ')
        except getpass.GetPassWarning:
            raise ClientError('A terminal with hidden password input is required for login') from None


def write_all(stream, data):
    remaining = memoryview(data)
    while remaining:
        written = stream.write(remaining)
        if not written:
            raise BrokenPipeError('SSH input closed')
        remaining = remaining[written:]
    stream.flush()


def mcp(profile, store):
    token = store.get(credential_key(profile))
    if not token:
        raise ClientError('No saved credential; run client.py login for this profile before starting the agent')
    process = subprocess.Popen(ssh_command(profile), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=sys.stderr, bufsize=0)
    try:
        write_all(process.stdin, (json.dumps({'bridge_version': 1, 'action': 'connect', 'token': token}) + '\n').encode('utf-8'))
        reply = process.stdout.readline(16 * 1024 + 1)
        try:
            identity = json.loads(reply)
        except (ValueError, UnicodeError):
            raise ClientError('Connection could not be authenticated; run login again or check server availability') from None
        if len(reply) > 16 * 1024 or not isinstance(identity, dict) or identity.get('ok') is not True:
            raise ClientError('Connection could not be authenticated')
        token = None

        def forward_input():
            try:
                while True:
                    chunk = sys.stdin.buffer.read1(65536)
                    if not chunk:
                        break
                    write_all(process.stdin, chunk)
            except (OSError, ValueError):
                pass
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass

        thread = threading.Thread(target=forward_input, daemon=True)
        thread.start()
        while True:
            chunk = process.stdout.read(65536)
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        return process.wait()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config-dir', type=Path, default=None, help='Non-secret connector profile directory')
    sub = parser.add_subparsers(dest='action', required=True)
    setup = sub.add_parser('configure')
    setup.add_argument('--profile', required=True)
    setup.add_argument('--ssh-target', required=True)
    setup.add_argument('--remote-bridge', required=True)
    setup.add_argument('--remote-config', required=True)
    for name in ['login', 'logout', 'status', 'mcp']:
        command = sub.add_parser(name)
        command.add_argument('--profile', required=True)
        if name == 'login':
            command.add_argument('--username', help='Login name only; password is read interactively')
    args = parser.parse_args()
    try:
        root = args.config_dir or config_root()
        if args.action == 'configure':
            configure(root, args.profile, args.ssh_target, args.remote_bridge, args.remote_config)
            print('Profile created. Confirm SSH host trust and run login before connecting the agent.')
            return 0
        profile = load_profile(root, args.profile)
        store = secrets.open_store()  # Fail before asking for a password if no safe storage exists.
        if args.action == 'login':
            store.get(credential_key(profile))  # Check store access before sending the password.
            username = args.username or input('Second Brain username: ')
            password = read_password()
            user = login(profile, store, username, password)
            password = None
            print('Signed in as ' + user + '. Credential saved in the OS store.')
        elif args.action == 'logout':
            logout(profile, store)
            print('Logout completed; saved credential removed.')
        elif args.action == 'status':
            present = bool(store.get(credential_key(profile)))
            print('Saved credential present (not a server connectivity check).' if present else 'No saved credential.')
        elif args.action == 'mcp':
            return mcp(profile, store)
        return 0
    except (ClientError, secrets.StoreError) as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, EOFError):
        print('Second Brain connector failed. Check the profile, native credential store, SSH access or run login again.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
