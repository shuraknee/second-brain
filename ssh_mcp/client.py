#!/usr/bin/env python3
"""Second Brain SSH MCP connector. Config-injected credentials; OS store is opt-in."""
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
import stat
import subprocess
import sys
import threading
import uuid
import warnings

ROOT = Path(__file__).resolve().parent
TOKEN_ENV = 'SECONDBRAIN_MCP_TOKEN'
PROFILE_ENV = 'SECONDBRAIN_MCP_PROFILE_KEY'


class ClientError(Exception):
    pass


def open_native_store():
    # This module is loaded only after an explicit --credential-source os-store.
    path = ROOT / 'secret_store.py'
    if not path.is_file():
        raise ClientError('Native storage requires secret_store.py; config and file modes do not')
    spec = importlib.util.spec_from_file_location('secondbrain_secret_store', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        backend = module.open_store()
    except module.StoreError as error:
        raise ClientError(str(error)) from None

    class NativeStore:
        def invoke(self, name, *args):
            try:
                return getattr(backend, name)(*args)
            except module.StoreError as error:
                raise ClientError(str(error)) from None
        def get(self, key): return self.invoke('get', key)
        def set(self, key, value): return self.invoke('set', key, value)
        def delete(self, key): return self.invoke('delete', key)
    return NativeStore()


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


def validate_token(token):
    if (not isinstance(token, str) or not token.startswith('sbm_') or len(token) > 1024
            or len(token) < 5 or any(ord(c) < 33 or ord(c) > 126 for c in token)):
        raise ClientError('A valid personal MCP token is required; ordinary API tokens are not accepted')
    return token


class EnvironmentStore:
    """A single profile-bound credential supplied by the agent's MCP config."""
    def __init__(self, profile, environment=None):
        environment = os.environ if environment is None else environment
        self.key = credential_key(profile)
        # Do not leave the secret in the connector's environment or forward it to SSH.
        self.token = environment.pop(TOKEN_ENV, None)
        self.binding = environment.pop(PROFILE_ENV, None)

    def get(self, key):
        if self.token is None and self.binding is None:
            return None
        if key != self.key or self.binding != self.key:
            raise ClientError('Credential/profile mismatch. Copy both exported environment values for this profile')
        return validate_token(self.token)

    def delete(self, key):
        if key != self.key:
            raise ClientError('Credential/profile mismatch')
        self.token = self.binding = None


def ssh_environment():
    return {k: v for k, v in os.environ.items() if k not in [TOKEN_ENV, PROFILE_ENV]}


def private_export_path(value):
    path = Path(value).expanduser()
    if not path.is_absolute() or any(ord(c) < 32 for c in str(path)):
        raise ClientError('Use an absolute path in a private directory for the token export')
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise ClientError('Token export paths must not contain symlinks')
    if os.name != 'nt':
        info = path.parent.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ClientError('Token export directory must be owned by you and not writable by others')
    return path


def file_store(profile, value):
    path = private_export_path(value)
    fd = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or (os.name != 'nt' and
                (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077)):
            raise ClientError('Token export must be a private regular file (0600 on POSIX)')
        raw = stream.read(16 * 1024 + 1)
    if len(raw) > 16 * 1024:
        raise ClientError('Invalid token export')
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ClientError('Invalid token export') from None
    if (not isinstance(data, dict) or data.get('format_version') != 1
            or data.get('profile') != profile['name'] or not isinstance(data.get('environment'), dict)
            or set(data['environment']) != {TOKEN_ENV, PROFILE_ENV}):
        raise ClientError('Invalid token export or profile')
    store = EnvironmentStore(profile, data['environment'])
    store.get(credential_key(profile))
    return store


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
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=150, check=False,
            env=ssh_environment())
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


def issue_credential(profile, username, password):
    response = exchange(profile, {'bridge_version': 1, 'action': 'login', 'username': username,
        'password': password, 'label': 'SSH MCP ' + profile.get('name', 'client') + ' ' + profile['id']})
    validate_token(response.get('token'))
    if not isinstance(response.get('username'), str) or not response['username']:
        raise ClientError('Server returned an invalid account identity')
    return response


def cancel_issued_credential(profile, token):
    try:
        exchange(profile, {'bridge_version': 1, 'action': 'logout', 'token': token})
    except Exception:
        raise ClientError('Credential was issued but could not be saved or revocation confirmed; ask the administrator to revoke its connection label') from None
    raise ClientError('Credential could not be saved; the issued credential was revoked') from None


def login(profile, store, username, password):
    key = credential_key(profile)
    response = issue_credential(profile, username, password)
    token = response['token']
    try:
        store.set(key, token)
        if store.get(key) != token:
            raise ClientError('Native store did not confirm the saved credential')
    except Exception:
        cancel_issued_credential(profile, token)
    return response['username']


def issue_token(profile, output, username, password):
    path = private_export_path(output)
    # Reserve the output before issuing/rotating credentials; never replace a config.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    response = None
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            response = issue_credential(profile, username, password)
            data = {'format_version': 1, 'username': response['username'], 'profile': profile['name'],
                'expires_in': response.get('expires_in'), 'environment': {
                    TOKEN_ENV: response['token'], PROFILE_ENV: credential_key(profile)}}
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        if response:
            cancel_issued_credential(profile, response['token'])
        raise
    return response['username']


def logout(profile, store):
    key = credential_key(profile)
    token = store.get(key)
    if not token:
        return False
    exchange(profile, {'bridge_version': 1, 'action': 'logout', 'token': token})
    store.delete(key)
    return True


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
        raise ClientError('No personal MCP token. Set both exported environment values in the MCP config, or use --token-file')
    process = subprocess.Popen(ssh_command(profile), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=sys.stderr, bufsize=0, env=ssh_environment())
    try:
        write_all(process.stdin, (json.dumps({'bridge_version': 1, 'action': 'connect', 'token': token}) + '\n').encode('utf-8'))
        reply = process.stdout.readline(16 * 1024 + 1)
        try:
            identity = json.loads(reply)
        except (ValueError, UnicodeError):
            raise ClientError('Connection could not be authenticated; run issue-token again or check server availability') from None
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config-dir', type=Path, default=None, help='Non-secret connector profile directory')
    sub = parser.add_subparsers(dest='action', required=True)
    setup = sub.add_parser('configure')
    setup.add_argument('--profile', required=True)
    setup.add_argument('--ssh-target', required=True)
    setup.add_argument('--remote-bridge', required=True)
    setup.add_argument('--remote-config', required=True)
    issue = sub.add_parser('issue-token', help='Issue a token into a private JSON export without an OS credential store')
    issue.add_argument('--profile', required=True)
    issue.add_argument('--username', help='Your existing Second Brain account, not a separate agent account')
    issue.add_argument('--output', type=Path, required=True, help='New private JSON export file; never overwritten')
    for name in ['login', 'logout', 'status', 'mcp']:
        command = sub.add_parser(name)
        command.add_argument('--profile', required=True)
        source = command.add_mutually_exclusive_group()
        source.add_argument('--credential-source', choices=['env', 'os-store'], default='env',
                            help='env (default); os-store explicitly enables native credential storage')
        if name != 'login':
            source.add_argument('--token-file', type=Path, help='Read a private export instead of environment or OS storage')
        if name == 'login':
            command.add_argument('--username', help='Login name only; password is read interactively')
    args = parser.parse_args(argv)
    try:
        root = args.config_dir or config_root()
        if args.action == 'configure':
            configure(root, args.profile, args.ssh_target, args.remote_bridge, args.remote_config)
            print('Profile created. Confirm SSH host trust and run issue-token before connecting the agent.')
            return 0
        profile = load_profile(root, args.profile)
        if args.action == 'issue-token':
            path = private_export_path(args.output)
            if path.exists():
                raise ClientError('Export already exists; choose a new output file')
            username = args.username or input('Second Brain username: ')
            password = read_password()
            issue_token(profile, path, username, password)
            password = None
            print('Personal MCP token exported. Merge its environment values into your private MCP config. No OS credential store was used.')
            return 0
        if args.action == 'login' and args.credential_source != 'os-store':
            raise ClientError('Use issue-token for config-based credentials. Native login requires --credential-source os-store')
        if getattr(args, 'token_file', None):
            store = file_store(profile, args.token_file)
        elif args.credential_source == 'os-store':
            store = open_native_store()
        else:
            store = EnvironmentStore(profile)
        if args.action == 'login':
            store.get(credential_key(profile))  # Check store access before sending the password.
            username = args.username or input('Second Brain username: ')
            password = read_password()
            user = login(profile, store, username, password)
            password = None
            print('Signed in as ' + user + '. Credential saved in the OS store.')
        elif args.action == 'logout':
            changed = logout(profile, store)
            if not changed:
                print('No personal MCP token was supplied; no server credential was revoked.')
            elif args.credential_source == 'os-store':
                print('Logout completed; saved credential removed.')
            else:
                print('Credential revoked. Remove its values from your agent config and any export file; those files were not edited.')
        elif args.action == 'status':
            present = bool(store.get(credential_key(profile)))
            print('Personal MCP token present (not a server connectivity check).' if present else 'No personal MCP token supplied. OS storage was not used unless explicitly selected.')
        elif args.action == 'mcp':
            return mcp(profile, store)
        return 0
    except ClientError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, EOFError):
        print('Second Brain connector failed. Check the profile, selected credential source, SSH access or run issue-token again.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
