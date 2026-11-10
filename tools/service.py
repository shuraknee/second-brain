#!/usr/bin/env python3
"""Candidate supervisor; refuses pending config or missing process isolation.

The ingress/proxy service is finalized after the target probe and URL/port choice.
This process starts only the guarded native SilverBullet server, never downloads.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
children = []
owned_socket = None


def validate_guard_checks(proof):
    if not isinstance(proof, dict):
        raise ValueError('Invalid no-connect seccomp proof')
    expected = ['public_ipv4', 'private_ipv4_fixture', 'loopback', 'udp_dns', 'raw', 'packet']
    for checks in [proof, proof.get('child_inherits_filter', {})]:
        if not isinstance(checks, dict) or any(checks.get(key) != 'EPERM' for key in expected):
            raise ValueError('Incomplete no-connect seccomp proof')
        if checks.get('public_ipv6') not in ['EPERM', 'unavailable:EAFNOSUPPORT (socket creation)']:
            raise ValueError('Invalid IPv6 seccomp proof')


def process_policy_proof():
    result = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/egress_guard.py'), '--self-test'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError('No-connect seccomp self-test failed: ' + result.stderr.strip())
    proof = json.loads(result.stdout)
    validate_guard_checks(proof)
    return {'policy': 'seccomp-no-connect', 'namespace_required': False, 'guard': proof}


def main():
    global owned_socket
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if config.get('status') != 'target-approved' or (config.get('namespace_required') is not False or config.get('network_policy') != 'seccomp-no-connect'):
        raise RuntimeError('Target profile/config has not been approved; no server was started')
    if not isinstance(config.get('backend_port'), int) or not 1024 <= config['backend_port'] <= 65535:
        raise ValueError('Explicit backend_port in 1024..65535 required')
    if not isinstance(config.get('public_url'), str) or not config['public_url'].startswith(('http://', 'https://')):
        raise ValueError('Explicit public_url required')
    if not isinstance(config.get('admin_username'), str) or not config['admin_username']:
        raise ValueError('Explicit admin_username required')
    raw_data = config.get('data_directory')
    if not isinstance(raw_data, str) or not Path(raw_data).is_absolute():
        raise ValueError('Explicit absolute data_directory required')
    gateway = config.get('gateway_socket')
    if not isinstance(gateway, str) or not Path(gateway).is_absolute() or len(os.fsencode(gateway)) >= 104:
        raise ValueError('Explicit short absolute gateway_socket required')
    runtime = Path(config.get('runtime_directory', raw_data))
    if not runtime.is_absolute() or Path(gateway).parent != runtime:
        raise ValueError('gateway_socket must be directly inside runtime_directory')
    proof = process_policy_proof()
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    binary = ROOT / 'bin/silverbullet'
    if hashlib.sha256(binary.read_bytes()).hexdigest() != manifest['binary_sha256']:
        raise RuntimeError('Pinned SilverBullet hash mismatch')
    history_mode = config.get('history_mode', 'managed')
    if history_mode not in ['managed', 'unmanaged', 'disabled']:
        raise ValueError('Invalid history_mode')
    if history_mode != 'disabled':
        checked_git = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/git_support.py')],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if checked_git.returncode:
            raise RuntimeError(checked_git.stderr.strip())
    os.umask(0o077)
    data = Path(raw_data)
    data.mkdir(parents=True, exist_ok=True)
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = runtime.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError('runtime_directory must be owned by this user, mode 0700')
    if Path(gateway).exists() or Path(gateway).is_symlink():
        raise RuntimeError('Existing gateway socket/path; inspect owner before cleanup')
    # Lock the owned data directory, never another service or port.
    import fcntl
    lock = open(str(data / '.supply-service.lock'), 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    audit = data / 'audit'
    audit.mkdir(exist_ok=True)
    (audit / 'network-policy.json').write_text(json.dumps(proof, indent=2))
    # Explicit server feature policy; no proxy/cloud/environment inheritance.
    env = {'PATH': os.defpath, 'HOME': str(data), 'TMPDIR': str(data),
           'LANG': 'C.UTF-8', 'RUST_LOG': 'info', 'SB_RUNTIME_API': '0',
           'SB_SHELL_BACKEND': 'off', 'SB_HOSTNAME': '127.0.0.1',
           'SB_PORT': str(config['backend_port'])}
    def command(arguments):
        return [sys.executable, '-I', '-B', str(ROOT / 'tools/egress_guard.py'),
                '--', str(binary)] + arguments
    if not (data / 'users.json').exists():
        if (data / 'initial-credentials.json').exists():
            raise RuntimeError('Incomplete prior provisioning; inspect before retry')
        credentials = {'username': config['admin_username'], 'password': secrets.token_urlsafe(24)}
        secret_fd = os.open(str(data / 'initial-credentials.json'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(secret_fd, 'w') as stream:
            json.dump(credentials, stream)
        provisioning = subprocess.run(command(['setup', str(data), '--admin',
            credentials['username'] + ':' + credentials['password'],
            '--space', config.get('space_name', 'Second Brain'), '--at', '/']),
            env=env, check=False, close_fds=True)
        if provisioning.returncode:
            # Do not put the --admin argument/password into an exception log.
            raise RuntimeError('Provisioning failed; inspect retained data and audit before retry')
        spaces_path = data / 'spaces.json'
        spaces = json.loads(spaces_path.read_text())
        for space in spaces.values():
            space['revisions'] = history_mode
        spaces_path.write_text(json.dumps(spaces, ensure_ascii=False, indent=2) + '\n')
        (data / 'server.json').write_text(json.dumps({'primaryUrl': config['public_url'],
            'serverName': config.get('space_name', 'Second Brain'), 'runtimeApi': False,
            'mcp': True, 'search': {}}))
    else:
        server_config = json.loads((data / 'server.json').read_text())
        if server_config.get('primaryUrl') != config['public_url'] or server_config.get('runtimeApi') is not False or server_config.get('search', {}).get('model'):
            raise RuntimeError('Existing settings differ from the approved offline profile')
    process = subprocess.Popen(command([str(data)]), env=env, close_fds=True, start_new_session=True)
    children.append(process)
    for attempt in range(100):
        if process.poll() is not None:
            raise RuntimeError('Server exited before becoming ready')
        try:
            with socket.create_connection(('127.0.0.1', config['backend_port']), timeout=.2):
                break
        except OSError:
            time.sleep(.1)
    else:
        raise RuntimeError('Server readiness timeout')
    proxy = subprocess.Popen([sys.executable, '-I', '-B', str(ROOT / 'tools/proxy.py'),
                              '--config', str(args.config)], env=env, close_fds=True, start_new_session=True)
    children.append(proxy)
    for attempt in range(50):
        if proxy.poll() is not None:
            raise RuntimeError('Proxy exited before becoming ready')
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.connect(gateway)
            owned_socket = (Path(gateway), Path(gateway).stat().st_ino)
            break
        except OSError:
            time.sleep(.1)
    else:
        raise RuntimeError('Proxy readiness timeout')
    print('SUPPLY_READY: seccomp server and fixed Unix gateway', flush=True)
    while all(child.poll() is None for child in children):
        time.sleep(.2)
    raise RuntimeError('A required child exited')


def stop(*args):
    raise SystemExit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    sys.excepthook = sys.__excepthook__
    try:
        main()
    finally:
        for child in children:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        if owned_socket:
            path, inode = owned_socket
            if path.exists() and path.stat().st_ino == inode:
                path.unlink()
