#!/usr/bin/env python3
"""Offline user-service installation: preflight -> explicit plan -> exact apply.

All project locations come from arguments, the plan, or the installed config.
No downloads, sudo, SSH configuration changes or automatic dependency install.
"""
import argparse
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import uuid

SOURCE = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def absolute(value):
    path = Path(value).expanduser()
    if not path.is_absolute() or any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
        raise ValueError('An absolute path without control characters is required')
    return path.resolve()


def call(args, check=True, timeout=30):
    p = subprocess.run([str(a) for a in args], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(p.stdout.strip() or 'Command failed: ' + str(args[0]))
    return p


def load_module(path):
    spec = importlib.util.spec_from_file_location('supply_module', str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def payload():
    result = {}
    for line in (SOURCE / 'SHA256SUMS').read_text().splitlines():
        expected, name = line.split('  ', 1)
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or name in result:
            raise RuntimeError('Invalid payload manifest')
        path = SOURCE / relative
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise RuntimeError('Payload checksum/path mismatch: ' + name)
        result[name] = expected
    required = ['bin/silverbullet', 'manifest.json', 'agent.md', 'tools/install.py',
                'tools/service.py', 'tools/proxy.py', 'tools/ingress.py',
                'tools/egress_guard.py', 'tools/git_support.py', 'templates/silverbullet.service.in',
                'templates/silverbullet-ingress.service.in']
    if any(name not in result for name in required):
        raise RuntimeError('Incomplete prepared payload; use the offline release archive')
    manifest = json.loads((SOURCE / 'manifest.json').read_text())
    if result['bin/silverbullet'] != manifest['binary_sha256']:
        raise RuntimeError('Pinned server hash mismatch')
    return result


def preflight():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or sys.version_info < (3, 9):
        raise RuntimeError('Linux x86_64 and Python >=3.9 required')
    for name in ['systemctl', 'systemd-run', 'systemd-analyze']:
        if not shutil.which(name):
            raise RuntimeError('Missing preinstalled tool: ' + name)
    manager = call(['systemctl', '--user', 'is-system-running'], check=False)
    if manager.stdout.strip() not in ['running', 'degraded']:
        raise RuntimeError('User manager is unavailable: ' + manager.stdout.strip())
    guard = call([sys.executable, '-I', '-B', SOURCE / 'tools/egress_guard.py', '--self-test'])
    unit = 'second-brain-probe-' + uuid.uuid4().hex + '.service'
    probe = call(['systemd-run', '--user', '--quiet', '--wait', '--pipe', '--collect',
                  '--unit', unit, '--property=PrivateUsers=yes', '--property=PrivateNetwork=yes',
                  '--property=NoNewPrivileges=yes', sys.executable, '-I', '-B',
                  SOURCE / 'tools/install.py', '_namespace-probe'], check=False)
    if probe.returncode:
        # Stop only the newly created unique diagnostic unit, if it survived.
        call(['systemctl', '--user', 'stop', unit], check=False)
        raise RuntimeError('User-service network isolation probe failed; no fallback:\n' + probe.stdout)
    try:
        proof = json.loads(probe.stdout)
        if proof['interfaces'] != ['lo']:
            raise ValueError('Unexpected interfaces')
    except (ValueError, KeyError):
        raise RuntimeError('Invalid network isolation proof: ' + probe.stdout)
    return {'python': sys.version.split()[0], 'namespace': proof,
            'guard': json.loads(guard.stdout)}


def check_port(host, port):
    ip = ipaddress.ip_address(host)
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise ValueError('An explicit port in 1024..65535 is required')
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.bind((str(ip), port))


def exec_argument(value):
    value = str(value)
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Control characters are not supported in unit arguments')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def render_units(target, python, name):
    units = {}
    for script, template, unit in [
        ('service.py', 'silverbullet.service.in', name + '.service'),
        ('ingress.py', 'silverbullet-ingress.service.in', name + '-ingress.service')]:
        command = [python, '-I', '-B', target / 'tools' / script, '--config', target / 'config/service.json']
        text = (SOURCE / 'templates' / template).read_text()
        text = text.replace('@EXEC_START@', ' '.join(exec_argument(a) for a in command))
        text = text.replace('@SERVER_UNIT@', name + '.service')
        units[unit] = text
    return units


def empty_target(target):
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise RuntimeError('Target is not empty; existing installation/data will not be overwritten')


def fresh_units(directory, units):
    for name in units:
        if (directory / name).exists() or (directory / name).is_symlink():
            raise RuntimeError('Unit already exists: ' + name)
        loaded = call(['systemctl', '--user', 'show', name, '--property=LoadState', '--value'], check=False)
        if loaded.stdout.strip() not in ['', 'not-found']:
            raise RuntimeError('Unit name is already managed: ' + name)


def make_plan(args):
    files = payload()
    target = absolute(args.target)
    empty_target(target)
    if target == SOURCE:
        raise ValueError('Source and installation target must differ')
    output = args.output.expanduser().resolve()
    if output == target or target in output.parents:
        raise ValueError('Plan output must be outside TARGET')
    check_port(args.listen_host, args.port)
    check_port('127.0.0.1', args.backend_port)
    if args.port == args.backend_port:
        raise ValueError('External and backend ports must differ')
    public = urlsplit(args.public_url)
    if public.scheme not in ['http', 'https'] or not public.hostname or public.username or public.password or public.path not in ['', '/'] or public.query or public.fragment or any(c.isspace() for c in args.public_url):
        raise ValueError('public-url must be an HTTP(S) origin without credentials/path/query')
    host = public.hostname.encode('idna').decode().lower()
    authority = '[' + host + ']' if ':' in host else host
    if public.port and public.port != (443 if public.scheme == 'https' else 80):
        authority += ':' + str(public.port)
    public_url = public.scheme + '://' + authority
    identity = hashlib.sha256(os.fsencode(target)).hexdigest()[:16]
    name = 'second-brain-' + identity
    runtime_base = args.runtime_dir or os.environ.get('XDG_RUNTIME_DIR')
    if not runtime_base:
        raise RuntimeError('XDG_RUNTIME_DIR unavailable; provide an explicit --runtime-dir')
    runtime = absolute(args.runtime_dir) if args.runtime_dir else absolute(runtime_base) / name
    if len(os.fsencode(runtime / 'http.sock')) >= 104:
        raise ValueError('Unix socket runtime path is too long; choose a shorter --runtime-dir. Target may remain long.')
    if runtime.exists() and (not runtime.is_dir() or runtime.stat().st_uid != os.getuid() or any(runtime.iterdir())):
        raise RuntimeError('Runtime directory must be unused and owned by this user')
    config_home = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
    if not config_home.is_absolute():
        raise ValueError('XDG_CONFIG_HOME must be absolute')
    unit_dir = config_home / 'systemd/user'
    python = Path(sys.executable).resolve()
    units = render_units(target, python, name)
    fresh_units(unit_dir, units)
    proof = preflight()
    history_mode = getattr(args, 'history_mode', 'managed')
    if history_mode not in ['managed', 'unmanaged', 'disabled']:
        raise ValueError('Invalid local history mode')
    if history_mode != 'disabled':
        proof['git'] = load_module(SOURCE / 'tools/git_support.py').require_git()
    config = {'status': 'target-approved', 'namespace_required': True,
        'public_url': public_url, 'backend_port': args.backend_port,
        'listen_host': args.listen_host, 'listen_port': args.port,
        'gateway_socket': str(runtime / 'http.sock'), 'runtime_directory': str(runtime),
        'admin_username': args.admin_user, 'space_name': args.space_name,
        'data_directory': str(target / 'data'), 'history_mode': history_mode}
    if not args.admin_user or any(c in args.admin_user for c in ':/\n\r'):
        raise ValueError('Invalid admin username')
    return {'schema_version': 1, 'source': str(SOURCE), 'target': str(target),
        'uid': os.getuid(), 'python': str(python), 'unit_directory': str(unit_dir),
        'units': units, 'config': config, 'payload': files, 'preflight': proof,
        'start': not args.no_start, 'enable': args.enable}


def owned(target):
    state = json.loads((target / '.install-state.json').read_text())
    if state['target'] != str(target) or state['uid'] != os.getuid():
        raise RuntimeError('Installation owner/target mismatch')
    for name, expected in state['units'].items():
        path = Path(state['unit_directory']) / name
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise RuntimeError('Unit ownership/content changed; no control action: ' + name)
        fragment = call(['systemctl', '--user', 'show', name, '--property=FragmentPath', '--value']).stdout.strip()
        if fragment != str(path):
            raise RuntimeError('Unexpected loaded unit path: ' + name)
    return state


def health(config):
    host = {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(config['listen_host'], config['listen_host'])
    connection = http.client.HTTPConnection(host, config['listen_port'], timeout=2)
    try:
        authority = urlsplit(config['public_url']).netloc
        connection.request('GET', '/.well-known/oauth-authorization-server', headers={'Host': authority})
        response = connection.getresponse()
        if response.status != 200 or "connect-src 'self'" not in response.getheader('Content-Security-Policy', ''):
            raise RuntimeError('Unexpected HTTP status or missing CSP')
        if json.loads(response.read())['issuer'] != config['public_url']:
            raise RuntimeError('Wrong application/issuer on the selected port')
        return True
    finally:
        connection.close()


def control(target, action):
    state = owned(target)
    names = list(state['units'])
    if action == 'stop':
        call(['systemctl', '--user', 'stop'] + list(reversed(names)))
    elif action == 'start':
        config = json.loads((target / 'config/service.json').read_text())
        check_port(config['listen_host'], config['listen_port'])
        preflight()
        if config.get('history_mode', 'managed') != 'disabled':
            load_module(target / 'tools/git_support.py').require_git()
        call(['systemctl', '--user', 'start', names[-1]])
        try:
            for attempt in range(100):
                try:
                    health(config)
                    print('START_OK: web/OAuth metadata and CSP verified')
                    return
                except (OSError, ValueError, RuntimeError, http.client.HTTPException):
                    time.sleep(.2)
            raise RuntimeError('HTTP readiness failed; inspect status/journal')
        except BaseException:
            call(['systemctl', '--user', 'stop'] + list(reversed(names)), check=False)
            raise
    elif action == 'status':
        for name in names:
            print(call(['systemctl', '--user', 'status', '--no-pager', name], check=False).stdout)
        config = json.loads((target / 'config/service.json').read_text())
        try:
            health(config)
            print('HTTP_OK (does not verify external HTTPS or authenticated note workflow)')
        except Exception as error:
            raise RuntimeError('HTTP_ERROR: ' + str(error))


def apply_plan(args):
    if digest(args.plan) != args.sha256:
        raise RuntimeError('Plan SHA256 mismatch')
    plan = json.loads(args.plan.read_text())
    if plan['source'] != str(SOURCE) or plan['uid'] != os.getuid() or plan['payload'] != payload():
        raise RuntimeError('Source, owner or payload changed; create a new plan')
    target = absolute(plan['target'])
    if str(target) != plan['target'] or plan.get('schema_version') != 1:
        raise RuntimeError('Target path or plan schema changed; create a new plan')
    identity = hashlib.sha256(os.fsencode(target)).hexdigest()[:16]
    expected = render_units(target, Path(sys.executable).resolve(), 'second-brain-' + identity)
    expected_directory = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) / 'systemd/user'
    if plan['units'] != expected or plan['python'] != str(Path(sys.executable).resolve()) or plan['unit_directory'] != str(expected_directory):
        raise RuntimeError('Interpreter, unit content or user directory changed; create a new plan')
    if plan['config']['data_directory'] != str(target / 'data') or plan['config'].get('namespace_required') is not True:
        raise RuntimeError('Unexpected data path or isolation policy in plan')
    if plan['config'].get('history_mode') not in ['managed', 'unmanaged', 'disabled']:
        raise RuntimeError('Unexpected local history mode in plan')
    if plan['config']['history_mode'] != 'disabled':
        load_module(SOURCE / 'tools/git_support.py').require_git()
    empty_target(target)
    directory = Path(plan['unit_directory'])
    fresh_units(directory, plan['units'])
    check_port(plan['config']['listen_host'], plan['config']['listen_port'])
    runtime = absolute(plan['config']['runtime_directory'])
    if runtime.exists() and (not runtime.is_dir() or any(runtime.iterdir()) or runtime.stat().st_uid != os.getuid()):
        raise RuntimeError('Runtime directory changed or is in use; create a new plan')
    preflight()
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.second-brain-stage-', dir=target.parent))
    try:
        for name in list(plan['payload']) + ['SHA256SUMS']:
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(SOURCE / name, path)
        config = stage / 'config/service.json'
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(json.dumps(plan['config'], ensure_ascii=False, indent=2) + '\n')
        config.chmod(0o600)
        for name, expected in plan['payload'].items():
            if digest(stage / name) != expected:
                raise RuntimeError('Copy verification failed: ' + name)
        # The generated config deliberately replaces the absent private config,
        # never a manifest-listed payload file.
        empty_target(target)
        if target.exists():
            target.rmdir()
        stage.rename(target)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    directory.mkdir(parents=True, exist_ok=True)
    state = {'target': str(target), 'uid': os.getuid(), 'unit_directory': str(directory), 'units': {}}
    for name, content in plan['units'].items():
        path = directory / name
        with path.open('x') as stream:
            stream.write(content)
        state['units'][name] = digest(path)
    state_file = target / '.install-state.json'
    state_file.write_text(json.dumps(state, indent=2) + '\n')
    state_file.chmod(0o600)
    call(['systemctl', '--user', 'daemon-reload'])
    call(['systemd-analyze', '--user', 'verify'] + [directory / name for name in plan['units']])
    if plan['enable']:
        call(['systemctl', '--user', 'enable', list(plan['units'])[-1]])
    if plan['start']:
        control(target, 'start')
    print('INSTALL_OK: ' + str(target))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('preflight')
    sub.add_parser('_namespace-probe')
    plan = sub.add_parser('plan')
    plan.add_argument('--target', required=True)
    plan.add_argument('--port', type=int, required=True)
    plan.add_argument('--backend-port', type=int, required=True)
    plan.add_argument('--public-url', required=True)
    plan.add_argument('--listen-host', default='127.0.0.1')
    plan.add_argument('--runtime-dir')
    plan.add_argument('--admin-user', required=True)
    plan.add_argument('--space-name', default='Second Brain')
    plan.add_argument('--history-mode', choices=['managed', 'unmanaged', 'disabled'], default='managed')
    plan.add_argument('--no-start', action='store_true')
    plan.add_argument('--enable', action='store_true')
    plan.add_argument('--output', type=Path, required=True)
    apply = sub.add_parser('apply')
    apply.add_argument('--plan', type=Path, required=True)
    apply.add_argument('--sha256', required=True)
    for operation in ['start', 'stop', 'status']:
        control_parser = sub.add_parser(operation)
        control_parser.add_argument('--target', required=True)
    args = parser.parse_args()
    if args.operation == '_namespace-probe':
        print(json.dumps(load_module(SOURCE / 'tools/service.py').network_proof()))
    elif args.operation == 'preflight':
        print(json.dumps(preflight(), indent=2))
    elif args.operation == 'plan':
        result = make_plan(args)
        with args.output.open('x') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        args.output.chmod(0o600)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        print('PLAN_SHA256=' + digest(args.output))
    elif args.operation == 'apply':
        apply_plan(args)
    else:
        control(absolute(args.target), args.operation)


if __name__ == '__main__':
    sys.excepthook = sys.__excepthook__
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
