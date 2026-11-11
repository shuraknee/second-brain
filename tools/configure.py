#!/usr/bin/env python3
"""Plan/apply a direct browser endpoint on an owned plain-service installation."""
import importlib.util
import hashlib
import ipaddress
import json
import os
import socket
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('endpoint_repair', str(ROOT / 'tools/repair.py'))
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)
install = repair.install


def inputs(target):
    for name in ['.install-state.json', 'config', 'config/service.json', 'data', 'data/server.json']:
        if (target / name).is_symlink():
            raise RuntimeError('Endpoint configuration refuses symlinked metadata/data directories')
    state = install.owned(target)
    install.payload(target)
    unit_dir = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) / 'systemd/user'
    name = 'second-brain-' + hashlib.sha256(os.fsencode(target)).hexdigest()[:16]
    units = install.render_units(target, Path(sys.executable).resolve(), name, source=target)
    if (state['unit_directory'] != str(unit_dir) or set(state['units']) != set(units)
            or any((unit_dir / unit).read_text() != text for unit, text in units.items())):
        raise RuntimeError('Unexpected managed units or interpreter; no services changed')
    config = json.loads((target / 'config/service.json').read_text())
    server = json.loads((target / 'data/server.json').read_text())
    if (config.get('status') != 'target-approved' or config.get('namespace_required') is not False
            or config.get('network_policy') != 'seccomp-no-connect'
            or config.get('data_directory') != str(target / 'data')
            or server.get('primaryUrl') != config.get('public_url')):
        raise RuntimeError('Expected a consistent plain-service installation; repair older profiles first')
    return state, config, server


def endpoint(config, host, port, public_url):
    host = str(ipaddress.ip_address(host))
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError('Explicit listen port in 1024..65535 required')
    if port == config['backend_port']:
        raise ValueError('Browser port and internal backend port must differ')
    return dict(config, listen_host=host, listen_port=port, public_url=install.canonical_public_url(public_url))


def make_plan(args):
    target = install.absolute(args.target)
    state, config, server = inputs(target)
    updated = endpoint(config, args.listen_host, args.port, args.public_url)
    # An existing listener can occupy the same port while planning. Binding
    # port zero still checks the requested local interface without stopping it.
    if updated['listen_port'] != config['listen_port']:
        install.check_port(updated['listen_host'], updated['listen_port'])
    else:
        family = socket.AF_INET6 if ipaddress.ip_address(updated['listen_host']).version == 6 else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.bind((updated['listen_host'], 0))
    backup = repair.backup_path(args.backup, target, state, config)
    output = Path(args.output).expanduser().resolve()
    if output == target or target in output.parents or output == backup or backup in output.parents:
        raise RuntimeError('Configuration plan must be outside target and backup')
    return {'schema_version': 1, 'operation': 'configure-browser-endpoint',
        'source': str(install.SOURCE), 'target': str(target), 'uid': os.getuid(),
        'python': str(Path(sys.executable).resolve()), 'backup': str(backup),
        'source_payload': install.payload(),
        'previous_config_sha256': install.digest(target / 'config/service.json'),
        'previous_server_sha256': install.digest(target / 'data/server.json'),
        'previous_state_sha256': install.digest(target / '.install-state.json'),
        'previous_sums_sha256': install.digest(target / 'SHA256SUMS'),
        'config': updated, 'server': dict(server, primaryUrl=updated['public_url']),
        'preflight': install.preflight(), 'start': not args.no_start}


def apply(args):
    if install.digest(args.plan) != args.sha256:
        raise RuntimeError('Configuration plan SHA256 mismatch')
    plan = json.loads(args.plan.read_text())
    if (plan.get('schema_version') != 1 or plan.get('operation') != 'configure-browser-endpoint'
            or plan['source'] != str(install.SOURCE) or plan['uid'] != os.getuid()
            or plan['python'] != str(Path(sys.executable).resolve())
            or plan.get('source_payload') != install.payload()):
        raise RuntimeError('Unexpected configuration plan source, owner or interpreter')
    target = install.absolute(plan['target'])
    state, config, server = inputs(target)
    expected = endpoint(config, plan['config']['listen_host'], plan['config']['listen_port'], plan['config']['public_url'])
    if plan['target'] != str(target) or plan['config'] != expected or plan['server'] != dict(server, primaryUrl=expected['public_url']):
        raise RuntimeError('Unexpected configuration changes; only browser endpoint may change')
    files = [('config/service.json', 'previous_config_sha256'), ('data/server.json', 'previous_server_sha256'),
             ('.install-state.json', 'previous_state_sha256'), ('SHA256SUMS', 'previous_sums_sha256')]
    for name, key in files:
        if install.digest(target / name) != plan[key]:
            raise RuntimeError('Existing configuration changed; create a new plan')
    backup = repair.backup_path(plan['backup'], target, state, config)
    install.preflight()
    backup.mkdir(mode=0o700)
    old_config = (target / 'config/service.json').read_bytes()
    old_server = (target / 'data/server.json').read_bytes()
    repair.replace(backup / 'service.json', old_config, 0o600)
    repair.replace(backup / 'server.json', old_server, 0o600)
    journal = {'phase': 'backed-up', 'target': str(target), 'notes_and_accounts_modified': False}
    def save():
        repair.replace(backup / 'configure.json', (json.dumps(journal, indent=2) + '\n').encode(), 0o600)
    save()
    files_written = False
    try:
        install.control(target, 'stop')
        for name, key in files:
            if install.digest(target / name) != plan[key]:
                raise RuntimeError('Configuration changed while stopping; no changes applied')
        install.check_port(expected['listen_host'], expected['listen_port'])
        install.check_port('127.0.0.1', expected['backend_port'])
        files_written = True
        repair.replace(target / 'config/service.json', (json.dumps(expected, ensure_ascii=False, indent=2) + '\n').encode(), 0o600)
        repair.replace(target / 'data/server.json', (json.dumps(plan['server'], ensure_ascii=False, indent=2) + '\n').encode(), 0o600)
        journal['phase'] = 'configured'
        save()
        if plan['start']:
            install.control(target, 'start')
        journal['phase'] = 'completed'
        save()
    except BaseException:
        # Preserve a consistent previous pair on failure. Do not restart it
        # automatically: the operator may need to resolve a port/firewall issue.
        try:
            install.control(target, 'stop')
        except Exception as error:
            journal['phase'] = 'failed; stop not confirmed; inspect before retry'
            save()
            raise RuntimeError('Cannot confirm stopped services; backup retained') from error
        if files_written:
            repair.replace(target / 'config/service.json', old_config, 0o600)
            repair.replace(target / 'data/server.json', old_server, 0o600)
        journal['phase'] = 'failed; previous configuration retained/restored; services stopped'
        save()
        raise
    print('CONFIGURE_OK: ' + expected['public_url'] + '; backup=' + str(backup))
