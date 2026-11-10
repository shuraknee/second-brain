#!/usr/bin/env python3
"""Reviewed wrapper repair for known releases; notes/accounts stay in place."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('repair_installer', str(ROOT / 'tools/install.py'))
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)
SUPPORTED = {'offline-ipv4-only-20261110', 'offline-local-git-20261110'}


def inputs(target):
    for name in ['.install-state.json', 'config', 'config/service.json', 'SHA256SUMS']:
        if (target / name).is_symlink():
            raise RuntimeError('Repair refuses symlinked installation metadata')
    for entry in (target / 'SHA256SUMS').read_text().splitlines():
        _, name = entry.split('  ', 1)
        path = target / name
        if any(parent.is_symlink() for parent in path.parents if target in parent.parents):
            raise RuntimeError('Repair refuses symlinked payload directories')
    state = install.owned(target)
    directory = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) / 'systemd/user'
    if state['unit_directory'] != str(directory):
        raise RuntimeError('Unexpected existing user-unit directory')
    import hashlib
    unit_name = 'second-brain-' + hashlib.sha256(os.fsencode(target)).hexdigest()[:16]
    old_units = install.render_units(target, Path(sys.executable).resolve(), unit_name, source=target)
    if set(state['units']) != set(old_units):
        raise RuntimeError('Unexpected managed unit names')
    for unit, content in old_units.items():
        if (directory / unit).read_text() != content:
            raise RuntimeError('Installed units differ from the original templates')
    previous = install.payload(target)
    current = install.payload()
    manifest = json.loads((target / 'manifest.json').read_text())
    if manifest['supply_revision'] not in SUPPORTED:
        raise RuntimeError('Repair supports only the recorded local-Git/IPv4-only releases')
    if manifest['binary_sha256'] != json.loads((install.SOURCE / 'manifest.json').read_text())['binary_sha256']:
        raise RuntimeError('Repair must not replace the SilverBullet core or migrate data')
    if not set(previous).issubset(current):
        raise RuntimeError('Unexpected old payload files; manual review required')
    for name in set(current) - set(previous):
        if (target / name).exists() or (target / name).is_symlink():
            raise RuntimeError('New payload path already exists: ' + name)
    config = json.loads((target / 'config/service.json').read_text())
    if config['data_directory'] != str(target / 'data') or config.get('status') != 'target-approved':
        raise RuntimeError('Unexpected existing data path/profile')
    new_config = dict(config, namespace_required=False, network_policy='seccomp-no-connect')
    return state, previous, current, new_config, unit_name


def backup_path(value, target, state, config):
    path = install.absolute(value)
    for forbidden in [target, Path(state['unit_directory']), Path(config['runtime_directory'])]:
        if path == forbidden or forbidden in path.parents:
            raise RuntimeError('Repair backup must be outside target, unit and runtime directories')
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise RuntimeError('Repair backup must be a new directory with an existing parent')
    return path


def make_plan(args):
    target = install.absolute(args.target)
    if target == install.SOURCE:
        raise RuntimeError('Repair source must be separate from target')
    state, previous, current, config, name = inputs(target)
    backup = backup_path(args.backup, target, state, config)
    output = Path(args.output).expanduser().resolve()
    if output == target or target in output.parents or output == backup or backup in output.parents:
        raise RuntimeError('Repair plan must be outside target and backup')
    proof = install.preflight()
    if config.get('history_mode', 'managed') != 'disabled':
        install.load_module(install.SOURCE / 'tools/git_support.py').require_git()
    return {'schema_version': 1, 'operation': 'repair-plain-seccomp',
        'source': str(install.SOURCE), 'target': str(target), 'uid': os.getuid(),
        'python': str(Path(sys.executable).resolve()), 'backup': str(backup),
        'previous_payload': previous, 'payload': current,
        'previous_config_sha256': install.digest(target / 'config/service.json'),
        'previous_state_sha256': install.digest(target / '.install-state.json'),
        'previous_sums_sha256': install.digest(target / 'SHA256SUMS'),
        'config': config, 'unit_directory': state['unit_directory'],
        'units': install.render_units(target, Path(sys.executable).resolve(), name),
        'preflight': proof, 'start': not args.no_start}


def replace(path, data, mode):
    fd, name = tempfile.mkstemp(prefix='.second-brain-repair-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def apply(args):
    if install.digest(args.plan) != args.sha256:
        raise RuntimeError('Repair plan SHA256 mismatch')
    plan = json.loads(args.plan.read_text())
    if (plan.get('operation') != 'repair-plain-seccomp' or plan.get('schema_version') != 1
            or plan['source'] != str(install.SOURCE) or plan['uid'] != os.getuid()
            or plan['python'] != str(Path(sys.executable).resolve())):
        raise RuntimeError('Unexpected repair source, operation, owner or interpreter')
    target = install.absolute(plan['target'])
    state, previous, current, config, name = inputs(target)
    expected_units = install.render_units(target, Path(sys.executable).resolve(), name)
    if (plan['target'] != str(target) or plan['previous_payload'] != previous
            or plan['payload'] != current or plan['config'] != config
            or plan['units'] != expected_units or plan['unit_directory'] != state['unit_directory']):
        raise RuntimeError('Repair inputs changed; create a new plan')
    for file, key in [('config/service.json', 'previous_config_sha256'),
                      ('.install-state.json', 'previous_state_sha256'),
                      ('SHA256SUMS', 'previous_sums_sha256')]:
        if install.digest(target / file) != plan[key]:
            raise RuntimeError('Existing installation changed; create a new plan')
    backup = backup_path(plan['backup'], target, state, config)
    install.preflight()
    if config.get('history_mode', 'managed') != 'disabled':
        install.load_module(install.SOURCE / 'tools/git_support.py').require_git()
    backup.mkdir(mode=0o700)
    journal = {'phase': 'backing-up', 'target': str(target), 'data_modified': False}
    def save():
        replace(backup / 'repair.json', (json.dumps(journal, indent=2) + '\n').encode(), 0o600)
    save()
    try:
        # Synchronous stop affects only units validated against the ownership marker.
        install.control(target, 'stop')
        for host, port in [(config['listen_host'], config['listen_port']), ('127.0.0.1', config['backend_port'])]:
            install.check_port(host, port)
        for name in list(previous) + ['SHA256SUMS', 'config/service.json', '.install-state.json']:
            path = target / name
            destination = backup / 'payload' / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(path, destination)
            if install.digest(path) != install.digest(destination):
                raise RuntimeError('Repair backup checksum mismatch')
        for unit in state['units']:
            destination = backup / 'units' / unit
            destination.parent.mkdir(exist_ok=True, mode=0o700)
            shutil.copy2(Path(state['unit_directory']) / unit, destination)
        journal['phase'] = 'backup-verified'
        save()
        for name, expected in current.items():
            if previous.get(name) == expected:
                continue
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            mode = stat.S_IMODE(destination.stat().st_mode) if destination.exists() else 0o644
            replace(destination, (install.SOURCE / name).read_bytes(), mode)
        replace(target / 'SHA256SUMS', (install.SOURCE / 'SHA256SUMS').read_bytes(), 0o644)
        replace(target / 'config/service.json', (json.dumps(config, ensure_ascii=False, indent=2) + '\n').encode(), 0o600)
        new_state = dict(state, units={})
        for unit, content in expected_units.items():
            path = Path(state['unit_directory']) / unit
            replace(path, content.encode(), 0o644)
            new_state['units'][unit] = install.digest(path)
        replace(target / '.install-state.json', (json.dumps(new_state, indent=2) + '\n').encode(), 0o600)
        install.payload(target)
        journal['phase'] = 'files-updated'
        save()
        install.call(['systemctl', '--user', 'daemon-reload'])
        install.call(['systemd-analyze', '--user', 'verify'] + [Path(state['unit_directory']) / unit for unit in expected_units])
        # Stopped units can have been garbage-collected after daemon-reload;
        # reset-failed then reports "not loaded". Start/readiness remain strict.
        install.call(['systemctl', '--user', 'reset-failed'] + list(expected_units), check=False)
        if plan['start']:
            install.control(target, 'start')
        journal['phase'] = 'completed'
        save()
    except BaseException:
        journal['phase'] = 'failed; inspect backup before retry'
        save()
        raise
    print('REPAIR_OK: data and credentials preserved; backup=' + str(backup))
