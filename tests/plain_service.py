#!/usr/bin/env python3
"""Real user-systemd services and in-place wrapper repair; no namespace tools.

Uses only unique test units and synthetic notes. The old archive is an explicit
local input; its namespace/capability unit files are never started.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=150)
    if result.returncode:
        raise RuntimeError(result.stdout[-1500:] + result.stderr[-1500:])
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--previous-archive', type=Path, required=True)
    parser.add_argument('--browser-python', type=Path, required=True)
    parser.add_argument('--browser', type=Path, required=True)
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix='plain-service-', dir=ROOT / 'evidence'))
    runtime = tempfile.TemporaryDirectory(prefix='sb-plain-', dir=os.environ['XDG_RUNTIME_DIR'])
    source = work / 'source'
    previous = work / 'previous'
    for destination in [source, previous]:
        destination.mkdir()
        with tarfile.open(args.previous_archive) as archive:
            for entry in archive.getmembers():
                path = Path(entry.name)
                assert entry.isfile() and not path.is_absolute() and '..' not in path.parts
            archive.extractall(destination)
    source = source / 'silverbullet-offline'
    previous = previous / 'silverbullet-offline'
    for old in source.rglob('*'):
        relative = old.relative_to(source)
        current = ROOT / relative
        if old.is_file() and current.is_file() and str(relative) != 'SHA256SUMS':
            shutil.copy2(current, old)
    shutil.copy2(ROOT / 'tools/repair.py', source / 'tools/repair.py')
    files = sorted(p for p in source.rglob('*') if p.is_file())
    (source / 'SHA256SUMS').write_text(''.join(digest(p) + '  ' + str(p.relative_to(source)) + '\n' for p in files if p.name != 'SHA256SUMS'))
    target = work / ('произвольный каталог % $ ' * 4)
    command = [sys.executable, '-I', '-B', source / 'tools/install.py']
    plan_path = work / 'install.plan.json'
    report = {'passed': False, 'checks': {}, 'scope': 'real VM user-systemd; no target-server acceptance'}
    units = {}
    old_units = {}
    try:
        run(command + ['plan', '--target', target, '--port', '3098', '--backend-port', '3097',
            '--public-url', 'http://127.0.0.1:3098', '--admin-user', 'plain-test-only',
            '--space-name', 'Synthetic runtime test', '--runtime-dir', runtime.name, '--output', plan_path])
        plan = json.loads(plan_path.read_text())
        units = plan['units']
        for text in units.values():
            for forbidden in ['PrivateNetwork=', 'PrivateUsers=', 'CapabilityBoundingSet=', 'AmbientCapabilities=']:
                assert forbidden not in text
        run(command + ['apply', '--plan', plan_path, '--sha256', digest(plan_path)])
        report['checks']['real_plan_apply_both_user_units_http_ready'] = True
        unit_dir = Path(plan['unit_directory'])
        main_unit = next(iter(units))
        pid = int(run(['systemctl', '--user', 'show', main_unit, '--property=MainPID', '--value']))
        assert os.readlink('/proc/%d/ns/net' % pid) == os.readlink('/proc/self/ns/net')
        assert os.readlink('/proc/%d/ns/user' % pid) == os.readlink('/proc/self/ns/user')
        children = Path('/proc/%d/task/%d/children' % (pid, pid)).read_text().split()
        core = [child for child in children if os.readlink('/proc/' + child + '/exe').endswith('/bin/silverbullet')]
        assert len(core) == 1
        status = Path('/proc/' + core[0] + '/status').read_text()
        assert 'NoNewPrivs:\t1' in status and 'Seccomp:\t2' in status
        assert 'CapEff:\t0000000000000000' in status
        report['checks']['same_host_namespaces_actual_core_seccomp_no_new_privs_zero_effective_caps'] = True
        browser = [args.browser_python, '-I', '-B', ROOT / 'tests/browser_workflow.py',
                   '--browser', args.browser, '--credentials', target / 'data/initial-credentials.json']
        before = work / 'browser-before.json'
        # Browser fixture saves its screenshot under report-parent/evidence.
        (work / 'evidence').mkdir()
        run(browser + ['--report', before])
        report['checks']['browser_mcp_git_before_repair'] = json.loads(before.read_text())['checks']
        run([sys.executable, '-I', '-B', target / 'tools/install.py', 'stop', '--target', target])
        account = {name: (target / 'data' / name).read_bytes() for name in ['initial-credentials.json', 'users.json', 'spaces.json', 'server.json']}
        notes = {str(p.relative_to(target / 'data/spaces')): p.read_bytes()
                 for p in (target / 'data/spaces').rglob('*') if p.is_file() and '.git' not in p.parts}
        # Reproduce the exact old installed wrapper/unit layout without starting it.
        (target / 'tools/repair.py').unlink()
        for path in previous.rglob('*'):
            if path.is_file():
                shutil.copy2(path, target / path.relative_to(previous))
        config = dict(plan['config'], namespace_required=True)
        config.pop('network_policy')
        (target / 'config/service.json').write_text(json.dumps(config))
        spec = importlib.util.spec_from_file_location('plain_installer', str(source / 'tools/install.py'))
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        name = main_unit.removesuffix('.service')
        old_units = installer.render_units(target, Path(sys.executable).resolve(), name, source=target)
        state = json.loads((target / '.install-state.json').read_text())
        state['units'] = {}
        for unit, text in old_units.items():
            (unit_dir / unit).write_text(text)
            state['units'][unit] = digest(unit_dir / unit)
        (target / '.install-state.json').write_text(json.dumps(state))
        run(['systemctl', '--user', 'daemon-reload'])
        repair = work / 'repair.plan.json'
        backup = work / 'wrapper-backup'
        run(command + ['repair-plan', '--target', target, '--backup', backup, '--output', repair])
        run(command + ['repair-apply', '--plan', repair, '--sha256', digest(repair)])
        for name, data in account.items():
            assert (target / 'data' / name).read_bytes() == data, name
        for name, data in notes.items():
            assert (target / 'data/spaces' / name).read_bytes() == data, name
        assert not (backup / 'payload/data').exists()
        assert json.loads((backup / 'repair.json').read_text())['phase'] == 'completed'
        report['checks']['real_known_release_repair_preserves_accounts_notes_and_backup'] = True
        after = work / 'browser-after.json'
        run(browser + ['--report', after, '--previous-report', before])
        report['checks']['browser_mcp_git_after_repair'] = json.loads(after.read_text())['checks']
        report['passed'] = True
    finally:
        for unit in reversed(list(units)):
            subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
        if units:
            for unit, text in units.items():
                path = Path(plan['unit_directory']) / unit
                if path.exists() and path.read_text() in [text, old_units.get(unit)]:
                    path.unlink()
            subprocess.run(['systemctl', '--user', 'daemon-reload'], capture_output=True)
        runtime.cleanup()
        (ROOT / 'evidence/plain-user-service.json').write_text(json.dumps(report, indent=2) + '\n')
        if report['passed']:
            shutil.rmtree(work)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
