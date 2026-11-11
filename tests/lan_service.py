#!/usr/bin/env python3
"""Configure a real owned loopback installation for direct non-loopback HTTP.

The server IP is read at test time; it is never written into public artifacts.
Browser/client and server run on the VM, connecting by its real interface IP.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(result.stdout[-1800:] + result.stderr[-1800:])
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--previous-archive', type=Path, required=True)
    parser.add_argument('--browser-python', type=Path, required=True)
    parser.add_argument('--browser', type=Path, required=True)
    args = parser.parse_args()
    addresses = json.loads(run(['ip', '-j', '-4', 'address', 'show', 'scope', 'global']))
    server_ip = next(item['local'] for interface in addresses for item in interface['addr_info']
                     if item['family'] == 'inet' and not ipaddress.ip_address(item['local']).is_loopback)
    work = Path(tempfile.mkdtemp(prefix='lan-service-', dir=ROOT / 'evidence'))
    runtime = tempfile.TemporaryDirectory(prefix='sb-lan-', dir=os.environ['XDG_RUNTIME_DIR'])
    old_source = work / 'old-source'
    old_source.mkdir()
    with tarfile.open(args.previous_archive) as archive:
        for entry in archive.getmembers():
            assert entry.isfile() and not Path(entry.name).is_absolute() and '..' not in Path(entry.name).parts
        archive.extractall(old_source)
    old_source = old_source / 'silverbullet-offline'
    source = work / 'new-source'
    shutil.copytree(old_source, source)
    for path in source.rglob('*'):
        current = ROOT / path.relative_to(source)
        if path.is_file() and current.is_file() and path != source / 'SHA256SUMS':
            shutil.copy2(current, path)
    shutil.copy2(ROOT / 'tools/configure.py', source / 'tools/configure.py')
    files = sorted(p for p in source.rglob('*') if p.is_file() and p != source / 'SHA256SUMS')
    (source / 'SHA256SUMS').write_text(''.join(digest(p) + '  ' + str(p.relative_to(source)) + '\n' for p in files))
    target = work / ('заметки путь % $ ' * 5)
    old_command = [sys.executable, '-I', '-B', old_source / 'tools/install.py']
    command = [sys.executable, '-I', '-B', source / 'tools/install.py']
    report = {'passed': False, 'checks': {}, 'scope': 'VM interface IP; no corporate-host acceptance'}
    units = {}
    try:
        plan_path = work / 'install.plan.json'
        run(old_command + ['plan', '--target', target, '--port', 3098, '--backend-port', 3097,
            '--public-url', 'http://127.0.0.1:3098', '--admin-user', 'lan-test-only',
            '--space-name', 'Synthetic runtime test', '--runtime-dir', runtime.name, '--output', plan_path])
        plan = json.loads(plan_path.read_text())
        units = plan['units']
        run(old_command + ['apply', '--plan', plan_path, '--sha256', digest(plan_path)])
        accounts = {name: (target / name).read_bytes() for name in ['data/users.json', 'data/initial-credentials.json', 'data/spaces.json']}
        wrapper_plan = work / 'repair.plan.json'
        run(command + ['repair-plan', '--target', target, '--backup', work / 'wrapper-backup', '--output', wrapper_plan])
        run(command + ['repair-apply', '--plan', wrapper_plan, '--sha256', digest(wrapper_plan)])
        for name, data in accounts.items():
            assert (target / name).read_bytes() == data, name
        preserved = {name: (target / name).read_bytes() for name in ['data/users.json', 'data/initial-credentials.json',
            'data/spaces.json', '.install-state.json', 'SHA256SUMS', 'manifest.json']}
        configure_plan = work / 'configure.plan.json'
        origin = 'http://' + server_ip + ':3098'
        run(command + ['configure-plan', '--target', target, '--listen-host', server_ip, '--port', 3098,
            '--public-url', origin, '--backup', work / 'endpoint-backup', '--output', configure_plan])
        run(command + ['configure-apply', '--plan', configure_plan, '--sha256', digest(configure_plan)])
        for name, data in preserved.items():
            assert (target / name).read_bytes() == data, name
        report['checks']['real_reconfigure_old_plain_installation_preserves_accounts_payload_units'] = True
        for name in units:
            assert (Path(plan['unit_directory']) / name).read_text() == units[name]
        try:
            connection = socket.create_connection((server_ip, 3097), timeout=2)
        except OSError:
            pass
        else:
            connection.close()
            raise AssertionError('Backend was exposed on the external interface')
        report['checks']['backend_remains_loopback_only'] = True
        browser = [args.browser_python, '-I', '-B', ROOT / 'tests/browser_workflow.py',
            '--browser', args.browser, '--credentials', target / 'data/initial-credentials.json',
            '--base-url', origin, '--oauth-callback', 'http://127.0.0.1:44559/offline-oauth-callback']
        (work / 'evidence').mkdir()
        before = work / 'browser-before.json'
        run(browser + ['--report', before])
        first = json.loads(before.read_text())
        assert first['passed'] and first['browser_context'] == {'secure': False, 'serviceWorker': False}
        report['checks']['direct_ip_http_browser_mcp_git'] = first['checks']
        report['checks']['real_nonsecure_browser_context_without_origin_bypass_flags'] = True
        installed = [sys.executable, '-I', '-B', target / 'tools/install.py']
        run(installed + ['stop', '--target', target])
        run(installed + ['start', '--target', target])
        after = work / 'browser-after.json'
        run(browser + ['--report', after, '--previous-report', before])
        second = json.loads(after.read_text())
        assert second['passed']
        report['checks']['direct_ip_after_restart'] = second['checks']
        report['passed'] = True
    finally:
        for unit in reversed(list(units)):
            subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
        if units:
            for unit, content in units.items():
                path = Path(plan['unit_directory']) / unit
                if path.exists() and path.read_text() == content:
                    path.unlink()
            subprocess.run(['systemctl', '--user', 'daemon-reload'], capture_output=True)
        runtime.cleanup()
        (ROOT / 'evidence/lan-user-service.json').write_text(json.dumps(report, indent=2) + '\n')
        if report['passed']:
            shutil.rmtree(work)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
