#!/usr/bin/env python3
"""Candidate integration check; the corporate server is never contacted.

Host mode creates an isolated child with the already available VM facilities.
Test-host namespace facilities are NOT a dependency of the supply.
"""
import json
import argparse
import importlib.util
import os
import re
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TRACE = '--trace' in sys.argv


def inside():
    work = Path(sys.argv[sys.argv.index('--work') + 1])
    ipv6_simulated = '--simulate-no-ipv6' in sys.argv
    if ipv6_simulated:
        spec = importlib.util.spec_from_file_location('ipv6_fixture', str(ROOT / 'tests/test_ipv6.py'))
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        fixture.simulate_no_ipv6()
    guard = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/egress_guard.py'), '--self-test'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    guard_checks = json.loads(guard.stdout)
    if ipv6_simulated:
        for checks in [guard_checks, guard_checks['child_inherits_filter']]:
            assert checks['public_ipv6'] == 'unavailable:EAFNOSUPPORT (socket creation)'
            assert checks['public_ipv4'] == checks['loopback'] == 'EPERM'
    deployed = work / 'произвольный каталог % $ с пробелами' / 'длинный путь установки'
    for name in ['tools', 'templates']:
        shutil.copytree(ROOT / name, deployed / name, ignore=shutil.ignore_patterns('__pycache__'))
    (deployed / 'bin').mkdir()
    shutil.copy2(ROOT / 'bin/silverbullet', deployed / 'bin/silverbullet')
    shutil.copy2(ROOT / 'manifest.json', deployed / 'manifest.json')
    data = deployed / 'data'
    runtime = work / 'r'
    config = work / 'runtime-test.json'
    settings = {'status': 'target-approved', 'namespace_required': True,
        'public_url': 'http://127.0.0.1:3098', 'backend_port': 3097,
        'listen_host': '127.0.0.1', 'listen_port': 3098,
        'gateway_socket': str(runtime / 'g.sock'), 'runtime_directory': str(runtime), 'admin_username': 'test-only',
        'space_name': 'Synthetic runtime test', 'data_directory': str(data)}
    config.write_text(json.dumps(settings))
    log = open(str(work / 'service.log'), 'w')
    def start():
        command = [sys.executable, '-I', '-B', str(deployed / 'tools/service.py'), '--config', str(config)]
        if TRACE:
            command = ['strace', '-f', '-qq', '-s', '128', '-e',
                       'trace=connect,socket,sendto,sendmsg,sendmmsg,clone,clone3,fork,vfork', '-e',
                       'raw=sendto,sendmsg,sendmmsg', '-o', str(work / ('network-%d.trace' % time.time_ns()))] + command
        return subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
    def stop(process):
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=15)
    def ready(process):
        for attempt in range(150):
            if process.poll() is not None:
                raise AssertionError((work / 'service.log').read_text())
            if (runtime / 'g.sock').exists():
                return
            time.sleep(.1)
        raise AssertionError('Readiness timeout')
    server = start()
    ingress = None
    result = {'python': sys.version.split()[0], 'checks': {'egress_guard': guard_checks}, 'passed': False,
              'binary_sha256': json.loads((deployed / 'manifest.json').read_text())['binary_sha256'],
              'ipv6_kernel_errno_simulated': ipv6_simulated,
              'scope': 'development-host runtime test; not target-host acceptance'}
    try:
        if TRACE:
            for operation in ['upgrade', 'upgrade-edge']:
                trace_path = work / (operation + '.trace')
                outcome = subprocess.run(['strace', '-f', '-qq', '-e', 'trace=network', '-o', str(trace_path),
                                          str(deployed / 'bin/silverbullet'), operation],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                assert outcome.returncode != 0 and 'Offline build' in outcome.stderr
                trace = trace_path.read_text()
                assert 'connect(' not in trace and 'SOCK_DGRAM' not in trace and 'SOCK_RAW' not in trace
            result['checks']['upgrade_commands_fail_without_network_calls'] = True
        ready(server)
        if not TRACE:
            assert shutil.which('strace') is None
            result['checks']['runtime_without_strace_available'] = True
        guard_pids = re.findall(r'SERVER_GUARD: .* pid=(\d+)', (work / 'service.log').read_text())
        assert len(guard_pids) == 2
        status = Path('/proc/' + guard_pids[-1] + '/status').read_text()
        assert re.search(r'^NoNewPrivs:\s+1$', status, re.M)
        assert re.search(r'^Seccomp:\s+2$', status, re.M)
        result['checks']['actual_server_seccomp_and_no_new_privs'] = True
        secret = json.loads((data / 'initial-credentials.json').read_text())
        assert secret['username'] == 'test-only'
        assert (data / 'initial-credentials.json').stat().st_mode & 0o777 == 0o600
        result['checks']['guarded_fresh_provision_in_namespace'] = True
        ingress = subprocess.Popen([sys.executable, '-I', '-B', str(deployed / 'tools/ingress.py'),
                                    '--config', str(config)], stdout=log, stderr=log)
        base = settings['public_url']
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for attempt in range(100):
            try:
                response = opener.open(base + '/.well-known/oauth-authorization-server', timeout=1)
                metadata = json.load(response)
                break
            except urllib.error.URLError:
                if ingress.poll() is not None:
                    raise AssertionError('Ingress exited')
                time.sleep(.1)
        else:
            raise AssertionError('Ingress readiness timeout')
        assert metadata['issuer'] == base, metadata
        response = opener.open(base + '/.login', timeout=5)
        assert "connect-src 'self'" in response.headers['Content-Security-Policy']
        assert b'<html' in response.read().lower()
        result['checks']['web_via_unix_gateway_and_csp'] = True
        request = urllib.request.Request(base + '/.auth/register',
            data=json.dumps({'client_name': 'offline-candidate-check',
                 'redirect_uris': [base + '/callback'], 'token_endpoint_auth_method': 'none'}).encode(),
            headers={'Content-Type': 'application/json'})
        response = opener.open(request, timeout=5)
        assert response.status == 201
        registration = json.load(response)
        assert registration['client_id']
        result['checks']['local_mcp_client_registration'] = True
        try:
            opener.open(urllib.request.Request(base + '/.mcp', data=b'{}',
                         headers={'Content-Type': 'application/json'}), timeout=5)
        except urllib.error.HTTPError as error:
            assert error.code == 401
        else:
            raise AssertionError('MCP accepted an unauthenticated request')
        result['checks']['mcp_authentication_required'] = True
        policy = json.loads((data / 'server.json').read_text())
        assert policy['runtimeApi'] is False and policy['search'] == {}
        result['checks']['no_optional_download_features_enabled'] = True
        browser_report = None
        if '--browser-python' in sys.argv:
            browser_python = sys.argv[sys.argv.index('--browser-python') + 1]
            browser = sys.argv[sys.argv.index('--browser') + 1]
            browser_report = work / 'browser-before-restart.json'
            subprocess.run([browser_python, '-I', '-B', str(ROOT / 'tests/browser_workflow.py'),
                            '--browser', browser, '--credentials', str(data / 'initial-credentials.json'),
                            '--report', str(browser_report)], check=True)
            result['checks']['browser_before_restart'] = json.loads(browser_report.read_text())['checks']
        # Stop only our supervisor; its owned groups must clean up all children.
        stop(server)
        assert not (runtime / 'g.sock').exists()
        try:
            socket.create_connection(('127.0.0.1', 3097), timeout=.2).close()
        except OSError:
            pass
        else:
            raise AssertionError('Server still listening after owned stop')
        result['checks']['owned_stop_closes_server_and_gateway'] = True
        password_before = (data / 'initial-credentials.json').read_bytes()
        server = start()
        ready(server)
        assert (data / 'initial-credentials.json').read_bytes() == password_before
        with opener.open(base + '/.well-known/oauth-authorization-server', timeout=5) as response:
            assert json.load(response)['issuer'] == base
        result['checks']['restart_preserves_account_and_settings'] = True
        if browser_report:
            report_after = work / 'browser-after-restart.json'
            subprocess.run([browser_python, '-I', '-B', str(ROOT / 'tests/browser_workflow.py'),
                            '--browser', browser, '--credentials', str(data / 'initial-credentials.json'),
                            '--report', str(report_after), '--previous-report', str(browser_report)], check=True)
            result['checks']['browser_after_restart'] = json.loads(report_after.read_text())['checks']
        if TRACE:
            pids = set(re.findall(r'SERVER_GUARD: .* pid=(\d+)', (work / 'service.log').read_text()))
            all_lines = []
            for path in work.glob('network-*.trace'):
                all_lines.extend(path.read_text().splitlines())
            # Rust can make calls on any Tokio thread, not only the main PID.
            edges = []
            for line in all_lines:
                parent = re.match(r'^(\d+)\s+', line)
                child = re.search(r'=\s*(\d+)\s*$', line)
                if parent and child and re.search(r'\b(?:clone3?|fork|vfork)(?:\(| resumed>)', line):
                    edges.append((parent[1], child[1]))
            roots = len(pids)
            while True:
                descendants = {child for parent, child in edges if parent in pids}
                if descendants <= pids:
                    break
                pids |= descendants
            lines = [line for line in all_lines if line.split() and line.split()[0] in pids]
            assert lines, 'No server trace lines captured'
            for line in lines:
                assert 'connect(' not in line and 'SOCK_DGRAM' not in line and 'SOCK_RAW' not in line, line
                assert 'sendmsg(' not in line and 'sendmmsg(' not in line, line
                if 'sendto(' in line:
                    arguments = line.split('sendto(', 1)[1].split(')', 1)[0].split(',')
                    assert len(arguments) == 6 and arguments[4].strip() in ['0', '0x0', 'NULL'], line
            (work / 'server-only.trace').write_text('\n'.join(lines) + '\n')
            result['checks']['server_setup_and_workflow_no_outbound_attempts'] = True
            result['trace_coverage'] = {'setup_server_processes': roots,
                                        'all_server_tasks_including_threads': len(pids),
                                        'connect_attempts': 0, 'datagram_or_raw_attempts': 0}
        else:
            result['outbound_attempt_observation'] = 'not measured: tracing disabled'
        result['checks']['arbitrary_target_spaces_unicode_percent_dollar'] = True
        result['checks']['target_longer_than_unix_socket_limit'] = len(os.fsencode(deployed)) > 104
        assert result['checks']['target_longer_than_unix_socket_limit']
        result['passed'] = True
    finally:
        for child in [ingress, server]:
            if child is not None and child.poll() is None:
                stop(child) if child is server else child.terminate()
                child.wait(timeout=15)
        log.close()
        for name in ['network-namespace.json']:
            if (data / 'audit' / name).exists():
                shutil.copy2(data / 'audit' / name, work / name)
        (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


def host():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apparmor-profile')
    parser.add_argument('--trace', action='store_true', help='Development-only syscall observation')
    parser.add_argument('--simulate-no-ipv6', action='store_true', help='Test-only inherited EAFNOSUPPORT for AF_INET6')
    parser.add_argument('--browser-python', type=Path)
    parser.add_argument('--browser', type=Path)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 9):
        raise RuntimeError('Run with the existing local Python 3.9')
    work = ROOT / 'evidence/isolated-runtime-work'
    if work.exists():
        raise RuntimeError('Prior test work exists; inspect rather than overwrite')
    work.mkdir(mode=0o700)
    interpreter_root = Path(sys.executable).resolve().parents[1]
    extras = []
    if args.trace:
        if not shutil.which('strace'):
            raise RuntimeError('Tracing test requires strace; deployment does not')
    elif shutil.which('strace'):
        extras += ['--ro-bind', '/dev/null', str(Path(shutil.which('strace')).resolve())]
    if bool(args.browser_python) != bool(args.browser):
        raise RuntimeError('Both browser-python and browser must be provided')
    if args.browser_python:
        extras += ['--ro-bind', str(args.browser_python.parent.parent), str(args.browser_python.parent.parent),
                   '--ro-bind', str(args.browser.parent), str(args.browser.parent)]
    command = (['aa-exec', '-p', args.apparmor_profile, '--'] if args.apparmor_profile else []) + ['bwrap', '--unshare-all',
        '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--ro-bind', '/etc', '/etc', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--tmpfs', '/home', '--ro-bind', str(ROOT), str(ROOT),
        '--bind', str(work), str(work), '--ro-bind', str(interpreter_root), str(interpreter_root),
        *extras, '--clearenv', '--setenv', 'PATH', os.defpath, '--setenv', 'HOME', str(work),
        str(Path(sys.executable).resolve()), '-I', '-B', str(ROOT / 'tests/offline_runtime.py'), '--inside', '--work', str(work)]
    if args.trace:
        command += ['--trace']
    if args.simulate_no_ipv6:
        command += ['--simulate-no-ipv6']
    if args.browser_python:
        command += ['--browser-python', str(args.browser_python), '--browser', str(args.browser)]
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
    (ROOT / 'evidence/isolated-runtime.log').write_text(output.stdout)
    if output.returncode:
        raise RuntimeError(output.stdout)
    report = json.loads((work / 'result.json').read_text())
    assert report['passed']
    (ROOT / 'evidence/python39-isolated-runtime.json').write_text(json.dumps(report, indent=2) + '\n')
    # Preserve payload-free audit proofs, never retain test credentials/accounts.
    for name in ['network-namespace.json'] + (['server-only.trace'] if args.trace else []):
        shutil.copy2(work / name, ROOT / 'evidence' / ('candidate-' + name))
    shutil.rmtree(work)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    if '--inside' in sys.argv:
        inside()
    else:
        host()
