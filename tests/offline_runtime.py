#!/usr/bin/env python3
"""Candidate integration check; the corporate server is never contacted.

Host mode creates an isolated child with the already available VM facilities.
Test-host namespace facilities are NOT a dependency of the supply.
"""
import json
import argparse
import os
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


def inside():
    work = Path(sys.argv[sys.argv.index('--work') + 1])
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
        return subprocess.Popen([sys.executable, '-I', '-B', str(deployed / 'tools/service.py'),
                                 '--config', str(config)], stdout=log, stderr=log)
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
    result = {'python': sys.version.split()[0], 'checks': {}, 'passed': False,
              'scope': 'development-host runtime test; not target-host acceptance'}
    try:
        ready(server)
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
        setup_trace = (data / 'audit/setup-network.trace').read_text()
        trace = (data / 'audit/server-network.trace').read_text()
        for text in [setup_trace, trace]:
            assert 'connect(' not in text and 'SOCK_DGRAM' not in text and 'SOCK_RAW' not in text, text
        result['checks']['server_setup_and_http_no_outbound_attempts'] = True
        # Stop only our supervisor; its owned groups must clean up all children.
        server.terminate()
        server.wait(timeout=15)
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
        result['checks']['arbitrary_target_spaces_unicode_percent_dollar'] = True
        result['checks']['target_longer_than_unix_socket_limit'] = len(os.fsencode(deployed)) > 104
        assert result['checks']['target_longer_than_unix_socket_limit']
        result['passed'] = True
    finally:
        for child in [ingress, server]:
            if child is not None and child.poll() is None:
                child.terminate()
                child.wait(timeout=15)
        log.close()
        for name in ['setup-network.trace', 'server-network.trace', 'network-namespace.json']:
            if (data / 'audit' / name).exists():
                shutil.copy2(data / 'audit' / name, work / name)
        (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


def host():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apparmor-profile')
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 9):
        raise RuntimeError('Run with the existing local Python 3.9')
    work = ROOT / 'evidence/isolated-runtime-work'
    if work.exists():
        raise RuntimeError('Prior test work exists; inspect rather than overwrite')
    work.mkdir(mode=0o700)
    interpreter_root = Path(sys.executable).resolve().parents[1]
    command = (['aa-exec', '-p', args.apparmor_profile, '--'] if args.apparmor_profile else []) + ['bwrap', '--unshare-all',
        '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--ro-bind', '/etc', '/etc', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--tmpfs', '/home', '--ro-bind', str(ROOT), str(ROOT),
        '--bind', str(work), str(work), '--ro-bind', str(interpreter_root), str(interpreter_root),
        '--clearenv', '--setenv', 'PATH', os.defpath, '--setenv', 'HOME', str(work),
        str(Path(sys.executable).resolve()), '-I', '-B', str(ROOT / 'tests/offline_runtime.py'), '--inside', '--work', str(work)]
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90)
    (ROOT / 'evidence/isolated-runtime.log').write_text(output.stdout)
    if output.returncode:
        raise RuntimeError(output.stdout)
    report = json.loads((work / 'result.json').read_text())
    assert report['passed']
    (ROOT / 'evidence/python39-isolated-runtime.json').write_text(json.dumps(report, indent=2) + '\n')
    # Preserve payload-free audit traces, never retain test credentials/accounts.
    for name in ['setup-network.trace', 'server-network.trace', 'network-namespace.json']:
        shutil.copy2(work / name, ROOT / 'evidence' / ('candidate-' + name))
    shutil.rmtree(work)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    if '--inside' in sys.argv:
        inside()
    else:
        host()
