#!/usr/bin/env python3
"""Exercise a fresh packaged server and retrofit import on owned temporary data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def run(arguments, timeout=180):
    result = subprocess.run([str(a) for a in arguments], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stdout[-3000:] + result.stderr[-3000:])
    return result.stdout


def unused_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--browser-python', type=Path, required=True)
    parser.add_argument('--browser', type=Path, required=True)
    args = parser.parse_args()
    expected, filename = Path(str(args.archive) + '.sha256').read_text().strip().split('  ', 1)
    assert filename == args.archive.name
    assert hashlib.sha256(args.archive.read_bytes()).hexdigest() == expected
    work = Path(tempfile.mkdtemp(prefix='knowledge-runtime-', dir=ROOT / 'evidence'))
    runtime = tempfile.TemporaryDirectory(prefix='sb-kb-', dir=os.environ['XDG_RUNTIME_DIR'])
    report = {'passed': False, 'scope': 'temporary development-host package; no corporate-client acceptance', 'checks': {}}
    processes = []
    try:
        with tarfile.open(args.archive) as archive:
            for entry in archive.getmembers():
                assert entry.isfile() and not Path(entry.name).is_absolute() and '..' not in Path(entry.name).parts
            archive.extractall(work)
        source = work / 'silverbullet-offline'
        run([sys.executable, '-I', '-B', source / 'tools/verify_payload.py'])
        data = work / 'server data % $'
        config = work / 'service.json'
        port = unused_port()
        backend = unused_port()
        while backend == port:
            backend = unused_port()
        origin = 'http://127.0.0.1:' + str(port)
        config.write_text(json.dumps({'status': 'target-approved', 'namespace_required': False,
            'network_policy': 'seccomp-no-connect', 'public_url': origin,
            'backend_port': backend, 'listen_host': '127.0.0.1', 'listen_port': port,
            'gateway_socket': str(Path(runtime.name) / 'g.sock'), 'runtime_directory': runtime.name,
            'admin_username': 'test-only', 'space_name': 'Synthetic runtime test',
            'data_directory': str(data), 'history_mode': 'managed'}))
        log = (work / 'service.log').open('w')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def stop_all():
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=20)
            processes.clear()

        def start_all():
            for script in ['service.py', 'ingress.py']:
                processes.append(subprocess.Popen([sys.executable, '-I', '-B', str(source / 'tools' / script),
                    '--config', str(config)], stdout=log, stderr=log, start_new_session=True))
            for unused in range(200):
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError((work / 'service.log').read_text()[-3500:])
                try:
                    with opener.open(origin + '/.well-known/oauth-authorization-server', timeout=.5) as response:
                        assert json.load(response)['issuer'] == origin
                        return
                except (urllib.error.URLError, OSError):
                    time.sleep(.1)
            raise RuntimeError('Temporary server readiness timeout')

        start_all()
        browser = [args.browser_python, '-I', '-B', ROOT / 'tests/browser_workflow.py',
            '--browser', args.browser, '--credentials', data / 'initial-credentials.json',
            '--base-url', origin, '--check-knowledge']
        before = work / 'browser-before.json'
        run(browser + ['--report', before])
        report['checks']['fresh_install_mcp_browser'] = json.loads(before.read_text())['checks']
        stop_all()
        spaces = json.loads((data / 'spaces.json').read_text())
        space_id, config_space = next(iter(spaces.items()))
        folder = config_space.get('folder', '')
        space = Path(folder) if folder else Path('spaces') / space_id
        if not space.is_absolute():
            space = data / space
        # Simulate an old space with real notes but without any imported bundle.
        original_index = (space / 'index.md').read_bytes()
        shutil.rmtree(space / 'Library/Second Brain')
        importer = [sys.executable, '-I', '-B', source / 'tools/knowledge.py', '--space-dir', space]
        preview = json.loads(run(importer))
        assert preview['pending'] and not preview['created'] and preview['ok']
        assert not (space / 'Library/Second Brain').exists()
        imported = json.loads(run(importer + ['--apply']))
        assert len(imported['created']) == 10 and imported['ok']
        repeated = json.loads(run(importer + ['--apply']))
        assert not repeated['created'] and len(repeated['unchanged']) == 10
        assert (space / 'index.md').read_bytes() == original_index
        report['checks']['existing_space_import_preserves_notes_and_is_idempotent'] = True
        marker_page = space / 'Library/Second Brain/Происхождение.md'
        marker_page.write_text(marker_page.read_text() + '\nOperator annotation retained on restart.\n')
        start_all()
        after = work / 'browser-after.json'
        run(browser + ['--report', after, '--previous-report', before])
        report['checks']['after_import_and_restart_mcp_browser'] = json.loads(after.read_text())['checks']
        assert 'Operator annotation retained on restart.' in marker_page.read_text()
        report['checks']['restart_does_not_reseed_or_overwrite_edited_knowledge'] = True
        report['passed'] = True
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=20)
        runtime.cleanup()
        (ROOT / 'evidence/knowledge-runtime.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        if report['passed']:
            shutil.rmtree(work)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
