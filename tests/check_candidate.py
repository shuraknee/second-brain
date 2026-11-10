#!/usr/bin/env python3
"""Run locally with Python 3.9, without changing the live lab or any service."""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    result = {'python': sys.version.split()[0], 'checks': {}, 'passed': False}
    assert sys.version_info[:2] == (3, 9), sys.version
    for path in list((ROOT / 'tools').glob('*.py')) + list((ROOT / 'tests').glob('*.py')):
        ast.parse(path.read_text(), filename=str(path))
    result['checks']['python39_syntax'] = True
    guard = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/egress_guard.py'), '--self-test'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert guard.returncode == 0, guard.stderr
    result['checks']['egress_controls'] = json.loads(guard.stdout)
    version = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/egress_guard.py'), '--',
                              str(ROOT / 'bin/silverbullet'), 'version'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert version.returncode == 0, version.stderr
    assert 'g0fbe7b51' in version.stdout
    result['checks']['pinned_server_version_under_guard'] = version.stdout.strip()
    pending = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/service.py'), '--config',
                              str(ROOT / 'config/service.example.json')],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert pending.returncode != 0 and 'has not been approved' in pending.stderr, pending.stderr
    result['checks']['pending_profile_refuses_start'] = True
    with tempfile.TemporaryDirectory(prefix='candidate-tests-', dir=ROOT / 'evidence') as tmp:
        config = json.loads((ROOT / 'config/service.example.json').read_text())
        config.update(status='target-approved', public_url='http://127.0.0.1:3098',
                      backend_port=3098, admin_username='test-only', data_directory=str(Path(tmp) / 'data'),
                      gateway_socket=str(Path(tmp) / 'data/gateway.sock'))
        target = Path(tmp) / 'config.json'
        target.write_text(json.dumps(config))
        unisolated = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/service.py'), '--config', str(target)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert unisolated.returncode != 0 and 'Refusing host network' in unisolated.stderr, unisolated.stderr
        assert not (Path(tmp) / 'data').exists()
        result['checks']['host_network_refused_before_data_write'] = True
    inventory = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/collect_environment.py')],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert inventory.returncode == 0, inventory.stderr
    local_inventory = json.loads(inventory.stdout)
    assert local_inventory['arch'] == 'x86_64'
    result['checks']['collector_runs_on_python39'] = True
    result['passed'] = True
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
