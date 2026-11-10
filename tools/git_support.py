#!/usr/bin/env python3
"""Check preinstalled system Git under the same egress filter; never install it."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def require_git():
    binary = shutil.which('git', path=os.defpath)
    if not binary:
        raise RuntimeError('Local history requires preinstalled Git >=2.34; no download attempted')
    environment = {'PATH': os.defpath, 'LANG': 'C.UTF-8',
                   'HOME': os.environ.get('HOME', '/nonexistent')}
    result = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/egress_guard.py'),
                             '--', binary, '--version'], env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
    match = re.search(r'^git version (\d+)\.(\d+)(?:\.(\d+))?', result.stdout, re.M)
    if result.returncode or not match or tuple(map(int, match.group(1, 2))) < (2, 34):
        raise RuntimeError('A working preinstalled Git >=2.34 is required for local history')
    return {'path': str(Path(binary).resolve()), 'version': match.group(0).removeprefix('git version ')}


if __name__ == '__main__':
    try:
        print(json.dumps(require_git()))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
