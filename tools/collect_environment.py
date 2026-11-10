#!/usr/bin/env python3
"""Read-only target inventory. No downloads, package installs or service changes.

No namespace creation or network connection probes are performed.
"""
import ctypes
import json
import platform
import shutil
import subprocess
from pathlib import Path


def command(args):
    if not shutil.which(args[0]):
        return {'error': 'command not found'}
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=10)
        return {'exit': result.returncode, 'output': result.stdout.strip()[:4000]}
    except Exception as error:
        return {'error': str(error)}


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError as error:
        return {'error': str(error)}


def collect():
    result = {'os_release': read('/etc/os-release'), 'kernel': platform.release(),
        'arch': platform.machine(), 'python': platform.python_version(),
        'systemd': command(['systemctl', '--version']),
        'user_manager': command(['systemctl', '--user', 'is-system-running']),
        'selinux': command(['getenforce']),
        'tools': {name: shutil.which(name) for name in ['git', 'findmnt']}}

    try:
        ctypes.CDLL('libseccomp.so.2')
        result['libseccomp'] = 'load OK'
    except OSError as error:
        result['libseccomp'] = str(error)
    if platform.machine() == 'x86_64':
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        value = libc.syscall(444, 0, 0, 1)
        result['landlock'] = {'abi': value, 'errno': ctypes.get_errno() if value < 0 else 0}
    return result


if __name__ == '__main__':
    print(json.dumps(collect(), ensure_ascii=False, indent=2))
