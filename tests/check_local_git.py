#!/usr/bin/env python3
"""Compile/run the local Git contract tests in prepared sources, under egress_guard.

Run this on the isolated build machine. Toolchain/library paths are explicit;
no downloading, package installation or application service changes.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--libc', type=Path, required=True)
    parser.add_argument('--linker', type=Path, required=True)
    parser.add_argument('--python', required=True)
    args = parser.parse_args()
    source = (args.source / 'server/src/revisions/git.rs').resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='local-git-contract-') as temporary:
        directory = Path(temporary)
        wrapper = directory / 'tests.rs'
        wrapper.write_text('#[path = ' + json.dumps(str(source), ensure_ascii=False) + ']\nmod local_git;\n')
        binary = directory / 'git-contract-tests'
        subprocess.run([str(args.rustc), '--edition=2021', '--test', str(wrapper),
                        '--target=x86_64-unknown-linux-musl', '--extern', 'libc=' + str(args.libc),
                        '-L', 'dependency=' + str(args.libc.parent), '-C', 'linker=' + str(args.linker),
                        '-o', str(binary)], check=True)
        subprocess.run([args.python, '-I', '-B', str(ROOT / 'tools/egress_guard.py'),
                        '--', str(binary), '--nocapture'], check=True)


if __name__ == '__main__':
    main()
