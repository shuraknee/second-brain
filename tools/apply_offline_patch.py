#!/usr/bin/env python3
"""Apply the reviewed offline source patch to prepared local upstream sources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.expanduser().resolve(strict=True)
    manifest = json.loads((ROOT / 'manifest.json').read_text())['offline_build']
    patch = ROOT / 'patches/offline.patch'
    inventory = ROOT / 'patches/source-files.json'
    if digest(patch) != manifest['patch_sha256'] or digest(inventory) != manifest['source_files_sha256']:
        raise RuntimeError('Offline source patch/inventory checksum mismatch')
    files = json.loads(inventory.read_text())['files']
    for entry in files:
        relative = Path(entry['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise RuntimeError('Unsafe source path')
        path = source / relative
        if any(parent.is_symlink() for parent in [path, *path.parents] if parent != source.parent):
            raise RuntimeError('Symlink in source path: ' + entry['path'])
        before = entry['before_sha256']
        if (before is None and path.exists()) or (before is not None and
                (not path.is_file() or digest(path) != before)):
            raise RuntimeError('Upstream source differs from reviewed revision: ' + entry['path'])
    environment = {key: value for key, value in os.environ.items()
                   if key not in ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR']}
    environment['GIT_CEILING_DIRECTORIES'] = str(source.parent)
    command = ['git', 'apply', '--no-index', '--unidiff-zero', '--whitespace=nowarn']
    subprocess.run(command + ['--check', str(patch)], cwd=source, env=environment, check=True)
    subprocess.run(command + [str(patch)], cwd=source, env=environment, check=True)
    for entry in files:
        if digest(source / entry['path']) != entry['after_sha256']:
            raise RuntimeError('Patched source checksum mismatch: ' + entry['path'])
    print('OFFLINE_PATCH_OK: %d source files' % len(files))


if __name__ == '__main__':
    main()
