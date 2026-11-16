#!/usr/bin/env python3
"""Import the bundled Second Brain pages without replacing existing content.

Default: inspect only. --apply creates missing pages after checking all conflicts.
No network, shell, server configuration changes or dependency installation.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'knowledge-base'
PREFIX = 'Library/Second Brain/'
MAX_PAGE = 1024 * 1024


def bundle_files(bundle=None):
    bundle = Path(bundle or BUNDLE)
    manifest = json.loads((bundle / 'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('schema_version') != 1 or not isinstance(manifest.get('files'), dict) or not manifest['files']:
        raise ValueError('Invalid knowledge bundle manifest')
    result = {}
    for name, expected in sorted(manifest['files'].items()):
        relative = PurePosixPath(name)
        if (relative.is_absolute() or '..' in relative.parts or str(relative) != name
                or not name.startswith(PREFIX) or not name.endswith('.md')
                or not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected)):
            raise ValueError('Invalid knowledge page/checksum: ' + name)
        path = bundle / 'pages' / name
        if path.resolve() != path.absolute() or not path.is_file():
            raise ValueError('Missing/linked knowledge page: ' + name)
        content = path.read_bytes()
        if not content or len(content) > MAX_PAGE or hashlib.sha256(content).hexdigest() != expected:
            raise ValueError('Knowledge page checksum/size mismatch: ' + name)
        content.decode('utf-8')
        result[name] = content
    actual = {p.relative_to(bundle / 'pages').as_posix()
              for p in (bundle / 'pages').rglob('*') if p.is_file() or p.is_symlink()}
    if actual != set(result):
        raise ValueError('Knowledge bundle file set mismatch')
    return result


@contextmanager
def directory(root_fd, parts, create=False):
    fd = os.dup(root_fd)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


@contextmanager
def absolute_directory(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        with directory(fd, path.parts[1:]) as selected:
            yield selected
    finally:
        os.close(fd)


def read_existing(root_fd, name):
    parts = PurePosixPath(name).parts
    try:
        with directory(root_fd, parts[:-1]) as parent:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_PAGE:
                    raise ValueError('Not a bounded regular unlinked page: ' + name)
                return stream.read(MAX_PAGE + 1)
    except FileNotFoundError:
        return None


def create_page(root_fd, name, content):
    parts = PurePosixPath(name).parts
    with directory(root_fd, parts[:-1], create=True) as parent:
        temporary = '.second-brain-import-' + secrets.token_hex(12)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            # Atomic publication of a complete file, with no overwrite even in a race.
            os.link(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.fsync(parent)
        finally:
            os.unlink(temporary, dir_fd=parent)


def install_pages(space_dir, apply=False, bundle=None):
    path = Path(space_dir)
    if (not path.is_absolute() or '..' in path.parts
            or any(ord(c) < 32 or ord(c) == 127 for c in str(path))):
        raise ValueError('Use an existing absolute space directory without .. or control characters')
    pages = bundle_files(bundle)
    report = {'mode': 'apply' if apply else 'inspect', 'created': [], 'unchanged': [],
              'pending': [], 'conflicts': []}
    # Open every component without following links, including the selected root.
    with absolute_directory(path) as root_fd:
        if os.fstat(root_fd).st_uid != os.getuid():
            raise ValueError('Space directory must belong to the importing user')
        fcntl.flock(root_fd, fcntl.LOCK_EX if apply else fcntl.LOCK_SH)
        for name, content in pages.items():
            current = read_existing(root_fd, name)
            if current is None:
                report['pending'].append(name)
            elif current == content:
                report['unchanged'].append(name)
            else:
                report['conflicts'].append(name)
        if apply and not report['conflicts']:
            try:
                for name in list(report['pending']):
                    # A non-cooperating writer may have created a page after preflight.
                    current = read_existing(root_fd, name)
                    if current is None:
                        create_page(root_fd, name, pages[name])
                        report['created'].append(name)
                    elif current == pages[name]:
                        report['unchanged'].append(name)
                    else:
                        raise RuntimeError('Concurrent page change: ' + name)
                    report['pending'].remove(name)
            except Exception as error:
                # Retain completed pages; the report makes partial application explicit.
                report['error'] = str(error)
    report['ok'] = not report['conflicts'] and 'error' not in report
    return report


def seed_fresh_spaces(data):
    """Called only after fresh provisioning; follows SilverBullet's folder rules."""
    data = Path(data)
    spaces = json.loads((data / 'spaces.json').read_text(encoding='utf-8'))
    if not isinstance(spaces, dict) or not spaces:
        raise ValueError('Fresh provisioning did not create a space')
    reports = []
    for space_id, config in spaces.items():
        if not re.fullmatch('[A-Za-z0-9-]+', space_id):
            raise ValueError('Invalid space id')
        folder = config.get('folder', '')
        path = Path(folder) if folder else Path('spaces') / space_id
        if not path.is_absolute():
            path = data / path
        report = install_pages(path, apply=True)
        if not report['ok']:
            raise RuntimeError('Knowledge import incomplete; inspect with tools/knowledge.py: ' + json.dumps(report))
        reports.append(report)
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--space-dir', type=Path, required=True,
                        help='Existing absolute directory of notes, not the server data root')
    parser.add_argument('--apply', action='store_true', help='Create missing pages; never replace differing pages')
    args = parser.parse_args()
    report = install_pages(args.space_dir, apply=args.apply)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({'ok': False, 'error': str(error)}, ensure_ascii=False), file=sys.stderr)
        sys.exit(1)
