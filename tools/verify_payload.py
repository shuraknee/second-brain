#!/usr/bin/env python3
"""Verify an unpacked candidate using the local checksums only."""
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    lines = (ROOT / 'SHA256SUMS').read_text().splitlines()
    checked = 0
    for line in lines:
        expected, name = line.split('  ', 1)
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise RuntimeError('Unsafe manifest path')
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('Missing/unsafe file: ' + name)
        with path.open('rb') as stream:
            digest = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != expected:
            raise RuntimeError('Checksum mismatch: ' + name)
        checked += 1
    print('PAYLOAD_OK: %d files' % checked)


if __name__ == '__main__':
    sys.excepthook = sys.__excepthook__
    main()
