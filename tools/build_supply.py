#!/usr/bin/env python3
"""Offline archive builder: local input binary and output path are explicit."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    binary = args.binary.expanduser().resolve()
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    if digest(binary) != manifest['binary_sha256']:
        raise RuntimeError('Binary hash differs from the pinned build')
    if any(Path(str(output) + suffix).exists() for suffix in ['', '.sha256', '.part']):
        raise RuntimeError('Output exists; choose a new archive path')
    if not output.parent.is_dir():
        raise RuntimeError('Select an existing output directory')
    files = [ROOT / name for name in ['README.md', 'agent.md', 'AGENTS.md', 'INSTALL.md', 'RELEASING.md',
                                      'LICENSE', 'THIRD_PARTY_NOTICES.md', 'LICENSING.md',
                                      'LICENSE.silverbullet.md', 'manifest.json']]
    for name in ['agent.md', 'INSTALL.md']:
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or not path.read_text(encoding='utf-8').strip():
            raise RuntimeError('Required installation instruction is missing/empty: ' + name)
    legal = json.loads((ROOT / 'licenses/audit.json').read_text())
    if legal.get('status') != 'verified-notices-and-source-offer' or legal.get('unresolved_packages') != 0:
        raise RuntimeError('Legal review is incomplete; packaging blocked')
    expected_legal = {entry['path']: entry['sha256'] for entry in legal['files']}
    actual_legal = {str(path.relative_to(ROOT)) for path in (ROOT / 'licenses').rglob('*') if path.is_file() and path.name != 'audit.json'}
    if set(expected_legal) != actual_legal:
        raise RuntimeError('Legal file set differs from the reviewed inventory')
    for name, expected in expected_legal.items():
        if digest(ROOT / name) != expected:
            raise RuntimeError('Legal notice/source checksum mismatch: ' + name)
    files.extend(path for path in (ROOT / 'licenses').rglob('*') if path.is_file())
    # Deployment payload is an explicit allowlist. Test sources, evidence,
    # host inventories and builder work files never enter a runtime package.
    files.extend(ROOT / 'tools' / name for name in [
        'collect_environment.py', 'egress_guard.py', 'ingress.py', 'install.py',
        'proxy.py', 'service.py', 'verify_payload.py'])
    files.extend(ROOT / 'templates' / name for name in [
        'silverbullet.service.in', 'silverbullet-ingress.service.in'])
    files.append(ROOT / 'config/service.example.json')
    with tempfile.TemporaryDirectory(prefix='supply-build-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'silverbullet-offline'
        stage.mkdir()
        for path in sorted(files):
            if path.is_symlink():
                raise RuntimeError('Symlink in source payload')
            destination = stage / path.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
        (stage / 'bin').mkdir()
        shutil.copy2(binary, stage / 'bin/silverbullet')
        entries = sorted(path for path in stage.rglob('*') if path.is_file())
        (stage / 'SHA256SUMS').write_text(''.join(digest(path) + '  ' + str(path.relative_to(stage)) + '\n' for path in entries))
        with open(str(output) + '.part', 'xb') as raw:
            with gzip.GzipFile(filename='', mode='wb', compresslevel=1, mtime=0, fileobj=raw) as compressed:
                with tarfile.open(fileobj=compressed, mode='w') as archive:
                    for path in sorted(stage.rglob('*')):
                        if path.is_file():
                            name = 'silverbullet-offline/' + str(path.relative_to(stage))
                            info = archive.gettarinfo(str(path), arcname=name)
                            info.uid = info.gid = 0
                            info.uname = info.gname = ''
                            info.mtime = 0
                            info.pax_headers = {}
                            info.mode = 0o755 if path == stage / 'bin/silverbullet' else 0o644
                            with path.open('rb') as stream:
                                archive.addfile(info, stream)
    Path(str(output) + '.part').rename(output)
    checksum = digest(output)
    Path(str(output) + '.sha256').write_text(checksum + '  ' + output.name + '\n')
    print(json.dumps({'archive': str(output), 'sha256': checksum,
                      'size_bytes': output.stat().st_size}, indent=2))


if __name__ == '__main__':
    main()
