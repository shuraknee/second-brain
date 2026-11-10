#!/usr/bin/env python3
"""Prepare local release assets with versioned human/AI instructions; no network."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = ('agent.md', 'INSTALL.md', 'README.md', 'RELEASING.md', 'LICENSE',
             'LICENSE.silverbullet.md', 'LICENSING.md', 'THIRD_PARTY_NOTICES.md',
             'OFFLINE-AUDIT.md', 'BUILD-OFFLINE.md')


def digest(path):
    with path.open('rb') as stream:
        return stream_digest(stream)


def stream_digest(stream):
    result = hashlib.sha256()
    for block in iter(lambda: stream.read(1048576), b''):
        result.update(block)
    return result.hexdigest()


def read_package(path):
    """Check every payload file before returning the release documentation."""
    with tarfile.open(path) as archive:
        members = {}
        for member in archive.getmembers():
            relative = Path(member.name)
            if (not member.isfile() or relative.is_absolute() or '..' in relative.parts
                    or not member.name.startswith('silverbullet-offline/')
                    or str(relative) != member.name or member.name in members):
                raise RuntimeError('Unsafe/duplicate archive member: ' + member.name)
            members[member.name] = member

        def read(name):
            member = members.get('silverbullet-offline/' + name)
            if member is None:
                raise RuntimeError('Required payload file missing: ' + name)
            return archive.extractfile(member).read()

        documents = {}
        for name in DOCUMENTS:
            data = read(name)
            if not data.decode('utf-8').strip():
                raise RuntimeError('Required document is empty: ' + name)
            if data != (ROOT / name).read_bytes():
                raise RuntimeError('Document differs from this checkout: ' + name)
            documents[name] = data
        manifest_data = read('manifest.json')
        if manifest_data != (ROOT / 'manifest.json').read_bytes():
            raise RuntimeError('Manifest differs from this checkout')
        manifest = json.loads(manifest_data)
        if manifest.get('offline_build', {}).get('audit_status') != 'source-and-runtime-verified':
            raise RuntimeError('Offline source/runtime acceptance incomplete')
        checksums = {}
        for line in read('SHA256SUMS').decode('utf-8').splitlines():
            checksum, name = line.split('  ', 1)
            if name in checksums or not re.fullmatch('[0-9a-f]{64}', checksum):
                raise RuntimeError('Invalid/duplicate payload checksum')
            checksums[name] = checksum
        expected_names = {'silverbullet-offline/' + name for name in checksums}
        if expected_names != set(members) - {'silverbullet-offline/SHA256SUMS'}:
            raise RuntimeError('Payload checksum file set mismatch')
        for name, checksum in checksums.items():
            with archive.extractfile(members['silverbullet-offline/' + name]) as stream:
                if stream_digest(stream) != checksum:
                    raise RuntimeError('Payload checksum mismatch: ' + name)
        if checksums.get('bin/silverbullet') != manifest['binary_sha256']:
            raise RuntimeError('Binary differs from the pinned manifest')
        return documents, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repository', required=True, help='GitHub OWNER/REPO; used only to render links')
    parser.add_argument('--notes-file', type=Path, required=True, help='Actual changes, checks and limitations')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', args.repository):
        raise RuntimeError('Use repository as OWNER/REPO')
    archive = args.archive.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not archive.name.endswith('.tar.gz'):
        raise RuntimeError('Runtime archive must use the .tar.gz extension')
    if output.exists() or not output.parent.is_dir():
        raise RuntimeError('Choose a new output directory with an existing parent')
    expected, name = Path(str(archive) + '.sha256').read_text(encoding='utf-8').strip().split('  ', 1)
    if name != archive.name or digest(archive) != expected:
        raise RuntimeError('Archive SHA256 mismatch')
    documents, manifest = read_package(archive)
    tag = manifest['supply_revision']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', tag):
        raise RuntimeError('Supply revision must be a release tag without path components')
    notes = args.notes_file.read_text(encoding='utf-8').strip()
    if not notes:
        raise RuntimeError('Release notes must describe changes, checks and limitations')
    base = 'https://github.com/' + args.repository + '/blob/' + tag
    heading = ('[Для ИИ: сначала прочитать в браузере](' + base + '/agent.md) · '
               '[Для человека: установка](' + base + '/INSTALL.md)\n\n'
               'Инструкции и файлы относятся к версии `' + tag + '`. '
               'agent.md и INSTALL.md приложены отдельно и входят в runtime-архив.\n\n')
    with tempfile.TemporaryDirectory(prefix='release-assets-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'assets'
        stage.mkdir()
        shutil.copyfile(archive, stage / archive.name)
        if digest(stage / archive.name) != expected:
            raise RuntimeError('Archive changed while preparing release assets')
        documents['RELEASE_NOTES.md'] = (heading + notes + '\n').encode('utf-8')
        for name, data in documents.items():
            (stage / name).write_bytes(data)
        for path in sorted(stage.iterdir()):
            (stage / (path.name + '.sha256')).write_text(digest(path) + '  ' + path.name + '\n', encoding='utf-8')
        (stage / 'SHA256SUMS').write_text(''.join(digest(path) + '  ' + path.name + '\n'
            for path in sorted(stage.iterdir())), encoding='utf-8')
        stage.rename(output)
    print(json.dumps({'directory': str(output), 'tag': tag, 'assets': len(list(output.iterdir()))}))


if __name__ == '__main__':
    main()
