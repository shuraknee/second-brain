#!/usr/bin/env python3
"""Install the Second Brain client from the operator-provisioned SSH host."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def fetch(alias):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@:-]{0,254}', alias):
        raise ValueError('Укажите SSH-псевдоним из инструкции администратора.')
    ssh = shutil.which('ssh')
    if not ssh:
        raise ValueError('Для подключения требуется установленный OpenSSH.')
    command = [ssh, '-nT', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
               '-oClearAllForwardings=yes', '-oForwardAgent=no', '-oPermitLocalCommand=no',
               '-oConnectTimeout=20', alias, 'secondbrain-client-v1']
    # Keep old bridges from waiting for a stdin packet. Only the pinned SSH host
    # and its operator-controlled forced command may supply local executable code.
    reply = subprocess.run(command, stdout=subprocess.PIPE, timeout=45, check=True)
    try:
        packet = json.loads(reply.stdout)
        code = base64.b64decode(packet['client'], validate=True)
        if packet['format'] != 1 or not code or len(code) > 512 * 1024:
            raise ValueError()
        if hashlib.sha256(code).hexdigest() != packet['sha256']:
            raise ValueError()
        for field in ('bridge', 'config'):
            value = packet[field]
            if not isinstance(value, str) or not value.startswith('/') or any(ord(c) < 32 for c in value):
                raise ValueError()
    except (KeyError, ValueError, TypeError):
        raise ValueError('Сервер не вернул комплект клиента. Проверьте версию моста и SSH-псевдоним.') from None
    return code, packet


@contextmanager
def setup_lock(root):
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError('Выберите личный каталог без символьных ссылок.')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != 'nt' and (root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o022):
        raise ValueError('Каталог клиента должен принадлежать вам и быть закрыт для чужой записи.')
    lock = root / '.setup.lock'
    if lock.is_symlink():
        raise ValueError('Недопустимая ссылка вместо файла блокировки.')
    with lock.open('a+b') as stream:
        try:
            if os.name == 'nt':
                import msvcrt
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError('Уже идёт настройка клиента или файл блокировки недоступен.') from None
        yield


def install_client(root, code):
    path = root / 'client.py'
    if path.is_symlink():
        raise ValueError('client.py не должен быть ссылкой.')
    if path.exists():
        if path.read_bytes() == code:
            return path
        if input('Заменить локальный client.py версией с этого сервера? [y/N] ').lower() != 'y':
            raise ValueError('Установка отменена.')
    temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=root, delete=False) as f:
            temp = Path(f.name)
            f.write(code)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('server', help='SSH alias prepared by the administrator')
    parser.add_argument('--renew', action='store_true', help='Explicitly replace the personal token')
    parser.add_argument('--sha256', help='Optional client.py digest supplied independently by IT')
    args = parser.parse_args()
    root = Path.home() / '.silverbullet' / 'ssh-mcp'
    try:
        code, packet = fetch(args.server)
        if args.sha256 is not None and packet['sha256'] != args.sha256.lower():
            raise ValueError('SHA256 клиента отличается от значения администратора.')
        with setup_lock(root):
            # Refuse switching installations before replacing their shared local client.
            profile = root / 'team.json'
            if profile.exists():
                old = json.loads(profile.read_bytes())
                if (old.get('ssh_target'), old.get('remote_bridge'), old.get('remote_config')) != (
                        args.server, packet['bridge'], packet['config']):
                    raise ValueError('Профиль team связан с другим сервером. Обратитесь к администратору.')
            path = install_client(root, code)
            command = [sys.executable, '-I', '-B', str(path), '--config-dir', str(root), 'setup',
                       '--ssh-target', args.server, '--remote-bridge', packet['bridge'],
                       '--remote-config', packet['config']]
            if args.renew:
                command.append('--renew')
            return subprocess.run(command).returncode
    except subprocess.CalledProcessError as error:
        print('SSH не выдал комплект клиента (код %d). Проверьте ключ, known_hosts и мост.' % error.returncode, file=sys.stderr)
    except (OSError, ValueError, EOFError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
