#!/usr/bin/env python3
"""IPv4-only kernel compatibility, including inherited real seccomp controls.

The disabled-kernel case is simulated in child processes by an additional
seccomp rule returning EAFNOSUPPORT for AF_INET6. No host IPv6 settings change.
"""
import ctypes as C
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / 'tools' / (name + '.py')))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


guard = module('egress_guard')
service = module('service')


def simulate_no_ipv6():
    """Test-only kernel errno emulation, inherited by exec and descendants."""
    libc = C.CDLL(None, use_errno=True)
    sec = C.CDLL('libseccomp.so.2', use_errno=True)
    sec.seccomp_init.argtypes = [C.c_uint32]
    sec.seccomp_init.restype = C.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes = [C.c_char_p]
    sec.seccomp_rule_add_array.argtypes = [C.c_void_p, C.c_uint32, C.c_int,
                                         C.c_uint, C.POINTER(guard.Cmp)]
    sec.seccomp_load.argtypes = [C.c_void_p]
    sec.seccomp_release.argtypes = [C.c_void_p]
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(C.get_errno(), 'test PR_SET_NO_NEW_PRIVS failed')
    ctx = sec.seccomp_init(guard.ALLOW)
    if not ctx:
        raise RuntimeError('test seccomp allocation failed')
    try:
        number = sec.seccomp_syscall_resolve_name(b'socket')
        conditions = (guard.Cmp * 1)(guard.Cmp(0, 4, socket.AF_INET6, 0))
        if number < 0 or sec.seccomp_rule_add_array(ctx, 0x50000 | errno.EAFNOSUPPORT,
                                                   number, 1, conditions) < 0:
            raise RuntimeError('test IPv6 seccomp rule failed')
        if sec.seccomp_load(ctx) < 0:
            raise RuntimeError('test IPv6 seccomp load failed')
    finally:
        sec.seccomp_release(ctx)


def proc_read(path, *args, **kwargs):
    values = {'/proc/net/dev': 'header\nheader\n lo: 0\n',
              '/proc/net/route': 'Iface Destination Gateway\n'}
    if str(path) in values:
        return values[str(path)]
    if str(path) == '/proc/net/ipv6_route':
        raise FileNotFoundError(errno.ENOENT, 'synthetic missing IPv6 table')
    raise AssertionError('unexpected test read: ' + str(path))


class IPv6Tests(unittest.TestCase):
    def proof(self, read=proc_read, socket_effect=None):
        with patch.object(Path, 'read_text', read), \
             patch.object(service.os, 'readlink', return_value='synthetic-test-namespace'), \
             patch.object(service.socket, 'socket', side_effect=socket_effect):
            return service.network_proof()

    def test_disabled_kernel_selftest_keeps_ipv4_and_child_controls(self):
        result = subprocess.run([sys.executable, '-I', '-B', __file__, '--disabled-kernel-selftest'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        checks = json.loads(result.stdout)
        for data in [checks, checks['child_inherits_filter']]:
            for key in ['public_ipv4', 'private_ipv4_fixture', 'loopback', 'udp_dns', 'raw', 'packet']:
                self.assertEqual(data[key], 'EPERM')
            self.assertEqual(data['public_ipv6'], 'unavailable:EAFNOSUPPORT (socket creation)')

    def test_missing_table_requires_kernel_family_unavailable(self):
        result = self.proof(socket_effect=OSError(errno.EAFNOSUPPORT, 'synthetic disabled family'))
        self.assertIsNone(result['ipv6_routes'])
        self.assertEqual(result['ipv6_status'], 'unavailable:EAFNOSUPPORT (socket creation)')

    def test_missing_table_with_available_ipv6_is_rejected(self):
        connection = Mock()
        with self.assertRaisesRegex(RuntimeError, 'route table cannot be verified'):
            self.proof(socket_effect=lambda *args: connection)
        connection.close.assert_called_once()
        connection.connect.assert_not_called()

    def test_other_ipv6_socket_errors_are_not_treated_as_disabled(self):
        with self.assertRaises(OSError) as raised:
            self.proof(socket_effect=OSError(errno.ENOMEM, 'synthetic allocation failure'))
        self.assertEqual(raised.exception.errno, errno.ENOMEM)

    def test_unavailable_ipv4_is_not_treated_as_optional(self):
        with patch.object(guard.socket, 'socket', side_effect=OSError(errno.EAFNOSUPPORT, 'synthetic')):
            with self.assertRaises(OSError):
                guard.negative_controls()

    def test_other_ipv6_control_errors_are_not_ignored(self):
        def construct(family, kind):
            if family == socket.AF_INET6:
                raise OSError(errno.ENOMEM, 'synthetic allocation failure')
            connection = Mock()
            connection.__enter__ = Mock(return_value=connection)
            connection.__exit__ = Mock(return_value=False)
            connection.connect.side_effect = OSError(errno.EPERM, 'synthetic blocked connect')
            return connection
        with patch.object(guard.socket, 'socket', side_effect=construct):
            with self.assertRaises(OSError) as raised:
                guard.negative_controls()
        self.assertEqual(raised.exception.errno, errno.ENOMEM)

    def test_unreadable_ipv6_table_is_rejected(self):
        def read(path, *args, **kwargs):
            if str(path) == '/proc/net/ipv6_route':
                raise PermissionError(errno.EACCES, 'synthetic permission error')
            return proc_read(path)
        with self.assertRaises(PermissionError):
            self.proof(read=read)

    def test_external_ipv6_route_is_rejected(self):
        def read(path, *args, **kwargs):
            return 'synthetic route eth0\n' if str(path) == '/proc/net/ipv6_route' else proc_read(path)
        with self.assertRaisesRegex(RuntimeError, 'external IPv6 routes'):
            self.proof(read=read)

    def test_external_ipv4_route_is_rejected(self):
        def read(path, *args, **kwargs):
            return 'header\nsynthetic route\n' if str(path) == '/proc/net/route' else proc_read(path)
        with self.assertRaisesRegex(RuntimeError, 'Refusing host network'):
            self.proof(read=read)

    def test_available_ipv6_table_is_checked_without_socket_probe(self):
        def read(path, *args, **kwargs):
            return 'synthetic route lo\n' if str(path) == '/proc/net/ipv6_route' else proc_read(path)
        result = self.proof(read=read, socket_effect=AssertionError('unnecessary socket probe'))
        self.assertEqual(result['ipv6_status'], 'route-table-checked')


if __name__ == '__main__':
    if sys.argv[1:] == ['--disabled-kernel-selftest']:
        simulate_no_ipv6()
        os.execv(sys.executable, [sys.executable, '-I', '-B', str(ROOT / 'tools/egress_guard.py'), '--self-test'])
    else:
        unittest.main()
