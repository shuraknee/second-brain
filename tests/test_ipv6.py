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




class IPv6Tests(unittest.TestCase):
    def test_complete_seccomp_proof_accepts_unavailable_ipv6(self):
        values = {key: 'EPERM' for key in ['public_ipv4', 'private_ipv4_fixture', 'loopback', 'udp_dns', 'raw', 'packet']}
        values['public_ipv6'] = 'unavailable:EAFNOSUPPORT (socket creation)'
        service.validate_guard_checks(dict(values, child_inherits_filter=dict(values)))

    def test_missing_child_filter_proof_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            service.validate_guard_checks({'public_ipv4': 'EPERM'})

    def test_unblocked_ipv4_is_rejected_even_without_ipv6(self):
        values = {key: 'EPERM' for key in ['public_ipv4', 'private_ipv4_fixture', 'loopback', 'udp_dns', 'raw', 'packet']}
        values['public_ipv6'] = 'unavailable:EAFNOSUPPORT (socket creation)'
        values['loopback'] = 'allowed'
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            service.validate_guard_checks(dict(values, child_inherits_filter=dict(values)))

    def test_disabled_kernel_selftest_keeps_ipv4_and_child_controls(self):
        result = subprocess.run([sys.executable, '-I', '-B', __file__, '--disabled-kernel-selftest'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        checks = json.loads(result.stdout)
        for data in [checks, checks['child_inherits_filter']]:
            for key in ['public_ipv4', 'private_ipv4_fixture', 'loopback', 'udp_dns', 'raw', 'packet']:
                self.assertEqual(data[key], 'EPERM')
            self.assertEqual(data['public_ipv6'], 'unavailable:EAFNOSUPPORT (socket creation)')




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






if __name__ == '__main__':
    if sys.argv[1:] == ['--disabled-kernel-selftest']:
        simulate_no_ipv6()
        os.execv(sys.executable, [sys.executable, '-I', '-B', str(ROOT / 'tools/egress_guard.py'), '--self-test'])
    else:
        unittest.main()
