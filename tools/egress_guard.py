#!/usr/bin/env python3
"""Python 3.9 / Linux x86_64: inherited no-new-connections filter.

This guards the SERVER. The local fixed-upstream proxy has a separate role.
No downloading, no user namespace creation, no AppArmor assumptions here.
Filesystem/mount isolation belongs to the selected service profile.
"""
import ctypes as C
import errno
import json
import os
import platform
import resource
import socket
import subprocess
import sys

ALLOW = 0x7fff0000
DENY = 0x50000 | errno.EPERM


class Cmp(C.Structure):
    _fields_ = [('arg', C.c_uint), ('op', C.c_int),
                ('a', C.c_uint64), ('b', C.c_uint64)]


def apply():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise RuntimeError('Only Linux x86_64 is validated')
    libc = C.CDLL(None, use_errno=True)
    sec = C.CDLL('libseccomp.so.2', use_errno=True)
    sec.seccomp_init.argtypes = [C.c_uint32]
    sec.seccomp_init.restype = C.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes = [C.c_char_p]
    sec.seccomp_rule_add_array.argtypes = [C.c_void_p, C.c_uint32, C.c_int,
                                         C.c_uint, C.POINTER(Cmp)]
    sec.seccomp_load.argtypes = [C.c_void_p]
    sec.seccomp_release.argtypes = [C.c_void_p]
    if libc.prctl(38, 1, 0, 0, 0) < 0:
        raise OSError(C.get_errno(), 'PR_SET_NO_NEW_PRIVS failed')
    ctx = sec.seccomp_init(ALLOW)
    if not ctx:
        raise RuntimeError('seccomp_init failed')
    def deny(name, *conditions):
        number = sec.seccomp_syscall_resolve_name(name.encode())
        if number < 0:
            raise RuntimeError('Unknown syscall: ' + name)
        result = sec.seccomp_rule_add_array(ctx, DENY, number, len(conditions),
                                           (Cmp * len(conditions))(*conditions))
        if result < 0:
            raise RuntimeError('seccomp rule %s: %d' % (name, result))
    try:
        for name in ['connect', 'sendmsg', 'sendmmsg', 'io_uring_setup', 'ptrace',
                     'process_vm_readv', 'process_vm_writev', 'pidfd_getfd',
                     'pidfd_send_signal', 'kill', 'tkill', 'bpf', 'setns',
                     'unshare', 'mount', 'open_by_handle_at']:
            deny(name)
        for family in range(47):
            if family not in [1, 2, 10]:
                deny('socket', Cmp(0, 4, family, 0))
        deny('socket', Cmp(0, 6, 46, 0))
        for kind in range(16):
            if kind != 1:
                deny('socket', Cmp(1, 7, 15, kind))
        deny('sendto', Cmp(4, 1, 0, 0))
        result = sec.seccomp_load(ctx)
        if result < 0:
            raise RuntimeError('seccomp_load failed: %d' % result)
    finally:
        sec.seccomp_release(ctx)


def negative_controls():
    checks = {}
    for name, family, address in [
        ('public_ipv4', socket.AF_INET, ('198.51.100.10', 443)),
        # Synthetic RFC1918 negative-control fixture, not a deployment address.
        ('private_ipv4_fixture', socket.AF_INET, ('10.255.255.254', 443)),
        ('loopback', socket.AF_INET, ('127.0.0.1', 9)),
        ('public_ipv6', socket.AF_INET6, ('2001:db8::10', 443)),
    ]:
        try:
            connection = socket.socket(family, socket.SOCK_STREAM)
        except OSError as error:
            # ipv6.disable=1 / a kernel without AF_INET6 is compatible with
            # IPv4 operation. This does not claim that connect was exercised.
            if family == socket.AF_INET6 and error.errno == errno.EAFNOSUPPORT:
                checks[name] = 'unavailable:EAFNOSUPPORT (socket creation)'
                continue
            raise
        with connection:
            try:
                connection.connect(address)
            except OSError as error:
                if error.errno != errno.EPERM:
                    raise AssertionError((name, error.errno))
            else:
                raise AssertionError('Unexpected allowed connect: ' + name)
        checks[name] = 'EPERM'
    for name, family, kind in [
        ('udp_dns', socket.AF_INET, socket.SOCK_DGRAM),
        ('raw', socket.AF_INET, socket.SOCK_RAW),
        ('packet', socket.AF_PACKET, socket.SOCK_RAW),
    ]:
        try:
            connection = socket.socket(family, kind)
        except OSError as error:
            if error.errno != errno.EPERM:
                raise AssertionError((name, error.errno))
        else:
            connection.close()
            raise AssertionError('Unexpected allowed socket: ' + name)
        checks[name] = 'EPERM'
    return checks


def main():
    arguments = sys.argv[1:]
    if arguments == ['--self-test']:
        # Fail closed before any network negative control is attempted.
        apply()
        checks = negative_controls()
        child = subprocess.run([sys.executable, '-I', '-B', __file__, '--child-test'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if child.returncode:
            raise RuntimeError(child.stderr)
        checks['child_inherits_filter'] = json.loads(child.stdout)
        print(json.dumps(checks, indent=2))
        return
    if arguments == ['--child-test']:
        print(json.dumps(negative_controls()))
        return
    if arguments[:1] != ['--'] or len(arguments) < 2:
        raise SystemExit('Usage: egress_guard.py --self-test | -- COMMAND [ARGS]')
    # No inherited network descriptors other than intentional stdio/journal.
    maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    os.closerange(3, min(maximum, 1048576))
    apply()
    print('SERVER_GUARD: seccomp=loaded no_new_privs=1 outgoing=deny pid=%d' % os.getpid(), flush=True)
    env = {key: value for key, value in os.environ.items()
           if key in ['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'RUST_LOG'] or key.startswith('SB_')}
    os.execvpe(arguments[1], arguments[1:], env)


if __name__ == '__main__':
    sys.excepthook = sys.__excepthook__
    main()
