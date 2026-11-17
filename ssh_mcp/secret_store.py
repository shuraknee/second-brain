"""Native per-user credential stores. No plaintext-file fallback or secret argv."""
import ctypes
import ctypes.util
import os
import shutil
import subprocess
import sys


class StoreError(Exception):
    pass


class SecretService:
    def __init__(self):
        self.tool = shutil.which('secret-tool')
        if not self.tool:
            raise StoreError('Linux requires an available Secret Service and secret-tool; no file fallback is used')

    def _run(self, operation, key, secret=None):
        args = [self.tool, operation]
        if operation == 'store':
            args += ['--label=Second Brain MCP']
        args += ['service', 'secondbrain-mcp', 'profile', key]
        try:
            result = subprocess.run(args, input=secret, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise StoreError('Secret Service operation failed or was cancelled') from None
        if result.returncode:
            if operation in ['lookup', 'clear'] and result.returncode == 1 and not result.stderr.strip():
                return None
            raise StoreError('Secret Service is unavailable, locked or access was denied')
        return result.stdout.rstrip(b'\n')

    def get(self, key):
        value = self._run('lookup', key)
        return value.decode('utf-8') if value else None

    def set(self, key, value):
        self._run('store', key, value.encode('utf-8'))

    def delete(self, key):
        self._run('clear', key)


class MacKeychain:
    NOT_FOUND = -25300

    def __init__(self):
        try:
            self.sec = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
            self.cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        except OSError:
            raise StoreError('macOS Keychain is unavailable') from None
        pointer = ctypes.c_void_p
        count = ctypes.c_uint32
        self.sec.SecKeychainFindGenericPassword.argtypes = [pointer, count, pointer, count, pointer,
                                                           ctypes.POINTER(count), ctypes.POINTER(pointer), ctypes.POINTER(pointer)]
        self.sec.SecKeychainAddGenericPassword.argtypes = [pointer, count, pointer, count, pointer, count, pointer, ctypes.POINTER(pointer)]
        self.sec.SecKeychainItemModifyAttributesAndData.argtypes = [pointer, pointer, count, pointer]
        self.sec.SecKeychainItemDelete.argtypes = [pointer]
        self.sec.SecKeychainItemFreeContent.argtypes = [pointer, pointer]
        self.cf.CFRelease.argtypes = [pointer]
        for name in ['SecKeychainFindGenericPassword', 'SecKeychainAddGenericPassword',
                     'SecKeychainItemModifyAttributesAndData', 'SecKeychainItemDelete', 'SecKeychainItemFreeContent']:
            getattr(self.sec, name).restype = ctypes.c_int32
        self.cf.CFRelease.restype = None
        self.service = b'org.secondbrain.mcp'

    def _find(self, key):
        account = key.encode('utf-8')
        size, data, item = ctypes.c_uint32(), ctypes.c_void_p(), ctypes.c_void_p()
        status = self.sec.SecKeychainFindGenericPassword(None, len(self.service), self.service,
            len(account), account, ctypes.byref(size), ctypes.byref(data), ctypes.byref(item))
        if status == self.NOT_FOUND:
            return None, None
        if status:
            raise StoreError('Keychain is locked, access was denied or the operation failed')
        try:
            secret = ctypes.string_at(data, size.value).decode('utf-8')
        finally:
            self.sec.SecKeychainItemFreeContent(None, data)
        return secret, item

    def get(self, key):
        value, item = self._find(key)
        if item:
            self.cf.CFRelease(item)
        return value

    def set(self, key, value):
        unused, item = self._find(key)
        encoded = value.encode('utf-8')
        try:
            if item:
                status = self.sec.SecKeychainItemModifyAttributesAndData(item, None, len(encoded), encoded)
            else:
                account = key.encode('utf-8')
                status = self.sec.SecKeychainAddGenericPassword(None, len(self.service), self.service,
                    len(account), account, len(encoded), encoded, None)
            if status:
                raise StoreError('Could not save credential to Keychain')
        finally:
            if item:
                self.cf.CFRelease(item)

    def delete(self, key):
        unused, item = self._find(key)
        if item:
            try:
                if self.sec.SecKeychainItemDelete(item):
                    raise StoreError('Could not delete Keychain credential')
            finally:
                self.cf.CFRelease(item)


class WindowsCredentials:
    def __init__(self):
        from ctypes import wintypes as w
        class Credential(ctypes.Structure):
            _fields_ = [('Flags', w.DWORD), ('Type', w.DWORD), ('TargetName', w.LPWSTR),
                ('Comment', w.LPWSTR), ('LastWritten', w.FILETIME), ('CredentialBlobSize', w.DWORD),
                ('CredentialBlob', ctypes.POINTER(ctypes.c_ubyte)), ('Persist', w.DWORD),
                ('AttributeCount', w.DWORD), ('Attributes', ctypes.c_void_p),
                ('TargetAlias', w.LPWSTR), ('UserName', w.LPWSTR)]
        self.Credential = Credential
        self.api = ctypes.WinDLL('Advapi32.dll', use_last_error=True)
        self.api.CredReadW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.POINTER(Credential))]
        self.api.CredReadW.restype = w.BOOL
        self.api.CredWriteW.argtypes = [ctypes.POINTER(Credential), w.DWORD]
        self.api.CredWriteW.restype = w.BOOL
        self.api.CredDeleteW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD]
        self.api.CredDeleteW.restype = w.BOOL
        self.api.CredFree.argtypes = [ctypes.c_void_p]
        self.api.CredFree.restype = None

    def _target(self, key):
        return 'SecondBrainMCP/' + key

    def get(self, key):
        pointer = ctypes.POINTER(self.Credential)()
        if not self.api.CredReadW(self._target(key), 1, 0, ctypes.byref(pointer)):
            if ctypes.get_last_error() == 1168:
                return None
            raise StoreError('Windows Credential Manager is unavailable or access was denied')
        try:
            return ctypes.string_at(pointer.contents.CredentialBlob,
                                    pointer.contents.CredentialBlobSize).decode('utf-8')
        finally:
            self.api.CredFree(pointer)

    def set(self, key, value):
        data = value.encode('utf-8')
        if len(data) > 2560:
            raise StoreError('Credential is too large')
        blob = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        credential = self.Credential()
        credential.Type = 1
        credential.TargetName = self._target(key)
        credential.UserName = 'SecondBrain'
        credential.CredentialBlobSize = len(data)
        credential.CredentialBlob = ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte))
        credential.Persist = 2  # Per-user, retained on this computer.
        if not self.api.CredWriteW(ctypes.byref(credential), 0):
            raise StoreError('Could not save credential to Windows Credential Manager')

    def delete(self, key):
        if not self.api.CredDeleteW(self._target(key), 1, 0) and ctypes.get_last_error() != 1168:
            raise StoreError('Could not delete Windows credential')


def open_store():
    if sys.platform == 'darwin':
        return MacKeychain()
    if os.name == 'nt':
        return WindowsCredentials()
    if sys.platform.startswith('linux'):
        return SecretService()
    raise StoreError('Unsupported operating system; no plaintext credential fallback is available')
