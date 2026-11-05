from __future__ import annotations

import ctypes
import os
import sys
import unittest
import uuid
from ctypes import wintypes
from pathlib import Path

if os.name == "nt":
    ROOT = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(ROOT / "research" / "mt5_ea_g1"))
    from pipe_host import WindowsPipe
    from windows_security import _current_logon_sid


@unittest.skipUnless(os.name == "nt", "Requires Windows kernel named pipes and access tokens")
class NativePipeAclTests(unittest.TestCase):
    def setUp(self):
        self.pipe_name = r"\\.\pipe\CheapTraderEAG1AclTest" + uuid.uuid4().hex
        self.pipe = WindowsPipe(self.pipe_name)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.handles = []
        self.local_allocations = []
        self.kernel.GetCurrentProcess.argtypes = []
        self.kernel.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        self.kernel.CreateFileW.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel.LocalFree.restype = ctypes.c_void_p
        self.advapi.GetSecurityInfo.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.advapi.GetSecurityInfo.restype = wintypes.DWORD
        self.advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD),
        ]
        self.advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
        self.advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        self.advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
        self.advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        self.advapi.OpenProcessToken.restype = wintypes.BOOL
        self.advapi.CreateRestrictedToken.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        self.advapi.CreateRestrictedToken.restype = wintypes.BOOL
        self.advapi.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
        self.advapi.ImpersonateLoggedOnUser.restype = wintypes.BOOL
        self.advapi.RevertToSelf.argtypes = []
        self.advapi.RevertToSelf.restype = wintypes.BOOL

    def tearDown(self):
        for handle in self.handles:
            self.kernel.CloseHandle(handle)
        for pointer in self.local_allocations:
            self.kernel.LocalFree(pointer)

    def _open_client(self, access=0xC0000000):
        handle = self.kernel.CreateFileW(self.pipe_name, access, 0, None, 3, 0, None)
        if not handle or handle == ctypes.c_void_p(-1).value:
            return None, ctypes.get_last_error()
        self.handles.append(handle)
        return handle, 0

    def _actual_pipe_sddl(self, handle):
        descriptor = ctypes.c_void_p()
        status = self.advapi.GetSecurityInfo(
            handle, 6, 0x4, None, None, None, None, ctypes.byref(descriptor)
        )
        if status:
            raise ctypes.WinError(status)
        try:
            text = wintypes.LPWSTR()
            if not self.advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, 0x4, ctypes.byref(text), None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                return text.value
            finally:
                self.kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        finally:
            self.kernel.LocalFree(descriptor)

    def _restricted_token_without_pipe_allow_sids(self):
        process = self.kernel.GetCurrentProcess()
        token = wintypes.HANDLE()
        if not self.advapi.OpenProcessToken(process, 0x0002 | 0x0008 | 0x0004, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_strings = [_current_logon_sid(self.advapi, self.kernel), "S-1-5-32-544"]
        sid_ptrs = []
        class SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]
        array = (SID_AND_ATTRIBUTES * len(sid_strings))()
        for index, sid_text in enumerate(sid_strings):
            sid = ctypes.c_void_p()
            if not self.advapi.ConvertStringSidToSidW(sid_text, ctypes.byref(sid)):
                raise ctypes.WinError(ctypes.get_last_error())
            sid_ptrs.append(sid)
            self.local_allocations.append(sid)
            array[index] = SID_AND_ATTRIBUTES(sid, 0)
        restricted = wintypes.HANDLE()
        if not self.advapi.CreateRestrictedToken(
            token, 0x1, len(sid_strings), ctypes.cast(array, ctypes.c_void_p),
            0, None, 0, None, ctypes.byref(restricted),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        self.handles.extend([token, restricted])
        return restricted

    def test_actual_pipe_descriptor_is_logon_scoped_and_remote_rejection_is_set(self):
        server = self.pipe.new_pipe()
        self.handles.append(server)
        sddl = self._actual_pipe_sddl(server)
        logon_sid = _current_logon_sid(self.advapi, self.kernel)
        self.assertIn(logon_sid, sddl)
        self.assertNotIn(";;;WD)", sddl)
        self.assertNotIn(";;;AN)", sddl)
        self.assertEqual(self.pipe.PIPE_REJECT_REMOTE_CLIENTS, 0x8)

    def test_native_acl_allows_current_logon_and_denies_token_without_allowed_sids(self):
        server = self.pipe.new_pipe()
        self.handles.append(server)
        token = self._restricted_token_without_pipe_allow_sids()
        denied_handle = ctypes.c_void_p()
        if not self.advapi.ImpersonateLoggedOnUser(token):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            denied_handle, error = self._open_client()
        finally:
            self.advapi.RevertToSelf()
        if denied_handle:
            self.fail("A token without the logon SID/Admin ACE connected to the real pipe ACL")
        self.assertEqual(error, 5, f"Expected ERROR_ACCESS_DENIED, got WinError={error}")

        allowed, error = self._open_client()
        self.assertIsNotNone(allowed, f"Current logon SID could not open pipe; WinError={error}")
        self.pipe.accept(server, timeout=2)
