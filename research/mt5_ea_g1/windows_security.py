"""Windows named-pipe DACL helpers for the isolated G1 prototype.

The descriptor grants SYSTEM and Administrators full control, and grants the
current interactive logon SID only the explicit read/write/synchronization
rights required by the MT5 client. The append/pipe-instance bit is present in
the documented generic-write mapping; it is not hidden behind GENERIC_WRITE.
The pipe must additionally set PIPE_REJECT_REMOTE_CLIENTS.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from dataclasses import dataclass

TOKEN_QUERY = 0x0008
TOKEN_LOGON_SID = 28
SE_GROUP_LOGON_ID = 0xC0000000
ERROR_INSUFFICIENT_BUFFER = 122

# FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE, expressed explicitly.
# FILE_APPEND_DATA aliases FILE_CREATE_PIPE_INSTANCE for named pipes.
PIPE_CLIENT_RIGHTS = 0x0012019F


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class TOKEN_GROUPS(ctypes.Structure):
    _fields_ = [("GroupCount", wintypes.DWORD), ("Groups", SID_AND_ATTRIBUTES * 1)]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


@dataclass
class PipeSecurity:
    """Owns the Win32 descriptor and SECURITY_ATTRIBUTES lifetime."""

    attributes: SECURITY_ATTRIBUTES
    descriptor: ctypes.c_void_p
    advapi32: object
    kernel32: object

    def close(self) -> None:
        if self.descriptor:
            self.kernel32.LocalFree(self.descriptor)
            self.descriptor = ctypes.c_void_p()


def _win32():
    if os.name != "nt":
        raise OSError("The MT5 G1 named-pipe host requires Windows.")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return advapi32, kernel32


def _current_logon_sid(advapi32, kernel32) -> str:
    token = wintypes.HANDLE()
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, TOKEN_LOGON_SID, None, 0, ctypes.byref(needed))
        if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER or not needed.value:
            raise ctypes.WinError(ctypes.get_last_error())
        storage = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token, TOKEN_LOGON_SID, storage, needed.value, ctypes.byref(needed)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        groups = ctypes.cast(storage, ctypes.POINTER(TOKEN_GROUPS)).contents
        first = ctypes.addressof(groups) + TOKEN_GROUPS.Groups.offset
        stride = ctypes.sizeof(SID_AND_ATTRIBUTES)
        for index in range(groups.GroupCount):
            item = SID_AND_ATTRIBUTES.from_address(first + index * stride)
            if item.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID:
                sid_text = wintypes.LPWSTR()
                advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
                advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
                if not advapi32.ConvertSidToStringSidW(item.Sid, ctypes.byref(sid_text)):
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    return sid_text.value
                finally:
                    kernel32.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        raise OSError("The current access token has no logon SID; refusing a broad named-pipe ACL.")
    finally:
        kernel32.CloseHandle(token)


def current_logon_pipe_security() -> PipeSecurity:
    """Build a non-inheritable DACL scoped to the current Windows logon SID."""
    advapi32, kernel32 = _win32()
    sid = _current_logon_sid(advapi32, kernel32)
    sddl = f"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{PIPE_CLIENT_RIGHTS:08X};;;{sid})"
    descriptor = ctypes.c_void_p()
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    attrs = SECURITY_ATTRIBUTES(
        ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False
    )
    return PipeSecurity(attrs, descriptor, advapi32, kernel32)
