from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
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
        self.kernel.ReadFile.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
        ]
        self.kernel.ReadFile.restype = wintypes.BOOL
        self.kernel.WriteFile.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
        ]
        self.kernel.WriteFile.restype = wintypes.BOOL
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

    def test_real_short_client_error_232_does_not_stop_accept_loop(self):
        from pipe_host import serve
        from protocol import (
            ACCOUNT_FIELDS,
            ProtocolError,
            decode_line,
            encode_line,
            sign,
            verify_auth_ok,
            verify_server_challenge,
            verify_snapshot_ack,
        )

        class NativeTestStore:
            committed_cursor = None

            def apply(self, message):
                return {"positions_added": 0, "positions_removed": 0,
                        "orders_added": 0, "orders_removed": 0,
                        "deals_added": len(message["deals"])}

            def mark_stale(self):
                pass

            def mark_ipc_connected(self):
                pass

        owner = self

        class InjectedDisconnectPipe(WindowsPipe):
            def __init__(self, name):
                super().__init__(name)
                self.accept_calls = 0
                self.seen_no_data = False

            def accept(self, handle, timeout=30.0):
                self.accept_calls += 1
                if self.accept_calls == 1:
                    client = open_target(self.pipe_name)
                    owner.kernel.CloseHandle(client)
                    try:
                        return super().accept(handle, timeout=timeout)
                    except OSError as exc:
                        self.seen_no_data = getattr(exc, "winerror", None) == 232
                        raise

                connected = threading.Event()
                release = threading.Event()
                client_errors = []

                def read_line(client):
                    collected = bytearray()
                    while len(collected) <= 1_048_576:
                        data = ctypes.create_string_buffer(4096)
                        count = wintypes.DWORD()
                        if not owner.kernel.ReadFile(client, data, len(data), ctypes.byref(count), None):
                            raise ctypes.WinError(ctypes.get_last_error())
                        collected.extend(data.raw[:count.value])
                        newline = collected.find(b"\n")
                        if newline >= 0:
                            return bytes(collected[:newline + 1])
                    raise AssertionError("native pipe frame exceeded maximum length")

                def write_line(client, message):
                    raw = encode_line(message)
                    data = ctypes.create_string_buffer(raw, len(raw))
                    count = wintypes.DWORD()
                    if not owner.kernel.WriteFile(client, data, len(raw), ctypes.byref(count), None):
                        raise ctypes.WinError(ctypes.get_last_error())
                    if count.value != len(raw):
                        raise AssertionError("native client short write")

                def authenticate_and_close():
                    client = None
                    try:
                        client = open_target(self.pipe_name)
                        connected.set()
                        challenge_message = decode_line(read_line(client))
                        challenge = verify_server_challenge(
                            bytes(range(32)), challenge_message, login=12345678, server="Demo"
                        )
                        auth = sign(bytes(range(32)), {
                            "type": "AUTH", "protocol": "CTEA2",
                            "session_id": challenge.session_id,
                            "server_nonce": challenge.server_nonce,
                            "login": challenge.login,
                            "server_hex": challenge.server.encode().hex(),
                        })
                        write_line(client, auth)
                        auth_ok = decode_line(read_line(client))
                        verify_auth_ok(bytes(range(32)), challenge, auth_ok)
                        account = {name: "0" for name in ACCOUNT_FIELDS}
                        account.update({"login": 12345678, "server": "Demo", "currency": "USD",
                                        "name": "Demo", "company": "Broker",
                                        "stop_out_mode": "percent", "trade_mode": "demo",
                                        "margin_mode": "hedging", "fifo_close": False,
                                        "leverage": 100, "currency_digits": 2, "limit_orders": 200})
                        message = sign(bytes(range(32)), {
                            "type": "SNAPSHOT", "protocol": "CTEA2",
                            "session_id": challenge.session_id,
                            "server_nonce": challenge.server_nonce,
                            "login": challenge.login, "server_hex": challenge.server.encode().hex(),
                            "seq": 1, "unix_time": int(time.time()), "account": account,
                            "positions": [], "pending_orders": [], "deals": [], "deal_cursor": None,
                            "snapshot_id": f"{challenge.session_id}:1",
                            "source_counts": {"positions": 0, "pending_orders": 0,
                                              "history_selected": 0, "deals_after_cursor": 0},
                            "deals_more": False, "broker_connected": True,
                        })
                        write_line(client, message)
                        ack = decode_line(read_line(client))
                        verify_snapshot_ack(bytes(range(32)), challenge, ack, seq=1,
                                            snapshot_id=message["snapshot_id"], pending_cursor=None)
                    except (OSError, AssertionError, ProtocolError) as exc:
                        client_errors.append(exc)
                    finally:
                        if client:
                            owner.kernel.CloseHandle(client)

                connector = threading.Thread(target=authenticate_and_close, daemon=True)
                connector.start()
                try:
                    if not connected.wait(timeout=2):
                        raise TimeoutError("native client did not connect")
                    return super().accept(handle, timeout=timeout)
                finally:
                    release.set()
                    connector.join(timeout=5)
                    if client_errors:
                        raise client_errors[0]

        def open_target(path):
            client = self.kernel.CreateFileW(path, 0xC0000000, 0, None, 3, 0, None)
            if not client or client == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            return client

        pipe = InjectedDisconnectPipe(self.pipe_name + "Recovery")
        events = []
        serve(pipe, bytes(range(32)), 12345678, "Demo", max_clients=1,
              store=NativeTestStore(), emit=lambda event, **details: events.append((event, details)))
        self.assertTrue(pipe.seen_no_data, "expected real ConnectNamedPipe ERROR_NO_DATA (232)")
        self.assertGreaterEqual(pipe.accept_calls, 2)
        self.assertTrue(any(name == "transport_accept_recovered" and details.get("error_code") == 232
                            for name, details in events))
        self.assertTrue(any(name == "client_connected" for name, _ in events))
        self.assertTrue(any(name == "snapshot" for name, _ in events))
