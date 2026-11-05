"""Independent Windows Named Pipe receiver for authenticated EA snapshots.

This process does not import MetaTrader5 or CheapTrader's broker adapter. The
EA is the only G1 broker-state source. This host only exchanges authenticated
CHALLENGE/AUTH/AUTH_OK/SNAPSHOT/SNAPSHOT_ACK messages and never sends a trade
command.
"""
from __future__ import annotations

import argparse
import ctypes
import math
import os
import time
from ctypes import wintypes
from pathlib import Path

from credentials import (
    default_credential_path,
    load,
    matches_current,
    provision,
    revoke,
)
from protocol import (
    ProtocolError,
)
from session_host import log_event
from session_host import serve_transport as _serve_transport
from state_store import SnapshotStore
from transport import RecoverableAcceptError
from windows_security import current_logon_pipe_security

PIPE_NAME = r"\\.\pipe\CheapTraderEAG1"
HEARTBEAT_TIMEOUT_S = 8.0
CONNECT_TIMEOUT_S = 30.0
RECOVERABLE_CONNECT_ERRORS = {109, 232, 233}  # BROKEN_PIPE, NO_DATA, PIPE_NOT_CONNECTED


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


class WindowsPipe:
    PIPE_ACCESS_DUPLEX = 0x00000003
    FILE_FLAG_OVERLAPPED = 0x40000000
    PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
    ERROR_IO_PENDING = 997
    ERROR_PIPE_CONNECTED = 535
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(self, pipe_name: str = PIPE_NAME):
        if os.name != "nt":
            raise RuntimeError("The G1 pipe host requires Windows.")
        self.pipe_name = pipe_name
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        a = self.api
        a.CreateNamedPipeW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
            wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        ]
        a.CreateNamedPipeW.restype = wintypes.HANDLE
        a.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        a.CreateEventW.restype = wintypes.HANDLE
        a.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED)]
        a.ConnectNamedPipe.restype = wintypes.BOOL
        a.ReadFile.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(OVERLAPPED),
        ]
        a.ReadFile.restype = wintypes.BOOL
        a.WriteFile.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(OVERLAPPED),
        ]
        a.WriteFile.restype = wintypes.BOOL
        a.GetOverlappedResult.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(OVERLAPPED),
            ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
        ]
        a.GetOverlappedResult.restype = wintypes.BOOL
        a.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED)]
        a.CancelIoEx.restype = wintypes.BOOL
        a.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        a.WaitForSingleObject.restype = wintypes.DWORD
        a.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
        a.DisconnectNamedPipe.restype = wintypes.BOOL
        a.CloseHandle.argtypes = [wintypes.HANDLE]
        a.CloseHandle.restype = wintypes.BOOL

    def _event(self):
        event = self.api.CreateEventW(None, True, False, None)
        if not event:
            raise ctypes.WinError(ctypes.get_last_error())
        return event

    def _await(self, handle, ov: OVERLAPPED, seconds: float) -> int:
        status = self.api.WaitForSingleObject(ov.hEvent, max(0, math.ceil(seconds * 1000)))
        if status != self.WAIT_OBJECT_0:
            wait_error = ctypes.get_last_error()
            self.api.CancelIoEx(handle, ctypes.byref(ov))
            transferred = wintypes.DWORD()
            self.api.GetOverlappedResult(handle, ctypes.byref(ov), ctypes.byref(transferred), True)
            if status == self.WAIT_TIMEOUT:
                raise TimeoutError("pipe_io_deadline")
            raise ctypes.WinError(wait_error)
        transferred = wintypes.DWORD()
        if not self.api.GetOverlappedResult(handle, ctypes.byref(ov), ctypes.byref(transferred), False):
            raise ctypes.WinError(ctypes.get_last_error())
        return transferred.value

    def new_pipe(self):
        security = current_logon_pipe_security()
        try:
            handle = self.api.CreateNamedPipeW(
                self.pipe_name,
                self.PIPE_ACCESS_DUPLEX | self.FILE_FLAG_OVERLAPPED,
                self.PIPE_REJECT_REMOTE_CLIENTS,
                1, 65536, 65536, 0, ctypes.byref(security.attributes),
            )
        finally:
            security.close()
        if not handle or handle == self.INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def new_session(self):
        return self.new_pipe()

    def accept(self, handle, timeout: float = CONNECT_TIMEOUT_S) -> None:
        event = self._event()
        try:
            ov = OVERLAPPED()
            ov.hEvent = event
            if self.api.ConnectNamedPipe(handle, ctypes.byref(ov)):
                return
            error = ctypes.get_last_error()
            if error == self.ERROR_PIPE_CONNECTED:
                return
            if error != self.ERROR_IO_PENDING:
                if error in RECOVERABLE_CONNECT_ERRORS:
                    raise RecoverableAcceptError(error, f"pipe_accept_client_abort:{error}")
                raise ctypes.WinError(error)
            self._await(handle, ov, timeout)
        finally:
            self.api.CloseHandle(event)

    def _transfer(self, handle, data_or_size, *, write: bool, timeout: float):
        event = self._event()
        try:
            ov = OVERLAPPED()
            ov.hEvent = event
            if write:
                data = data_or_size
                buffer = ctypes.create_string_buffer(data)
                size = len(data)
                transferred = wintypes.DWORD()
                ok = self.api.WriteFile(handle, buffer, size, ctypes.byref(transferred), ctypes.byref(ov))
            else:
                size = data_or_size
                buffer = ctypes.create_string_buffer(size)
                transferred = wintypes.DWORD()
                ok = self.api.ReadFile(handle, buffer, size, ctypes.byref(transferred), ctypes.byref(ov))
            if ok:
                count = transferred.value
            else:
                error = ctypes.get_last_error()
                if error != self.ERROR_IO_PENDING:
                    if not write and error in (109, 232):  # BROKEN_PIPE / NO_DATA
                        return b""
                    raise ctypes.WinError(error)
                count = self._await(handle, ov, timeout)
            return count if write else buffer.raw[:count]
        finally:
            self.api.CloseHandle(event)

    def read(self, handle, timeout: float) -> bytes:
        return self._transfer(handle, 4096, write=False, timeout=timeout)

    def write(self, handle, data: bytes, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        offset = 0
        while offset < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("pipe_write_deadline")
            count = self._transfer(handle, data[offset:], write=True, timeout=remaining)
            if count <= 0:
                raise OSError(f"short_pipe_write:{offset}/{len(data)}")
            offset += count

    def close_pipe(self, handle) -> None:
        self.api.DisconnectNamedPipe(handle)
        self.api.CloseHandle(handle)

    def close_session(self, handle) -> None:
        self.close_pipe(handle)


def serve_transport(pipe: WindowsPipe, key: bytes, login: int, server: str,
                    max_clients: int | None = None, *, emit=log_event,
                    store: SnapshotStore | None = None,
                    credential_path: Path | None = None,
                    handshake_timeout_s: float = CONNECT_TIMEOUT_S,
                    heartbeat_timeout_s: float = HEARTBEAT_TIMEOUT_S) -> None:
    if store is None:
        raise ProtocolError("durable_snapshot_store_required")
    return _serve_transport(
        pipe, key, login, server, max_clients, emit=emit, store=store,
        credential_path=credential_path, credential_check=matches_current,
        handshake_timeout_s=handshake_timeout_s, stale_timeout_s=heartbeat_timeout_s,
    )


# Existing Pipe-specific test and CLI entry points remain compatible.
serve = serve_transport


def run() -> None:
    parser = argparse.ArgumentParser(description="CheapTrader G1 read-only MT5 EA pipe host")
    parser.add_argument("action", choices=("provision", "revoke", "serve"))
    parser.add_argument("--credential-file", type=os.path.abspath)
    parser.add_argument("--state-file", type=os.path.abspath)
    parser.add_argument("--login", type=int)
    parser.add_argument("--server")
    args = parser.parse_args()
    credential_path = args.credential_file or default_credential_path()
    if args.action == "provision":
        if args.login is None or not args.server:
            parser.error("provision requires --login and --server")
        one_time_key = provision(credential_path, args.login, args.server)
        print("Provisioned encrypted host credential. Enter this once in the demo EA's InpSharedKeyHex.")
        print("Do not save the EA inputs as a .set file or paste the key into logs/issues.")
        print(one_time_key, flush=True)
        return
    if args.action == "revoke":
        existed = revoke(credential_path)
        log_event("credential_revoked", credential_file=str(credential_path), existed=existed)
        return
    credential = load(credential_path)
    state_path = args.state_file or str(credential_path) + ".state.dpapi"
    log_event("started", pipe=PIPE_NAME, mode="authenticated_read_only",
              account_login=credential["login"], account_server=credential["server"],
              credential_file=str(credential_path))
    try:
        serve_transport(WindowsPipe(), bytes.fromhex(credential["key_hex"]), credential["login"],
              credential["server"], store=SnapshotStore(
                  Path(state_path), credential["login"], credential["server"]
              ), credential_path=credential_path)
    except KeyboardInterrupt:
        log_event("stopped")


if __name__ == "__main__":
    run()
