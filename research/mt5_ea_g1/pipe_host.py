"""Independent Windows Named Pipe receiver for authenticated EA snapshots.

This process does not import MetaTrader5 or CheapTrader's broker adapter. The
EA is the only G1 broker-state source. It accepts only HELLO/AUTH/SNAPSHOT
messages and never sends a trading command.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
import time
from collections.abc import Callable
from ctypes import wintypes
from datetime import UTC, datetime
from pathlib import Path

from credentials import default_credential_path, load, matches_current, provision, revoke
from protocol import (
    MAX_FRAME_BYTES,
    ProtocolError,
    decode_line,
    encode_line,
    make_auth_ok,
    make_challenge,
    validate_snapshot,
    verify_auth,
)
from state_store import SnapshotStore
from windows_security import current_logon_pipe_security

PIPE_NAME = r"\\.\pipe\CheapTraderEAG1"
HEARTBEAT_TIMEOUT_S = 8.0
CONNECT_TIMEOUT_S = 30.0
MAX_LINE = MAX_FRAME_BYTES


def log_event(name: str, **fields) -> None:
    print(json.dumps({
        "utc": datetime.now(UTC).isoformat(), "event": name, **fields,
    }, separators=(",", ":"), sort_keys=True), flush=True)


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
            self.api.CancelIoEx(handle, ctypes.byref(ov))
            transferred = wintypes.DWORD()
            self.api.GetOverlappedResult(handle, ctypes.byref(ov), ctypes.byref(transferred), True)
            if status == self.WAIT_TIMEOUT:
                raise TimeoutError("pipe_io_deadline")
            raise ctypes.WinError(ctypes.get_last_error())
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
        count = self._transfer(handle, data, write=True, timeout=timeout)
        if count != len(data):
            raise OSError(f"short_pipe_write:{count}/{len(data)}")

    def close_pipe(self, handle) -> None:
        self.api.DisconnectNamedPipe(handle)
        self.api.CloseHandle(handle)


class LineReader:
    def __init__(self, pipe: WindowsPipe, handle):
        self.pipe = pipe
        self.handle = handle
        self.pending = bytearray()

    def read(self, timeout_s: float) -> bytes:
        deadline = time.monotonic() + timeout_s
        while True:
            newline = self.pending.find(b"\n")
            if newline >= 0:
                line = bytes(self.pending[:newline + 1])
                del self.pending[:newline + 1]
                return line
            if len(self.pending) >= MAX_LINE:
                raise ProtocolError("frame_too_large")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("frame_deadline")
            chunk = self.pipe.read(self.handle, remaining)
            if not chunk:
                return b""
            self.pending.extend(chunk)
            if len(self.pending) > MAX_LINE:
                raise ProtocolError("frame_too_large")


def _receive_one(pipe: WindowsPipe, handle, key: bytes, login: int, server: str,
                 emit: Callable[..., None], store: SnapshotStore | None = None,
                 credential_path: Path | None = None) -> dict:
    def ensure_credential_current() -> None:
        if credential_path is not None and not matches_current(credential_path, key, login, server):
            raise ProtocolError("credential_revoked_or_rotated")

    stream = LineReader(pipe, handle)
    started = time.monotonic()
    ensure_credential_current()
    hello = decode_line(stream.read(CONNECT_TIMEOUT_S))
    challenge = make_challenge(key, hello)
    if (challenge.login, challenge.server) != (login, server):
        raise ProtocolError("unauthorized_account_identity")
    pipe.write(handle, encode_line(challenge.response))
    auth = decode_line(stream.read(CONNECT_TIMEOUT_S))
    ensure_credential_current()
    verify_auth(key, challenge, auth)
    pipe.write(handle, encode_line(make_auth_ok(key, challenge)))
    emit("authenticated", login=login, server=server, session_id=challenge.session_id)

    last_seq = 0
    accepted = 0
    last_receive = time.monotonic()
    while True:
        line = stream.read(max(0.0, HEARTBEAT_TIMEOUT_S - (time.monotonic() - last_receive)))
        if not line:
            raise OSError("client_disconnected")
        ensure_credential_current()
        message = decode_line(line)
        last_seq = validate_snapshot(key, message, challenge, last_seq)
        accepted += 1
        last_receive = time.monotonic()
        reconciliation = store.apply(message) if store is not None else None
        emit("snapshot", seq=last_seq, positions=len(message["positions"]),
             pending_orders=len(message["pending_orders"]), deals=len(message.get("deals", [])),
             login=login, server=server, reconciliation=reconciliation)
    # unreachable; keep shape explicit for static analyzers
    return {"duration_s": time.monotonic() - started, "snapshots": accepted}


def serve(pipe: WindowsPipe, key: bytes, login: int, server: str,
          max_clients: int | None = None, *, emit=log_event,
          store: SnapshotStore | None = None,
          credential_path: Path | None = None) -> None:
    served = 0
    while max_clients is None or served < max_clients:
        handle = pipe.new_pipe()
        try:
            try:
                pipe.accept(handle)
            except TimeoutError:
                continue
            emit("client_connected")
            try:
                _receive_one(pipe, handle, key, login, server, emit, store, credential_path)
            except (ProtocolError, OSError, TimeoutError) as exc:
                if store is not None:
                    store.mark_stale()
                emit("client_disconnected", reason=str(exc))
            served += 1
        finally:
            pipe.close_pipe(handle)


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
        serve(WindowsPipe(), bytes.fromhex(credential["key_hex"]), credential["login"],
              credential["server"], store=SnapshotStore(
                  Path(state_path), credential["login"], credential["server"]
              ), credential_path=credential_path)
    except KeyboardInterrupt:
        log_event("stopped")


if __name__ == "__main__":
    run()
