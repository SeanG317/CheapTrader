"""Read-only Windows named-pipe receiver for the MQL5 heartbeat probe.

Not a trading service. No commands, account data, orders or writes to the EA.
No explicit pipe ACL/authentication yet: never use this as a production bridge.
"""
from __future__ import annotations

import ctypes
import json
import math
import os
import re
import time
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import datetime, timezone

PIPE_NAME = r"\\.\pipe\CheapTraderEAProbe"
HEARTBEAT_TIMEOUT_S = 8.0
CONNECT_TIMEOUT_S = 30.0
MAX_FRAME = 128
FRAME = re.compile(rb"CTEA1\|PING\|([0-9]{1,10})\|([0-9]{1,10})\n")


def parse_frame(frame: bytes) -> tuple[int, int] | None:
    """Accept only a bounded, observation-only protocol message."""
    if len(frame) > MAX_FRAME:
        return None
    match = FRAME.fullmatch(frame)
    return (int(match.group(1)), int(match.group(2))) if match else None


def log_event(name: str, **fields) -> None:
    print(json.dumps({
        "utc": datetime.now(timezone.utc).isoformat(),
        "event": name, **fields
    }, separators=(",", ":"), sort_keys=True), flush=True)


class ProtocolViolation(ValueError):
    """Drop this connection, not the entire pipe server."""


@dataclass
class HeartbeatMonitor:
    """Platform-neutral frame parser + measurable per-connection heartbeat state."""

    connected_at: float
    pending: bytearray = field(default_factory=bytearray)
    last_at: float | None = None
    last_seq: int | None = None
    heartbeats: int = 0
    missing_sequences: int = 0
    max_gap_s: float = 0.0
    largest_seq_gap: int = 0

    def deadline(self, timeout_s: float = HEARTBEAT_TIMEOUT_S) -> float:
        return (self.last_at if self.last_at is not None else self.connected_at) + timeout_s

    def feed(
        self, data: bytes, now: float, *,
        on_heartbeat: Callable[[dict], None] | None = None,
    ) -> list[dict]:
        """Decode frames in order, committing each valid event before later errors.

        A byte-stream read can combine valid and invalid frames. Emit accepted
        frames immediately so a later ProtocolViolation cannot erase their log.
        The returned list remains available for pure parser tests.
        """
        self.pending.extend(data)
        received: list[dict] = []
        while b"\n" in self.pending:
            end = self.pending.index(10) + 1
            frame = bytes(self.pending[:end])
            del self.pending[:end]
            parsed = parse_frame(frame)
            if parsed is None:
                raise ProtocolViolation("malformed_frame")
            seq, trade_events = parsed
            if self.last_seq is not None and seq <= self.last_seq:
                raise ProtocolViolation("duplicate_or_backward_sequence")
            missing = 0 if self.last_seq is None else seq - self.last_seq - 1
            gap = None if self.last_at is None else max(0.0, now - self.last_at)
            self.missing_sequences += missing
            self.largest_seq_gap = max(self.largest_seq_gap, missing)
            if gap is not None:
                self.max_gap_s = max(self.max_gap_s, gap)
            self.last_seq = seq
            self.last_at = now
            self.heartbeats += 1
            entry = {
                "seq": seq, "trade_events_observed": trade_events,
                "missing_sequences": missing, "gap_seconds": round(gap, 3) if gap is not None else None,
            }
            received.append(entry)
            if on_heartbeat is not None:
                on_heartbeat(entry)
        if len(self.pending) > MAX_FRAME:
            raise ProtocolViolation("unfinished_frame_too_long")
        return received

    def summary(self, now: float, reason: str) -> dict:
        return {
            "reason": reason, "duration_seconds": round(now - self.connected_at, 3),
            "heartbeats": self.heartbeats, "missing_sequences": self.missing_sequences,
            "largest_seq_gap": self.largest_seq_gap,
            "max_heartbeat_gap_seconds": round(self.max_gap_s, 3),
            "last_sequence": self.last_seq,
            "seconds_since_last_heartbeat": (
                None if self.last_at is None else round(now - self.last_at, 3)
            ),
        }


# Windows OVERLAPPED layout: two ULONG_PTRs, two DWORDs and one HANDLE.
# Offsets/packing must match winnt.h on 32-bit and 64-bit Python.
class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


class WindowsPipe:
    # Match MetaQuotes' FILE_READ|FILE_WRITE pipe client: Win32 requires duplex.
    # Transport capability is duplex, but THIS receiver never sends bytes.
    PIPE_ACCESS_DUPLEX = 0x00000003
    FILE_FLAG_OVERLAPPED = 0x40000000
    PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
    ERROR_IO_PENDING = 997
    ERROR_PIPE_CONNECTED = 535
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("Pipe transport requires Windows.")
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        a = self.api
        a.CreateNamedPipeW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
            wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p
        ]
        a.CreateNamedPipeW.restype = wintypes.HANDLE
        a.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        a.CreateEventW.restype = wintypes.HANDLE
        a.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED)]
        a.ConnectNamedPipe.restype = wintypes.BOOL
        a.ReadFile.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(OVERLAPPED)
        ]
        a.ReadFile.restype = wintypes.BOOL
        a.GetOverlappedResult.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(OVERLAPPED),
            ctypes.POINTER(wintypes.DWORD), wintypes.BOOL
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
        """Wait with a real deadline; drain canceled I/O before local buffers die."""
        milliseconds = max(0, math.ceil(seconds * 1000))
        status = self.api.WaitForSingleObject(ov.hEvent, milliseconds)
        if status != self.WAIT_OBJECT_0:
            # CancelIoEx requests cancellation but is NOT a synchronous drain.
            self.api.CancelIoEx(handle, ctypes.byref(ov))
            completed = wintypes.DWORD()
            self.api.GetOverlappedResult(handle, ctypes.byref(ov), ctypes.byref(completed), True)
            if status == self.WAIT_TIMEOUT:
                raise TimeoutError("pipe_io_deadline")
            raise ctypes.WinError(ctypes.get_last_error())
        transferred = wintypes.DWORD()
        if not self.api.GetOverlappedResult(handle, ctypes.byref(ov), ctypes.byref(transferred), False):
            raise ctypes.WinError(ctypes.get_last_error())
        return transferred.value

    def new_pipe(self):
        handle = self.api.CreateNamedPipeW(
            PIPE_NAME, self.PIPE_ACCESS_DUPLEX | self.FILE_FLAG_OVERLAPPED,
            self.PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, None,
        )
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

    def read(self, handle, timeout: float) -> bytes:
        event = self._event()
        try:
            ov = OVERLAPPED()
            ov.hEvent = event
            buffer = ctypes.create_string_buffer(512)
            length = wintypes.DWORD()
            if self.api.ReadFile(handle, buffer, len(buffer), ctypes.byref(length), ctypes.byref(ov)):
                return buffer.raw[:length.value]
            error = ctypes.get_last_error()
            if error != self.ERROR_IO_PENDING:
                raise ctypes.WinError(error)
            received = self._await(handle, ov, timeout)
            return buffer.raw[:received]
        finally:
            self.api.CloseHandle(event)

    def close_pipe(self, handle) -> None:
        self.api.DisconnectNamedPipe(handle)
        self.api.CloseHandle(handle)


def receive_connection(read_chunk, clock=time.monotonic, timeout_s: float = HEARTBEAT_TIMEOUT_S,
                       emit=log_event) -> dict:
    """Handle one client only; return reason so the *server* always reaccepts."""
    monitor = HeartbeatMonitor(connected_at=clock())
    reason = "client_disconnected"
    try:
        while True:
            remaining = monitor.deadline(timeout_s) - clock()
            if remaining <= 0:
                raise TimeoutError("heartbeat_deadline")
            data = read_chunk(remaining)
            if not data:
                break
            now = clock()
            if now > monitor.deadline(timeout_s):
                raise TimeoutError("heartbeat_deadline")
            monitor.feed(data, now, on_heartbeat=lambda entry: emit("heartbeat", **entry))
    except ProtocolViolation as exc:
        reason = str(exc)
    except TimeoutError:
        reason = "heartbeat_deadline"
    except OSError as exc:
        reason = f"pipe_io_error:{(getattr(exc, 'winerror', None) or getattr(exc, 'errno', None) or 'unknown')}"
    summary = monitor.summary(clock(), reason)
    emit("client_disconnected", **summary)
    return summary


def serve(pipe, max_clients: int | None = None, *, emit=log_event, clock=time.monotonic) -> None:
    """Accept independent clients. Faults in one connection never end the server.

    max_clients is strictly a test hook: production accepts without a limit.
    """
    served = 0
    while max_clients is None or served < max_clients:
        handle = pipe.new_pipe()
        try:
            try:
                pipe.accept(handle)
            except TimeoutError:
                # No client yet: accept was canceled and drained before handle cleanup.
                continue
            except OSError as exc:
                emit("accept_failed", winerror=getattr(exc, "winerror", None))
                continue
            emit("client_connected")
            receive_connection(lambda seconds: pipe.read(handle, seconds),
                               clock=clock, emit=emit)
            served += 1
        finally:
            pipe.close_pipe(handle)


def run() -> None:
    pipe = WindowsPipe()
    log_event("started", pipe=PIPE_NAME, mode="read_only",
              heartbeat_timeout_seconds=HEARTBEAT_TIMEOUT_S)
    try:
        serve(pipe)
    except KeyboardInterrupt:
        log_event("stopped")


if __name__ == "__main__":
    run()
