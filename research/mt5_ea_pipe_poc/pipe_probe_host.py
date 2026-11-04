"""Windows named-pipe receiver for CheapTraderPipeProbe.mq5.

OBSERVATION ONLY. Does not expose orders, account credentials or commands.
Run only for isolated transport research; do not embed this probe in the app.
"""
from __future__ import annotations

import ctypes
import os
import re
from ctypes import wintypes

PIPE_NAME = r"\\.\pipe\CheapTraderEAProbe"
MAX_PENDING = 4096
FRAME = re.compile(rb"CTEA1\|PING\|([0-9]{1,10})\|([0-9]{1,10})\n")


def parse_frame(frame: bytes) -> tuple[int, int] | None:
    """Strictly parse one bounded, non-trading wire frame."""
    if len(frame) > 128:
        return None
    match = FRAME.fullmatch(frame)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def run() -> None:
    if os.name != "nt":
        raise SystemExit("This transport probe requires Windows.")

    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateNamedPipeW.restype = wintypes.HANDLE
    api.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, ctypes.c_void_p,
    ]
    api.ConnectNamedPipe.restype = wintypes.BOOL
    api.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    api.ReadFile.restype = wintypes.BOOL
    api.ReadFile.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    api.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    api.CloseHandle.argtypes = [wintypes.HANDLE]

    PIPE_ACCESS_INBOUND = 0x00000001
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_READMODE_BYTE = 0x00000000
    PIPE_WAIT = 0x00000000
    PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
    ERROR_PIPE_CONNECTED = 535
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    print("OBSERVATION ONLY: named-pipe heartbeat probe; no order endpoints.", flush=True)
    print("Run the MQL5 EA on an MT5 demo terminal; Ctrl+C to stop.", flush=True)
    while True:
        handle = api.CreateNamedPipeW(
            PIPE_NAME,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, 4096, 4096, 0, None,
        )
        if handle == INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not api.ConnectNamedPipe(handle, None):
                code = ctypes.get_last_error()
                if code != ERROR_PIPE_CONNECTED:
                    print(f"Pipe connect error {code}; reopening.", flush=True)
                    continue
            print("EA probe connected.", flush=True)
            pending = bytearray()
            last_seq: int | None = None
            while True:
                buf = ctypes.create_string_buffer(512)
                received = wintypes.DWORD()
                if not api.ReadFile(handle, buf, len(buf), ctypes.byref(received), None):
                    break
                if received.value == 0:
                    break
                pending.extend(buf.raw[:received.value])
                if len(pending) > MAX_PENDING:
                    print("Oversized frame stream; disconnecting.", flush=True)
                    break
                while b"\n" in pending:
                    idx = pending.index(10)
                    frame = bytes(pending[:idx + 1])
                    del pending[:idx + 1]
                    parsed = parse_frame(frame)
                    if parsed is None:
                        print("Invalid heartbeat frame; disconnecting.", flush=True)
                        return
                    seq, events = parsed
                    if last_seq is not None and seq <= last_seq:
                        print("Out-of-order heartbeat; disconnecting.", flush=True)
                        return
                    last_seq = seq
                    print(f"probe seq={seq} trade_events_observed={events}", flush=True)
        finally:
            api.DisconnectNamedPipe(handle)
            api.CloseHandle(handle)
        print("EA probe disconnected. Waiting for reconnect.", flush=True)


if __name__ == "__main__":
    run()
