"""Windows-only OS pipe integration tests; no MT5 or trading calls."""
from __future__ import annotations

import ctypes
import os
import threading
import time
import unittest
import uuid
from ctypes import wintypes

import pipe_probe_host
from pipe_probe_host import WindowsPipe, serve


@unittest.skipUnless(os.name == "nt", "Requires Win32 named pipes")
class NativePipeTests(unittest.TestCase):
    def setUp(self):
        self.original_name = pipe_probe_host.PIPE_NAME
        pipe_probe_host.PIPE_NAME = (
            "\\\\.\\pipe\\CheapTraderEAProbeTest" + uuid.uuid4().hex
        )
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateFileW.restype = wintypes.HANDLE
        self.kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        self.kernel.WriteFile.restype = wintypes.BOOL
        self.kernel.WriteFile.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
        ]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self._handles = []

    def tearDown(self):
        for handle in self._handles:
            self.kernel.CloseHandle(handle)
        pipe_probe_host.PIPE_NAME = self.original_name

    def open_client(self, desired_access=0x40000000):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            handle = self.kernel.CreateFileW(
                pipe_probe_host.PIPE_NAME, desired_access, 0, None, 3, 0, None,
            )
            if handle and handle != ctypes.c_void_p(-1).value:
                self._handles.append(handle)
                return handle
            time.sleep(0.02)
        self.fail("Could not connect to OS named-pipe probe on Windows")

    def write(self, handle, data: bytes):
        buffer = ctypes.create_string_buffer(data)
        written = wintypes.DWORD()
        if not self.kernel.WriteFile(
            handle, buffer, len(data), ctypes.byref(written), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        self.assertEqual(written.value, len(data))

    def close_client(self, handle):
        self.kernel.CloseHandle(handle)
        self._handles.remove(handle)

    def start_host(self):
        events = []
        pipe = WindowsPipe()
        thread = threading.Thread(
            target=serve, args=(pipe,), kwargs={
                "max_clients": 2,
                "emit": lambda event, **detail: events.append((event, detail)),
            }, daemon=True,
        )
        thread.start()
        return thread, events

    def wait_for_connected(self, events, count):
        """Avoid a Win32 ERROR_NO_DATA race from closing before accept()."""
        deadline = time.monotonic() + 5
        while sum(name == "client_connected" for name, _ in events) < count:
            self.assertLess(time.monotonic(), deadline,
                            f"Server did not accept {count} clients; events={events!r}")
            time.sleep(0.01)

    def test_win32_bad_client_then_valid_client(self):
        thread, events = self.start_host()
        invalid = self.open_client()
        self.wait_for_connected(events, 1)
        self.write(invalid, b"bad\n")
        self.close_client(invalid)
        normal = self.open_client()
        self.wait_for_connected(events, 2)
        self.write(normal, b"CTEA1|PING|1|0\n")
        self.close_client(normal)
        thread.join(10)
        self.assertFalse(thread.is_alive(), "Receiver did not reaccept")
        ended = [d for event, d in events if event == "client_disconnected"]
        self.assertEqual(len(ended), 2)
        self.assertEqual(ended[0]["reason"], "malformed_frame")
        self.assertEqual(ended[1]["heartbeats"], 1)

    def test_win32_valid_then_bad_same_write_is_logged_before_disconnect(self):
        thread, events = self.start_host()
        combined = self.open_client()
        self.wait_for_connected(events, 1)
        self.write(combined, b"CTEA1|PING|1|7\nbad\n")
        self.close_client(combined)
        # Wait for the first client's disconnect to be recorded before starting
        # the replacement client. Avoid relying on unsynchronized Win32 timing.
        deadline = time.monotonic() + 6
        while not any(event == "client_disconnected" for event, _ in events):
            self.assertLess(time.monotonic(), deadline,
                            "Mixed-frame client was not rejected within 6s")
            time.sleep(0.01)
        normal = self.open_client()
        self.write(normal, b"CTEA1|PING|1|0\n")
        self.close_client(normal)
        thread.join(10)
        self.assertFalse(thread.is_alive(), "Receiver did not reaccept after mixed frames")
        accepted = [detail for event, detail in events if event == "heartbeat"]
        ended = [detail for event, detail in events if event == "client_disconnected"]
        self.assertEqual([item["seq"] for item in accepted], [1, 1])
        self.assertEqual(accepted[0]["trade_events_observed"], 7)
        self.assertEqual(ended[0]["reason"], "malformed_frame")
        self.assertEqual(ended[0]["heartbeats"], 1)
        self.assertEqual(ended[1]["heartbeats"], 1)

    def test_win32_duplex_client_open_and_heartbeat_recovery(self):
        """Use the same GENERIC_READ|GENERIC_WRITE access as MQL5's
        official FILE_READ|FILE_WRITE named-pipe example (no server writes).
        """
        thread, events = self.start_host()
        client = self.open_client(desired_access=0xC0000000)
        self.wait_for_connected(events, 1)
        self.write(client, b"CTEA1|PING|1|0\n")
        self.write(client, b"CTEA1|PING|2|0\n")
        self.close_client(client)
        # Confirm the host has observed and closed the first connection before
        # attempting a replacement connection; distinguish a stalled receiver
        # from a client scheduling race.
        deadline = time.monotonic() + 6
        while not any(name == "client_disconnected" for name, _ in events):
            self.assertLess(time.monotonic(), deadline,
                            f"Duplex client not disconnected; events={events!r}")
            time.sleep(0.01)
        replacement = self.open_client(desired_access=0xC0000000)
        self.wait_for_connected(events, 2)
        self.write(replacement, b"CTEA1|PING|1|0\n")
        self.close_client(replacement)
        thread.join(10)
        self.assertFalse(thread.is_alive(),
                         f"Duplex-mode receiver did not reaccept; events={events!r}")
        heartbeats = [d["seq"] for name, d in events if name == "heartbeat"]
        disconnected = [d for name, d in events if name == "client_disconnected"]
        self.assertEqual(heartbeats, [1, 2, 1])
        self.assertEqual([d["heartbeats"] for d in disconnected], [2, 1])

    def test_win32_stalled_client_times_out_and_reaccepts(self):
        thread, events = self.start_host()
        stalled = self.open_client()
        self.wait_for_connected(events, 1)
        # Keep first client open with no heartbeat until 8s heartbeat deadline.
        time.sleep(pipe_probe_host.HEARTBEAT_TIMEOUT_S + 0.4)
        good = self.open_client()
        self.wait_for_connected(events, 2)
        self.write(good, b"CTEA1|PING|1|0\n")
        self.close_client(good)
        self.close_client(stalled)
        thread.join(10)
        self.assertFalse(thread.is_alive(), "Receiver remained blocked after timeout")
        ended = [d for event, d in events if event == "client_disconnected"]
        self.assertEqual([x["reason"] for x in ended[:1]], ["heartbeat_deadline"])
        self.assertEqual(ended[1]["heartbeats"], 1)


if __name__ == "__main__":
    unittest.main()
