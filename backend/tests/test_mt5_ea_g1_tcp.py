from __future__ import annotations

import ctypes
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "research" / "mt5_ea_g1"))

from tempfile import TemporaryDirectory
from unittest.mock import patch

from protocol import (
    ACCOUNT_FIELDS,
    Challenge,
    decode_line,
    encode_line,
    sign,
    verify_auth_ok,
    verify_server_challenge,
    verify_snapshot_ack,
)
from session_host import serve_transport
from state_store import SnapshotStore
from tcp_host import LoopbackTcpServer, validate_endpoint

KEY = bytes(range(32))
LOGIN = 7654321
SERVER_NAME = "Local-Demo"


def account() -> dict:
    result = {name: "0" for name in ACCOUNT_FIELDS}
    result.update({
        "login": LOGIN, "server": SERVER_NAME, "currency": "USD", "name": "Demo",
        "company": "Broker", "stop_out_mode": "percent", "trade_mode": "demo",
        "margin_mode": "hedging", "fifo_close": False,
        "leverage": 100, "currency_digits": 2, "limit_orders": 200,
    })
    return result


def signed_snapshot(challenge: Challenge, seq: int, cursor=None) -> dict:
    return sign(KEY, {
        "type": "SNAPSHOT", "protocol": "CTEA2", "session_id": challenge.session_id,
        "server_nonce": challenge.server_nonce, "login": challenge.login,
        "server_hex": challenge.server.encode().hex(), "seq": seq,
        "unix_time": int(time.time()), "account": account(), "positions": [],
        "pending_orders": [], "deals": [], "deal_cursor": cursor,
        "snapshot_id": f"{challenge.session_id}:{seq}",
        "source_counts": {"positions": 0, "pending_orders": 0,
                           "history_selected": 0, "deals_after_cursor": 0},
        "deals_more": False, "broker_connected": True,
    })


def signed_snapshot_with_deal(challenge: Challenge) -> dict:
    deal = {"ticket": 99, "position_id": 88, "order": 100, "time": 10,
            "time_msc": 10001, "kind": "buy", "entry": "in", "symbol": "EURUSD",
            "volume": "0.1", "price": "1.1", "profit": "0", "commission": "0",
            "swap": "0", "fee": "0", "reason": "client", "comment": "", "magic": 0}
    message = signed_snapshot(challenge, 1)
    message.update({
        "deals": [deal], "deal_cursor": {"time_msc": 10001, "ticket": 99},
        "source_counts": {"positions": 0, "pending_orders": 0,
                           "history_selected": 1, "deals_after_cursor": 1},
    })
    unsigned = {key: value for key, value in message.items() if key != "mac"}
    return sign(KEY, unsigned)


class MemoryStore:
    def __init__(self):
        self.committed_cursor = None
        self.fresh = False
        self.applied = []

    def apply(self, message):
        self.applied.append(message)
        self.committed_cursor = message["deal_cursor"]
        self.fresh = True
        return {"positions_added": 0, "positions_removed": 0,
                "orders_added": 0, "orders_removed": 0, "deals_added": 0}

    def mark_stale(self):
        self.fresh = False

    def mark_ipc_connected(self):
        self.ipc_connected = True


def recv_line(sock: socket.socket, buffer: bytearray, timeout: float = 2.0) -> bytes:
    deadline = time.monotonic() + timeout
    while True:
        pos = buffer.find(b"\n")
        if pos >= 0:
            line = bytes(buffer[:pos + 1])
            del buffer[:pos + 1]
            return line
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("test_client_line_deadline")
        sock.settimeout(remaining)
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("server_closed_before_line")
        buffer.extend(chunk)
        if len(buffer) > 1_048_576:
            raise AssertionError("unexpected_oversize_test_frame")


class TcpServerTests(unittest.TestCase):
    def make_server(self, *, handshake_timeout=1.0, heartbeat_timeout=1.0, max_clients=1):
        server = LoopbackTcpServer(port=0, send_timeout_ms=250, receive_timeout_ms=100)
        store = MemoryStore()
        events = []
        thread = threading.Thread(target=serve_transport, kwargs={
            "transport": server, "key": KEY, "login": LOGIN, "server": SERVER_NAME,
            "max_clients": max_clients, "emit": lambda name, **fields: events.append((name, fields)),
            "store": store, "handshake_timeout_s": handshake_timeout,
            "stale_timeout_s": heartbeat_timeout,
        }, daemon=True)
        thread.start()
        self.addCleanup(server.close)
        self.addCleanup(thread.join, 3)
        return server, store, events, thread

    def authenticate(self, sock: socket.socket, buffer: bytearray,
                     expected_cursor=None) -> Challenge:
        challenge_message = decode_line(recv_line(sock, buffer))
        c = verify_server_challenge(KEY, challenge_message, login=LOGIN, server=SERVER_NAME)
        auth = sign(KEY, {
            "type": "AUTH", "protocol": "CTEA2", "session_id": c.session_id,
            "server_nonce": c.server_nonce, "login": LOGIN,
            "server_hex": SERVER_NAME.encode().hex(),
        })
        raw = encode_line(auth)
        # Exercise arbitrary application-level fragmentation over the real TCP
        # byte stream; the receiver may observe any grouping it wants.
        sizes = (1, 2, 5, 3, 8, 13)
        offset = 0
        index = 0
        while offset < len(raw):
            count = sizes[index % len(sizes)]
            sock.sendall(raw[offset:offset + count])
            offset += count
            index += 1
        auth_ok = decode_line(recv_line(sock, buffer))
        self.assertEqual(verify_auth_ok(KEY, c, auth_ok), expected_cursor)
        return c

    def test_endpoint_is_loopback_only_and_bind_conflict_is_clear(self):
        validate_endpoint("127.0.0.1", 47631)
        for unsafe in ("0.0.0.0", "localhost", "192.168.1.2", "::1"):
            with self.assertRaises(ValueError):
                validate_endpoint(unsafe, 47631)
        first = LoopbackTcpServer(port=0)
        try:
            with self.assertRaisesRegex(OSError, "tcp_loopback_bind_failed"):
                LoopbackTcpServer(port=first.port)
        finally:
            first.close()
        refused = LoopbackTcpServer(port=0)
        unused_port = refused.port
        refused.close()
        started = time.monotonic()
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", unused_port), timeout=2.0)
        self.assertLess(time.monotonic() - started, 2.5)

    def test_fragmented_auth_and_coalesced_snapshot_frames(self):
        server, store, _events, thread = self.make_server()
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=1)
        buffer = bytearray()
        with sock:
            c = self.authenticate(sock, buffer)
            first = encode_line(signed_snapshot(c, 1))
            second = encode_line(signed_snapshot(c, 2))
            # Two LF records are coalesced into a single send; send itself is
            # further split so neither boundary aligns with TCP packet edges.
            payload = first + second
            sock.sendall(payload[:7])
            sock.sendall(payload[7:])
            ack1 = decode_line(recv_line(sock, buffer))
            ack2 = decode_line(recv_line(sock, buffer))
            verify_snapshot_ack(KEY, c, ack1, seq=1, snapshot_id=f"{c.session_id}:1",
                                pending_cursor=None)
            verify_snapshot_ack(KEY, c, ack2, seq=2, snapshot_id=f"{c.session_id}:2",
                                pending_cursor=None)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual([m["seq"] for m in store.applied], [1, 2])

    def test_abrupt_short_client_does_not_prevent_next_authenticated_client(self):
        server, store, _events, thread = self.make_server(max_clients=6)
        for _ in range(5):
            short = socket.create_connection(("127.0.0.1", server.port), timeout=1)
            short_buffer = bytearray()
            recv_line(short, short_buffer)  # receive challenge, then abort before AUTH
            short.shutdown(socket.SHUT_RDWR)
            short.close()
        second = socket.create_connection(("127.0.0.1", server.port), timeout=1)
        second_buffer = bytearray()
        with second:
            c = self.authenticate(second, second_buffer)
            second.sendall(encode_line(signed_snapshot(c, 1)))
            ack = decode_line(recv_line(second, second_buffer))
            verify_snapshot_ack(KEY, c, ack, seq=1,
                                snapshot_id=f"{c.session_id}:1", pending_cursor=None)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(store.applied)

    def test_server_completes_partial_native_socket_writes(self):
        send_calls = []

        class ShortSendSocket:
            """Cap actual Winsock/POSIX socket sends to force partial writes."""

            def __init__(self, wrapped):
                self.wrapped = wrapped

            def settimeout(self, value):
                return self.wrapped.settimeout(value)

            def recv(self, size):
                return self.wrapped.recv(size)

            def send(self, data):
                send_calls.append(len(data))
                return self.wrapped.send(data[:7])

            def shutdown(self, how):
                return self.wrapped.shutdown(how)

            def close(self):
                return self.wrapped.close()

        class PartialWriteServer(LoopbackTcpServer):
            def accept(self, session, timeout=1.0):
                super().accept(session, timeout)
                session.client = ShortSendSocket(session.client)

        server = PartialWriteServer(port=0, send_timeout_ms=500, receive_timeout_ms=250)
        store = MemoryStore()
        thread = threading.Thread(target=serve_transport, kwargs={
            "transport": server, "key": KEY, "login": LOGIN, "server": SERVER_NAME,
            "max_clients": 1, "emit": lambda *_a, **_k: None, "store": store,
            "handshake_timeout_s": 1, "stale_timeout_s": 2,
        }, daemon=True)
        thread.start()
        self.addCleanup(server.close)
        self.addCleanup(thread.join, 3)
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=1)
        buffer = bytearray()
        with sock:
            challenge = self.authenticate(sock, buffer)
            sock.sendall(encode_line(signed_snapshot(challenge, 1)))
            ack = decode_line(recv_line(sock, buffer))
            verify_snapshot_ack(KEY, challenge, ack, seq=1,
                                snapshot_id=f"{challenge.session_id}:1", pending_cursor=None)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertGreater(len(send_calls), 10)

    @unittest.skipUnless(sys.platform == "win32", "Windows process handle count requires Win32")
    def test_repeated_native_tcp_sessions_release_process_handles(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        kernel.GetProcessHandleCount.restype = ctypes.c_int
        process = kernel.GetCurrentProcess()

        def handle_count():
            count = ctypes.c_ulong()
            if not kernel.GetProcessHandleCount(process, ctypes.byref(count)):
                raise ctypes.WinError(ctypes.get_last_error())
            return count.value

        server, _store, _events, thread = self.make_server(max_clients=20)
        time.sleep(0.05)
        baseline = handle_count()
        for _ in range(20):
            sock = socket.create_connection(("127.0.0.1", server.port), timeout=1)
            buffer = bytearray()
            with sock:
                challenge = self.authenticate(sock, buffer)
                sock.sendall(encode_line(signed_snapshot(challenge, 1)))
                decode_line(recv_line(sock, buffer))
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertLessEqual(handle_count(), baseline + 5)

    def test_slow_handshake_has_absolute_deadline(self):
        server, _store, _events, thread = self.make_server(handshake_timeout=0.25)
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=1)
        buffer = bytearray()
        challenge_message = decode_line(recv_line(sock, buffer))
        c = verify_server_challenge(KEY, challenge_message, login=LOGIN, server=SERVER_NAME)
        auth = encode_line(sign(KEY, {
            "type": "AUTH", "protocol": "CTEA2", "session_id": c.session_id,
            "server_nonce": c.server_nonce, "login": LOGIN,
            "server_hex": SERVER_NAME.encode().hex(),
        }))
        start = time.monotonic()
        try:
            for byte in auth[:10]:
                try:
                    sock.sendall(bytes((byte,)))
                except OSError:
                    break
                time.sleep(0.04)
            sock.settimeout(1)
            while sock.recv(1024):
                pass
        except (TimeoutError, OSError):
            pass
        finally:
            sock.close()
        elapsed = time.monotonic() - start
        thread.join(1)
        self.assertLess(elapsed, 0.8, f"handshake deadline overshot: {elapsed:.3f}s")
        self.assertFalse(thread.is_alive())

    def test_slow_snapshot_trickle_does_not_renew_heartbeat_deadline(self):
        server, store, _events, thread = self.make_server(heartbeat_timeout=0.25)
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=1)
        buffer = bytearray()
        with sock:
            c = self.authenticate(sock, buffer)
            frame = encode_line(signed_snapshot(c, 1))
            start = time.monotonic()
            for byte in frame[:12]:
                try:
                    sock.sendall(bytes((byte,)))
                except OSError:
                    break
                time.sleep(0.07)
            sock.settimeout(1)
            try:
                while sock.recv(4096):
                    pass
            except (OSError, TimeoutError):
                pass
            elapsed = time.monotonic() - start
        thread.join(1)
        self.assertLess(elapsed, 0.8, f"slow-trickle deadline overshot: {elapsed:.3f}s")
        self.assertFalse(thread.is_alive())
        self.assertFalse(store.fresh)

    def test_large_utf8_snapshot_is_received_as_stream_not_one_packet(self):
        server, store, _events, thread = self.make_server()
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=1)
        buffer = bytearray()
        with sock:
            c = self.authenticate(sock, buffer)
            message = signed_snapshot(c, 1)
            message["account"]["name"] = "x" * 800_000 + "宝可梦"
            unsigned = {key: value for key, value in message.items() if key != "mac"}
            frame = encode_line(sign(KEY, unsigned))
            self.assertGreater(len(frame), 800_000)
            sock.sendall(frame)
            ack = decode_line(recv_line(sock, buffer))
            verify_snapshot_ack(KEY, c, ack, seq=1,
                                snapshot_id=f"{c.session_id}:1", pending_cursor=None)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(store.applied[0]["account"]["name"][-3:], "宝可梦")

    def test_persisted_cursor_survives_tcp_ack_loss_and_host_restart(self):
        store = MemoryStore()

        class DropAckServer(LoopbackTcpServer):
            def write(self, session, data, timeout=None):
                if data.startswith(b'{"login"') and b'"type":"SNAPSHOT_ACK"' in data:
                    raise OSError("injected_ack_drop_after_apply")
                return super().write(session, data, timeout)

        # Use a listener with the ACK failure seam but real loopback TCP.
        second = DropAckServer(port=0, send_timeout_ms=250, receive_timeout_ms=100)
        writer_thread = threading.Thread(target=serve_transport, kwargs={
            "transport": second, "key": KEY, "login": LOGIN, "server": SERVER_NAME,
            "max_clients": 1, "emit": lambda *_a, **_k: None, "store": store,
            "handshake_timeout_s": 1, "stale_timeout_s": 1,
        }, daemon=True)
        writer_thread.start()
        first_client = socket.create_connection(("127.0.0.1", second.port), timeout=1)
        first_buffer = bytearray()
        with first_client:
            c = self.authenticate(first_client, first_buffer)
            first_client.sendall(encode_line(signed_snapshot_with_deal(c)))
            first_client.settimeout(1)
            self.assertEqual(first_client.recv(4096), b"")
        writer_thread.join(2)
        self.assertFalse(writer_thread.is_alive())
        self.assertEqual(store.committed_cursor, {"time_msc": 10001, "ticket": 99})

        resumed = LoopbackTcpServer(port=0, send_timeout_ms=250, receive_timeout_ms=100)
        resumed_thread = threading.Thread(target=serve_transport, kwargs={
            "transport": resumed, "key": KEY, "login": LOGIN, "server": SERVER_NAME,
            "max_clients": 1, "emit": lambda *_a, **_k: None, "store": store,
            "handshake_timeout_s": 1, "stale_timeout_s": 1,
        }, daemon=True)
        resumed_thread.start()
        client = socket.create_connection(("127.0.0.1", resumed.port), timeout=1)
        with client:
            c2 = self.authenticate(client, bytearray(), expected_cursor=store.committed_cursor)
            client.sendall(encode_line(signed_snapshot(c2, 1,cursor=store.committed_cursor)))
            ack = decode_line(recv_line(client, bytearray()))
            verify_snapshot_ack(KEY, c2, ack, seq=1,
                                snapshot_id=f"{c2.session_id}:1", pending_cursor=store.committed_cursor)
        resumed_thread.join(2)
        self.assertFalse(resumed_thread.is_alive())

    def test_cache_expires_stale_while_ipc_is_still_connected(self):
        with patch("state_store._protect", side_effect=lambda raw: raw), \
             patch("state_store._unprotect", side_effect=lambda raw: raw), \
             TemporaryDirectory() as temp:
            from protocol import make_challenge
            store = SnapshotStore(Path(temp) / "state.bin", LOGIN, SERVER_NAME, stale_after_s=1)
            c = make_challenge(KEY, LOGIN, SERVER_NAME)
            store.apply(signed_snapshot(c, 1))
            store.mark_ipc_connected()
            self.assertTrue(store.fresh)
            store._state["received_unix"] = time.time() - 2
            state = store.state
            self.assertFalse(state["fresh"])
            self.assertTrue(state["ipc_connected"])
            self.assertEqual(state["stale_reason"], "snapshot_expired")


if __name__ == "__main__":
    unittest.main()
