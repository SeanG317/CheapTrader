from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "research" / "mt5_ea_g1"))

from pipe_host import serve
from protocol import (
    ACCOUNT_FIELDS,
    Challenge,
    ProtocolError,
    decode_line,
    encode_line,
    make_auth_ok,
    make_challenge,
    sign,
    validate_snapshot,
    verify_auth,
)
from state_store import SnapshotStore

KEY = bytes(range(32))
LOGIN = 12345678
SERVER = "Broker-Demo"
CLIENT_NONCE = "11" * 32


def hello():
    return sign(KEY, {
        "type": "HELLO", "protocol": "CTEA2", "client_nonce": CLIENT_NONCE,
        "login": LOGIN, "server_hex": SERVER.encode().hex(),
    })


def challenge():
    return make_challenge(KEY, hello())


def auth_for(c: Challenge):
    return sign(KEY, {
        "type": "AUTH", "protocol": "CTEA2", "session_id": c.session_id,
        "client_nonce": c.client_nonce, "server_nonce": c.server_nonce,
        "login": c.login, "server_hex": c.server.encode().hex(),
    })


def account():
    data = {name: "0" for name in ACCOUNT_FIELDS}
    data.update({
        "login": LOGIN, "server": SERVER, "currency": "USD", "name": "Demo",
        "company": "Broker", "stop_out_mode": "percent", "trade_mode": "demo",
        "margin_mode": "hedging", "fifo_close": False,
        "leverage": 100, "currency_digits": 2, "limit_orders": 200,
    })
    return data


def snapshot(c: Challenge, **changes):
    data = {
        "type": "SNAPSHOT", "protocol": "CTEA2", "session_id": c.session_id,
        "client_nonce": c.client_nonce, "server_nonce": c.server_nonce,
        "login": c.login, "server_hex": c.server.encode().hex(), "seq": 1,
        "unix_time": 1_800_000_000, "account": account(), "positions": [],
        "pending_orders": [], "deals": [], "deal_cursor": {"time_msc": 10, "ticket": 2},
    }
    data.update(changes)
    return sign(KEY, data)


class ProtocolTests(unittest.TestCase):
    def test_canonical_json_line_roundtrip_and_frame_bound(self):
        message = {"z": "宝可梦", "a": 2}
        line = encode_line(message)
        self.assertEqual(line, '{"a":2,"z":"宝可梦"}\n'.encode())
        self.assertEqual(decode_line(line), message)
        with self.assertRaises(ProtocolError):
            decode_line(b'{"x":NaN}\n')
        with self.assertRaises(ProtocolError):
            decode_line(b"x" * (1024 * 1024 + 1) + b"\n")

    def test_hmac_matches_standard_library(self):
        message = {"b": "two", "a": 1}
        signed = sign(KEY, message)
        canonical = json.dumps(message, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode()
        self.assertEqual(signed["mac"], hmac.new(KEY, canonical, hashlib.sha256).hexdigest())

    def test_challenge_auth_and_account_pin(self):
        c = challenge()
        self.assertEqual((c.login, c.server), (LOGIN, SERVER))
        verify_auth(KEY, c, auth_for(c))
        with self.assertRaises(ProtocolError):
            verify_auth(KEY, c, auth_for(challenge()))
        wrong = sign(KEY, {**hello(), "server_hex": "4f746865722d44656d6f"})
        wrong_identity = make_challenge(KEY, wrong)
        self.assertNotEqual((wrong_identity.login, wrong_identity.server), (LOGIN, SERVER))
        self.assertEqual(make_auth_ok(KEY, c)["type"], "AUTH_OK")

    def test_full_snapshot_replay_and_identity_guards(self):
        c = challenge()
        message = snapshot(c)
        self.assertEqual(validate_snapshot(KEY, message, c, 0, now=1_800_000_000), 1)
        with self.assertRaisesRegex(ProtocolError, "replayed_or_backward_sequence"):
            validate_snapshot(KEY, message, c, 1, now=1_800_000_000)
        changed = snapshot(c, account={**account(), "login": LOGIN + 1})
        with self.assertRaisesRegex(ProtocolError, "account_identity_changed"):
            validate_snapshot(KEY, changed, c, 0, now=1_800_000_000)
        old = snapshot(c, unix_time=1_700_000_000)
        with self.assertRaisesRegex(ProtocolError, "stale_snapshot"):
            validate_snapshot(KEY, old, c, 0, now=1_800_000_000)

    def test_snapshot_rejects_unknown_or_malformed_payloads(self):
        c = challenge()
        with self.assertRaisesRegex(ProtocolError, "incomplete_or_unknown_snapshot_field"):
            validate_snapshot(KEY, snapshot(c, command={"type": "order"}), c, 0,
                              now=1_800_000_000)
        position = {
            "ticket": 1, "symbol": "EURUSD", "side": "BUY", "volume": "0.1",
            "price_open": "1.1", "price_current": "1.2", "sl": "1.0", "tp": "1.3",
            "profit": "10.00", "time": 1, "comment": "",
        }
        good = snapshot(c, positions=[position])
        self.assertEqual(validate_snapshot(KEY, good, c, 0, now=1_800_000_000), 1)
        bad = snapshot(c, positions=[{**position, "volume": "NaN"}])
        with self.assertRaisesRegex(ProtocolError, "non_finite_position_volume"):
            validate_snapshot(KEY, bad, c, 0, now=1_800_000_000)
        bad_shape = snapshot(c, positions=[{**position, "order_send": True}])
        with self.assertRaisesRegex(ProtocolError, "invalid_position_record"):
            validate_snapshot(KEY, bad_shape, c, 0, now=1_800_000_000)

    def test_receiver_restart_accepts_a_fresh_authenticated_session(self):
        sessions = []
        event_sets = []
        for _ in range(2):
            pipe = FakeAuthenticatedPipe()
            events = []

            def capture(event, _events=events, **details):
                _events.append((event, details))

            serve(pipe, KEY, LOGIN, SERVER, max_clients=1,
                  emit=capture)
            event_sets.append(events)
            sessions.extend(details["session_id"] for name, details in events if name == "authenticated")
        self.assertEqual(len(sessions), 2)
        self.assertNotEqual(sessions[0], sessions[1])
        for events in event_sets:
            self.assertTrue(any(name == "snapshot" and details["seq"] == 1 for name, details in events))

    def test_credential_rotation_terminates_live_session_before_accepting_snapshot(self):
        events = []

        def capture(event, **details):
            events.append((event, details))

        with patch("pipe_host.matches_current", side_effect=[True, True, False]):
            serve(FakeAuthenticatedPipe(), KEY, LOGIN, SERVER, max_clients=1,
                  emit=capture, credential_path=Path("credential.dpapi"))
        self.assertTrue(any(name == "client_disconnected" and
                            details["reason"] == "credential_revoked_or_rotated"
                            for name, details in events))
        self.assertFalse(any(name == "snapshot" for name, _details in events))

    def test_snapshot_store_reconciles_state_and_deduplicates_deals(self):
        c = challenge()
        position = {
            "ticket": 51, "symbol": "EURUSD", "side": "BUY", "volume": "0.1",
            "price_open": "1.1", "price_current": "1.2", "sl": "1.0", "tp": "1.3",
            "profit": "10.00", "time": 5, "comment": "",
        }
        deal = {
            "ticket": 70, "position_id": 51, "order": 80, "time": 10, "time_msc": 10000,
            "kind": "buy", "entry": "in", "symbol": "EURUSD", "volume": "0.1",
            "price": "1.1", "profit": "0", "commission": "0", "swap": "0", "fee": "0",
            "reason": "client", "comment": "", "magic": 0,
        }
        with patch("state_store._protect", side_effect=lambda raw: b"ENC" + raw), \
             patch("state_store._unprotect", side_effect=lambda raw: raw[3:]):
            from tempfile import TemporaryDirectory
            with TemporaryDirectory() as temp:
                path = Path(temp) / "snapshot.dpapi"
                store = SnapshotStore(path, LOGIN, SERVER)
                current = snapshot(c, positions=[position], deals=[deal])
                reconciliation = store.apply(current)
                self.assertTrue(store.fresh)
                self.assertEqual(reconciliation["positions_added"], 1)
                self.assertEqual(reconciliation["deals_added"], 1)
                restarted = SnapshotStore(path, LOGIN, SERVER)
                self.assertFalse(restarted.fresh)
                reconciliation = restarted.apply(snapshot(c, deals=[deal], seq=2))
                self.assertEqual(reconciliation["deals_added"], 0)
                self.assertEqual(len(restarted.state["deals"]), 1)


class FakeAuthenticatedPipe:
    """Lifecycle fake only; this does not count as a native Windows pipe test."""

    def __init__(self):
        nonce = "ab" * 32
        self.incoming = [encode_line(sign(KEY, {
            "type": "HELLO", "protocol": "CTEA2", "client_nonce": nonce,
            "login": LOGIN, "server_hex": SERVER.encode().hex(),
        }))]

    def new_pipe(self):
        return self

    def accept(self, handle):
        return None

    def write(self, handle, raw):
        message = decode_line(raw)
        if message["type"] == "CHALLENGE":
            c = Challenge(message, message["session_id"], message["client_nonce"],
                          message["server_nonce"], message["login"], SERVER)
            self.incoming.extend([
                encode_line(auth_for(c)),
                encode_line(snapshot(c, unix_time=int(time.time()))),
                b"",
            ])

    def read(self, handle, timeout):
        return self.incoming.pop(0) if self.incoming else b""

    def close_pipe(self, handle):
        return None


if __name__ == "__main__":
    unittest.main()
