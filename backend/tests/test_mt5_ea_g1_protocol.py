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

from history_paging import build_deal_page
from pipe_host import serve
from protocol import (
    ACCOUNT_FIELDS,
    Challenge,
    ProtocolError,
    decode_line,
    encode_line,
    make_auth_ok,
    make_challenge,
    make_snapshot_ack,
    sign,
    validate_snapshot,
    verify_auth,
    verify_auth_ok,
    verify_snapshot_ack,
)
from state_store import SnapshotStore

KEY = bytes(range(32))
LOGIN = 12345678
SERVER = "Broker-Demo"
def challenge():
    return make_challenge(KEY, LOGIN, SERVER)


def auth_for(c: Challenge):
    return sign(KEY, {
        "type": "AUTH", "protocol": "CTEA2", "session_id": c.session_id,
        "server_nonce": c.server_nonce,
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
        "server_nonce": c.server_nonce,
        "login": c.login, "server_hex": c.server.encode().hex(), "seq": 1,
        "unix_time": 1_800_000_000, "account": account(), "positions": [],
        "pending_orders": [], "deals": [], "deal_cursor": None,
        "snapshot_id": f"{c.session_id}:1",
        "source_counts": {"positions": 0, "pending_orders": 0,
                           "history_selected": 0, "deals_after_cursor": 0},
        "deals_more": False, "broker_connected": True,
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
        message = {"b": "two 😀", "a": 1}
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
        wrong_identity = make_challenge(KEY, LOGIN, "Other-Demo")
        self.assertNotEqual((wrong_identity.login, wrong_identity.server), (LOGIN, SERVER))
        with self.assertRaises(ProtocolError):
            verify_auth(KEY, c, {**auth_for(c), "extra": 1})
        ok = make_auth_ok(KEY, c, None)
        self.assertEqual(ok["type"], "AUTH_OK")
        self.assertIsNone(verify_auth_ok(KEY, c, ok))
        ack = make_snapshot_ack(KEY, c, snapshot(c), None)
        verify_snapshot_ack(KEY, c, ack, seq=1, snapshot_id=f"{c.session_id}:1", pending_cursor=None)
        with self.assertRaisesRegex(ProtocolError, "bad_mac"):
            verify_auth(KEY, c, {**auth_for(c), "mac": "0" * 64})
        with self.assertRaisesRegex(ProtocolError, "snapshot_ack_binding_mismatch:session_id"):
            verify_snapshot_ack(KEY, challenge(), ack, seq=1,
                                snapshot_id=f"{c.session_id}:1", pending_cursor=None)

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
        good = snapshot(c, positions=[position], source_counts={
            "positions": 1, "pending_orders": 0, "history_selected": 0, "deals_after_cursor": 0,
        })
        self.assertEqual(validate_snapshot(KEY, good, c, 0, now=1_800_000_000), 1)
        bad = snapshot(c, positions=[{**position, "volume": "NaN"}], source_counts={
            "positions": 1, "pending_orders": 0, "history_selected": 0, "deals_after_cursor": 0,
        })
        with self.assertRaisesRegex(ProtocolError, "non_finite_position_volume"):
            validate_snapshot(KEY, bad, c, 0, now=1_800_000_000)
        bad_shape = snapshot(c, positions=[{**position, "order_send": True}], source_counts={
            "positions": 1, "pending_orders": 0, "history_selected": 0, "deals_after_cursor": 0,
        })
        with self.assertRaisesRegex(ProtocolError, "invalid_position_record"):
            validate_snapshot(KEY, bad_shape, c, 0, now=1_800_000_000)

    def test_stop_limit_orders_and_incomplete_source_counts(self):
        c = challenge()
        for kind, side in (("BUY_STOP_LIMIT", "BUY"), ("SELL_STOP_LIMIT", "SELL")):
            order = {"ticket": 10 if side == "BUY" else 11, "symbol": "EURUSD",
                     "side": side, "order_type": kind, "volume": "0.1",
                     "price": "1.2", "sl": "1.0", "tp": "1.4",
                     "price_current": "1.1", "price_stop_limit": "1.19",
                     "time": 1, "comment": ""}
            msg = snapshot(c, pending_orders=[order], source_counts={
                "positions": 0, "pending_orders": 1, "history_selected": 0,
                "deals_after_cursor": 0,
            })
            self.assertEqual(validate_snapshot(KEY, msg, c, 0, now=1_800_000_000), 1)
        incomplete = snapshot(c, source_counts={"positions": 1, "pending_orders": 0,
                                                "history_selected": 0, "deals_after_cursor": 0})
        with self.assertRaisesRegex(ProtocolError, "incomplete_current_state_snapshot"):
            validate_snapshot(KEY, incomplete, c, 0, now=1_800_000_000)

    def test_history_pagination_orders_ties_and_513th_record(self):
        records = [{"ticket": n + 1, "time_msc": 50} for n in range(513)]
        records.reverse()  # Native enumeration order is deliberately irrelevant.
        page1 = build_deal_page(records, None)
        self.assertEqual(len(page1["deals"]), 512)
        self.assertTrue(page1["more"])
        self.assertEqual(page1["cursor"], (50, 512))
        page2 = build_deal_page(records, page1["cursor"])
        self.assertEqual([row["ticket"] for row in page2["deals"]], [513])
        self.assertFalse(page2["more"])
        self.assertEqual(page2["cursor"], (50, 513))

    def test_history_failure_and_ticket_conflict_abort_page(self):
        with self.assertRaisesRegex(ProtocolError, "history_read_failed"):
            build_deal_page(None, None)
        with self.assertRaisesRegex(ProtocolError, "history_record_read_failed:1"):
            build_deal_page([{"ticket": 10, "time_msc": 1}, None], None)
        with self.assertRaisesRegex(ProtocolError, "deal_ticket_payload_conflict"):
            build_deal_page([{"ticket": 10, "time_msc": 1},
                             {"ticket": 10, "time_msc": 2}], None)

    def test_persistence_failure_never_emits_snapshot_ack(self):
        pipe = FakeAuthenticatedPipe()
        store = FailingStore()
        events = []
        serve(pipe, KEY, LOGIN, SERVER, max_clients=1,
              emit=lambda event, **details: events.append((event, details)), store=store)
        self.assertEqual(store.apply_calls, 1)
        self.assertFalse(store.fresh)
        self.assertFalse(any(msg["type"] == "SNAPSHOT_ACK" for msg in pipe.outgoing))
        self.assertTrue(any(name == "client_disconnected" for name, _ in events))

    def test_duplicate_after_ack_is_reacked_without_second_persist(self):
        pipe = FakeAuthenticatedPipe(duplicate_after_ack=True)
        store = MemoryStore()
        events = []
        serve(pipe, KEY, LOGIN, SERVER, max_clients=1,
              emit=lambda event, **details: events.append((event, details)), store=store)
        self.assertEqual(store.apply_calls, 1)
        self.assertEqual(len(pipe.acks), 2)
        self.assertTrue(any(name == "snapshot_ack_replayed" for name, _ in events))

    def test_persisted_snapshot_with_lost_ack_recovers_cursor_on_new_session(self):
        deal = {"ticket": 70, "position_id": 51, "order": 80, "time": 10,
                "time_msc": 10000, "kind": "buy", "entry": "in", "symbol": "EURUSD",
                "volume": "0.1", "price": "1.1", "profit": "0", "commission": "0",
                "swap": "0", "fee": "0", "reason": "client", "comment": "", "magic": 0}
        payload = lambda c: snapshot(
            c, unix_time=int(time.time()), deals=[deal],
            deal_cursor={"time_msc": 10000, "ticket": 70},
            source_counts={"positions": 0, "pending_orders": 0,
                           "history_selected": 1, "deals_after_cursor": 1})

        class LoseAckPipe(FakeAuthenticatedPipe):
            def write(self, handle, raw, timeout=5.0):
                message = decode_line(raw)
                if message["type"] == "SNAPSHOT_ACK":
                    raise OSError("injected_ack_loss")
                super().write(handle, raw, timeout)

        store = MemoryStore()
        serve(LoseAckPipe(snapshot_payload=payload), KEY, LOGIN, SERVER,
              max_clients=1, emit=lambda *_a, **_k: None, store=store)
        self.assertEqual(store.committed_cursor, {"time_msc": 10000, "ticket": 70})
        self.assertFalse(store.fresh)

        resumed = FakeAuthenticatedPipe()
        serve(resumed, KEY, LOGIN, SERVER, max_clients=1,
              emit=lambda *_a, **_k: None, store=store)
        auth_ok = next(message for message in resumed.outgoing if message["type"] == "AUTH_OK")
        self.assertEqual(auth_ok["committed_cursor"], {"time_msc": 10000, "ticket": 70})

    def test_real_state_file_survives_receiver_crash_after_persist_before_ack(self):
        deal = {"ticket": 70, "position_id": 51, "order": 80, "time": 10,
                "time_msc": 10000, "kind": "buy", "entry": "in", "symbol": "EURUSD",
                "volume": "0.1", "price": "1.1", "profit": "0", "commission": "0",
                "swap": "0", "fee": "0", "reason": "client", "comment": "", "magic": 0}
        payload = lambda c: snapshot(
            c, unix_time=int(time.time()), deals=[deal],
            deal_cursor={"time_msc": 10000, "ticket": 70},
            source_counts={"positions": 0, "pending_orders": 0,
                           "history_selected": 1, "deals_after_cursor": 1})

        class LostAckPipe(FakeAuthenticatedPipe):
            def write(self, handle, raw, timeout=5.0):
                if decode_line(raw)["type"] == "SNAPSHOT_ACK":
                    raise OSError("receiver_crashed_after_durable_persist")
                super().write(handle, raw, timeout)

        from tempfile import TemporaryDirectory
        with patch("state_store._protect", side_effect=lambda raw: b"ENC" + raw), \
             patch("state_store._unprotect", side_effect=lambda raw: raw[3:]), \
             TemporaryDirectory() as temp:
            path = Path(temp) / "state.dpapi"
            store = SnapshotStore(path, LOGIN, SERVER)
            serve(LostAckPipe(snapshot_payload=payload), KEY, LOGIN, SERVER,
                  max_clients=1, emit=lambda *_a, **_k: None, store=store)
            restarted = SnapshotStore(path, LOGIN, SERVER)
            self.assertFalse(restarted.fresh)
            self.assertEqual(restarted.committed_cursor, {"time_msc": 10000, "ticket": 70})
            resumed = FakeAuthenticatedPipe()
            serve(resumed, KEY, LOGIN, SERVER, max_clients=1,
                  emit=lambda *_a, **_k: None, store=restarted)
            auth_ok = next(message for message in resumed.outgoing if message["type"] == "AUTH_OK")
            self.assertEqual(auth_ok["committed_cursor"], {"time_msc": 10000, "ticket": 70})

    def test_broker_disconnected_snapshot_is_rejected_and_cache_stales(self):
        pipe = FakeAuthenticatedPipe(broker_connected=False)
        store = MemoryStore()
        store.fresh = True
        events = []
        serve(pipe, KEY, LOGIN, SERVER, max_clients=1,
              emit=lambda event, **details: events.append((event, details)), store=store)
        self.assertFalse(store.fresh)
        self.assertFalse(any(msg["type"] == "SNAPSHOT_ACK" for msg in pipe.outgoing))
        self.assertTrue(any(name == "client_disconnected" and
                            "broker_disconnected_snapshot" in details["reason"]
                            for name, details in events))

    def test_receiver_restart_accepts_a_fresh_authenticated_session(self):
        sessions = []
        event_sets = []
        for _ in range(2):
            pipe = FakeAuthenticatedPipe()
            events = []

            def capture(event, _events=events, **details):
                _events.append((event, details))

            serve(pipe, KEY, LOGIN, SERVER, max_clients=1,
                  emit=capture, store=MemoryStore())
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
                  emit=capture, credential_path=Path("credential.dpapi"), store=MemoryStore())
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
                current = snapshot(c, positions=[position], deals=[deal],
                                   deal_cursor={"time_msc": 10000, "ticket": 70},
                                   source_counts={"positions": 1, "pending_orders": 0,
                                                  "history_selected": 1, "deals_after_cursor": 1})
                reconciliation = store.apply(current)
                self.assertTrue(store.fresh)
                self.assertEqual(reconciliation["positions_added"], 1)
                self.assertEqual(reconciliation["deals_added"], 1)
                with self.assertRaisesRegex(ProtocolError, "deal_ticket_payload_conflict"):
                    store.apply(snapshot(c, deals=[{**deal, "profit": "99"}], seq=2,
                                        snapshot_id=f"{c.session_id}:2",
                                        deal_cursor={"time_msc": 10000, "ticket": 70},
                                        source_counts={"positions": 0, "pending_orders": 0,
                                                       "history_selected": 1,
                                                       "deals_after_cursor": 1}))
                restarted = SnapshotStore(path, LOGIN, SERVER)
                self.assertFalse(restarted.fresh)
                reconciliation = restarted.apply(snapshot(
                    c, deals=[deal], seq=2, snapshot_id=f"{c.session_id}:2",
                    positions=[], pending_orders=[],
                    deal_cursor={"time_msc": 10000, "ticket": 70},
                    source_counts={"positions": 0, "pending_orders": 0,
                                   "history_selected": 1, "deals_after_cursor": 0}))
                self.assertEqual(reconciliation["deals_added"], 0)
                self.assertEqual(reconciliation["positions_removed"], 1)
                self.assertEqual(reconciliation["orders_removed"], 0)
                self.assertEqual(len(restarted.state["deals"]), 1)


class FakeAuthenticatedPipe:
    """Lifecycle fake only; this does not count as a native Windows pipe test."""

    def __init__(self, *, duplicate_after_ack=False, broker_connected=True, snapshot_payload=None):
        self.incoming = []
        self.outgoing = []
        self.duplicate_after_ack = duplicate_after_ack
        self.broker_connected = broker_connected
        self.duplicate_queued = False
        self.snapshot_payload = snapshot_payload

    def new_pipe(self):
        return self

    def accept(self, handle):
        return None

    def write(self, handle, raw, timeout=5.0):
        message = decode_line(raw)
        self.outgoing.append(message)
        if message["type"] == "CHALLENGE":
            c = Challenge(message, message["session_id"], message["server_nonce"], message["login"], SERVER)
            self.challenge = c
            self.incoming.append(encode_line(auth_for(c)))
        elif message["type"] == "AUTH_OK":
            self.committed_cursor = message["committed_cursor"]
            self.incoming.extend([
                encode_line(self.snapshot_payload(self.challenge) if callable(self.snapshot_payload)
                            else self.snapshot_payload or snapshot(
                                self.challenge, unix_time=int(time.time()),
                                broker_connected=self.broker_connected)),
                b"",
            ])
        elif message["type"] == "SNAPSHOT_ACK":
            self.acks = getattr(self, "acks", []) + [message]
            if self.duplicate_after_ack and not self.duplicate_queued:
                self.incoming.insert(0, encode_line(snapshot(self.challenge, unix_time=int(time.time()),
                                                            broker_connected=self.broker_connected)))
                self.duplicate_queued = True

    def read(self, handle, timeout):
        return self.incoming.pop(0) if self.incoming else b""

    def close_pipe(self, handle):
        return None


class MemoryStore:
    """Persistence seam for protocol tests; native durability is tested separately."""

    def __init__(self):
        self.committed_cursor = None
        self.fresh = False
        self.state = {}

    def apply(self, message):
        self.apply_calls = getattr(self, "apply_calls", 0) + 1
        self.committed_cursor = message["deal_cursor"]
        self.state["snapshot_id"] = message["snapshot_id"]
        self.state["session_id"] = message["session_id"]
        self.state["seq"] = message["seq"]
        self.fresh = True
        return {"positions_added": 0, "positions_removed": 0,
                "orders_added": 0, "orders_removed": 0, "deals_added": len(message["deals"])}

    def mark_stale(self):
        self.fresh = False

    def mark_ipc_connected(self):
        pass


class FailingStore(MemoryStore):
    def apply(self, message):
        self.apply_calls = getattr(self, "apply_calls", 0) + 1
        raise OSError("simulated_persist_failure")


if __name__ == "__main__":
    unittest.main()
