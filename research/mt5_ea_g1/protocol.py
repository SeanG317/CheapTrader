"""Authenticated, read-only wire protocol for the CheapTrader MT5 EA bridge.

This module is the Python reference implementation. It deliberately has no
order/request message type. The on-wire format is UTF-8 JSON Lines, with a
1 MiB hard limit and HMAC-SHA256 over canonical JSON (sorted keys, compact
separators, UTF-8, no NaN/Infinity).

The shared key is injected by the caller and must contain at least 32 random
bytes. Persistence/provisioning is intentionally separate from this module.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

PROTOCOL = "CTEA2"
MAX_FRAME_BYTES = 1_048_576
MAX_POSITIONS = 2048
MAX_PENDING_ORDERS = 2048
MAX_DEALS = 512
MAX_SERVER_ID_BYTES = 128
ACCOUNT_FIELDS = {
    "login", "server", "currency", "balance", "equity", "margin", "margin_free",
    "profit", "leverage", "name", "company", "credit", "margin_level",
    "margin_call_level", "stop_out_level", "stop_out_mode", "trade_mode",
    "margin_mode", "limit_orders", "fifo_close", "currency_digits", "assets",
    "liabilities", "commission_blocked",
}
POSITION_FIELDS = {
    "ticket", "symbol", "side", "volume", "price_open", "price_current", "sl",
    "tp", "profit", "time", "comment",
}
PENDING_ORDER_FIELDS = {
    "ticket", "symbol", "side", "order_type", "volume", "price", "sl", "tp",
    "price_current", "time", "comment",
}
DEAL_FIELDS = {
    "ticket", "position_id", "order", "time", "time_msc", "kind", "entry",
    "symbol", "volume", "price", "profit", "commission", "swap", "fee",
    "reason", "comment", "magic",
}


class ProtocolError(ValueError):
    """Invalid, unauthenticated, stale, or unsafe peer message."""


def _canonical(obj: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError("message_not_canonicalizable") from exc


def encode_line(message: dict[str, Any]) -> bytes:
    body = _canonical(message)
    if len(body) + 1 > MAX_FRAME_BYTES:
        raise ProtocolError("frame_too_large")
    return body + b"\n"


def decode_line(line: bytes) -> dict[str, Any]:
    if not line or len(line) > MAX_FRAME_BYTES or not line.endswith(b"\n"):
        raise ProtocolError("invalid_frame_length_or_terminator")
    try:
        value = json.loads(line[:-1].decode("utf-8"), parse_constant=lambda _: (_ for _ in ()).throw(
            ProtocolError("non_finite_number")
        ))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid_json") from exc
    if not isinstance(value, dict):
        raise ProtocolError("message_must_be_object")
    return value


def mac_hex(key: bytes, message: dict[str, Any]) -> str:
    if len(key) < 32:
        raise ProtocolError("key_too_short")
    unsigned = {name: value for name, value in message.items() if name != "mac"}
    return hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest()


def sign(key: bytes, message: dict[str, Any]) -> dict[str, Any]:
    result = dict(message)
    result["mac"] = mac_hex(key, result)
    return result


def verify(key: bytes, message: dict[str, Any]) -> None:
    supplied = message.get("mac")
    if not isinstance(supplied, str) or len(supplied) != 64:
        raise ProtocolError("missing_or_malformed_mac")
    if not hmac.compare_digest(supplied.lower(), mac_hex(key, message)):
        raise ProtocolError("bad_mac")


def _validate_identity(login: Any, server: Any) -> tuple[int, str]:
    if isinstance(login, bool) or not isinstance(login, int) or login <= 0:
        raise ProtocolError("invalid_account_login")
    if not isinstance(server, str) or not server or len(server.encode("utf-8")) > MAX_SERVER_ID_BYTES:
        raise ProtocolError("invalid_account_server")
    return login, server


def _validate_records(records: list[Any], allowed: set[str], integer_fields: set[str],
                      numeric_fields: set[str], string_fields: set[str], label: str) -> None:
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != allowed:
            raise ProtocolError(f"invalid_{label}_record:{index}")
        for field in integer_fields:
            if isinstance(record[field], bool) or not isinstance(record[field], int):
                raise ProtocolError(f"invalid_{label}_{field}:{index}")
        for field in numeric_fields:
            value = record[field]
            if isinstance(value, bool) or not isinstance(value, (int, float, str)):
                raise ProtocolError(f"invalid_{label}_{field}:{index}")
            try:
                number = Decimal(str(value))
            except InvalidOperation as exc:
                raise ProtocolError(f"invalid_{label}_{field}:{index}") from exc
            if not number.is_finite():
                raise ProtocolError(f"non_finite_{label}_{field}:{index}")
        for field in string_fields:
            if not isinstance(record[field], str):
                raise ProtocolError(f"invalid_{label}_{field}:{index}")


@dataclass(frozen=True)
class Challenge:
    response: dict[str, Any]
    session_id: str
    client_nonce: str
    server_nonce: str
    login: int
    server: str


def make_challenge(key: bytes, hello: dict[str, Any]) -> Challenge:
    """Validate a signed HELLO and return a signed fresh challenge."""
    if len(key) < 32:
        raise ProtocolError("key_too_short")
    if hello.get("type") != "HELLO" or hello.get("protocol") != PROTOCOL:
        raise ProtocolError("unsupported_hello")
    verify(key, hello)
    if set(hello).difference({"type", "protocol", "client_nonce", "login", "server_hex", "mac"}):
        raise ProtocolError("unknown_hello_field")
    client_nonce = hello.get("client_nonce")
    if not isinstance(client_nonce, str) or len(client_nonce) != 64:
        raise ProtocolError("invalid_client_nonce")
    try:
        bytes.fromhex(client_nonce)
    except ValueError as exc:
        raise ProtocolError("invalid_client_nonce") from exc
    login = hello.get("login")
    server_hex = hello.get("server_hex")
    if not isinstance(server_hex, str) or len(server_hex) < 2 or len(server_hex) > MAX_SERVER_ID_BYTES * 2:
        raise ProtocolError("invalid_account_server")
    try:
        server = bytes.fromhex(server_hex).decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProtocolError("invalid_account_server") from exc
    login, server = _validate_identity(login, server)
    server_nonce = secrets.token_hex(32)
    session_id = secrets.token_hex(16)
    base = {
        "type": "CHALLENGE", "protocol": PROTOCOL, "session_id": session_id,
        "client_nonce": client_nonce.lower(), "server_nonce": server_nonce,
        "login": login, "server_hex": server.encode("utf-8").hex(),
    }
    return Challenge(sign(key, base), session_id, client_nonce.lower(), server_nonce, login, server)


def verify_auth(key: bytes, challenge: Challenge, auth: dict[str, Any]) -> None:
    """Accept only a client proof bound to both nonces and the exact identity."""
    verify(key, auth)
    expected = {
        "type": "AUTH", "protocol": PROTOCOL,
        "session_id": challenge.session_id,
        "client_nonce": challenge.client_nonce,
        "server_nonce": challenge.server_nonce,
        "login": challenge.login, "server_hex": challenge.server.encode("utf-8").hex(),
    }
    for name, value in expected.items():
        if auth.get(name) != value:
            raise ProtocolError(f"auth_binding_mismatch:{name}")


def make_auth_ok(key: bytes, challenge: Challenge) -> dict[str, Any]:
    return sign(key, {
        "type": "AUTH_OK", "protocol": PROTOCOL,
        "session_id": challenge.session_id,
        "client_nonce": challenge.client_nonce,
        "server_nonce": challenge.server_nonce,
        "login": challenge.login, "server_hex": challenge.server.encode("utf-8").hex(),
    })


def validate_snapshot(key: bytes, message: dict[str, Any], challenge: Challenge,
                      last_seq: int, *, now: float | None = None,
                      max_clock_skew_s: int = 30) -> int:
    """Authenticate and validate a complete current-state snapshot.

    Sequence numbers are strictly increasing within the authenticated session;
    reconnects receive new random nonces/session IDs, so old signed frames cannot
    be replayed into the new session. Snapshot payloads are data only.
    """
    verify(key, message)
    if message.get("type") != "SNAPSHOT" or message.get("protocol") != PROTOCOL:
        raise ProtocolError("not_a_snapshot")
    bindings = {
        "session_id": challenge.session_id,
        "client_nonce": challenge.client_nonce,
        "server_nonce": challenge.server_nonce,
        "login": challenge.login,
        "server_hex": challenge.server.encode("utf-8").hex(),
    }
    for name, value in bindings.items():
        if message.get(name) != value:
            raise ProtocolError(f"snapshot_binding_mismatch:{name}")
    seq = message.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= last_seq:
        raise ProtocolError("replayed_or_backward_sequence")
    timestamp = message.get("unix_time")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ProtocolError("invalid_snapshot_time")
    current = int(time.time() if now is None else now)
    if abs(current - timestamp) > max_clock_skew_s:
        raise ProtocolError("stale_snapshot")
    account = message.get("account")
    if not isinstance(account, dict):
        raise ProtocolError("missing_account_snapshot")
    if set(account) != ACCOUNT_FIELDS:
        raise ProtocolError("incomplete_or_unknown_account_field")
    account_integers = {"login", "leverage", "currency_digits", "limit_orders"}
    account_booleans = {"fifo_close"}
    account_strings = ACCOUNT_FIELDS.difference(account_integers | account_booleans | {
        "assets", "balance", "commission_blocked", "credit", "equity", "liabilities",
        "margin", "margin_call_level", "margin_free", "margin_level", "profit", "stop_out_level",
    })
    for field in account_integers:
        if isinstance(account[field], bool) or not isinstance(account[field], int):
            raise ProtocolError(f"invalid_account_{field}")
    for field in account_booleans:
        if not isinstance(account[field], bool):
            raise ProtocolError(f"invalid_account_{field}")
    for field in account_strings:
        if not isinstance(account[field], str):
            raise ProtocolError(f"invalid_account_{field}")
    for field in ACCOUNT_FIELDS.difference(account_integers | account_booleans | account_strings):
        value = account[field]
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise ProtocolError(f"invalid_account_{field}")
        try:
            number = Decimal(str(value))
        except InvalidOperation as exc:
            raise ProtocolError(f"invalid_account_{field}") from exc
        if not number.is_finite():
            raise ProtocolError(f"non_finite_account_{field}")
    identity = _validate_identity(account.get("login"), account.get("server"))
    if identity != (challenge.login, challenge.server):
        raise ProtocolError("account_identity_changed")
    positions = message.get("positions")
    orders = message.get("pending_orders")
    deals = message.get("deals", [])
    if not isinstance(positions, list) or len(positions) > MAX_POSITIONS:
        raise ProtocolError("invalid_positions")
    if not isinstance(orders, list) or len(orders) > MAX_PENDING_ORDERS:
        raise ProtocolError("invalid_pending_orders")
    if not isinstance(deals, list) or len(deals) > MAX_DEALS:
        raise ProtocolError("invalid_deals")
    _validate_records(positions, POSITION_FIELDS, {"ticket", "time"},
                      {"volume", "price_open", "price_current", "sl", "tp", "profit"},
                      {"symbol", "side", "comment"}, "position")
    _validate_records(orders, PENDING_ORDER_FIELDS, {"ticket", "time"},
                      {"volume", "price", "sl", "tp", "price_current"},
                      {"symbol", "side", "order_type", "comment"}, "pending_order")
    _validate_records(deals, DEAL_FIELDS, {"ticket", "position_id", "order", "time", "time_msc", "magic"},
                      {"volume", "price", "profit", "commission", "swap", "fee"},
                      {"kind", "entry", "symbol", "reason", "comment"}, "deal")
    for position in positions:
        if position["side"] not in {"BUY", "SELL"}:
            raise ProtocolError("invalid_position_side")
    for order in orders:
        if order["side"] not in {"BUY", "SELL"} or order["order_type"] not in {
            "BUY_LIMIT", "SELL_LIMIT", "BUY_STOP", "SELL_STOP",
        }:
            raise ProtocolError("invalid_pending_order_type")
    for deal in deals:
        if deal["kind"] not in {
            "buy", "sell", "balance", "credit", "charge", "correction", "bonus",
            "commission", "interest", "dividend", "tax", "canceled", "other",
        } or deal["entry"] not in {"", "in", "out", "inout", "out_by"}:
            raise ProtocolError("invalid_deal_type")
    if "deal_cursor" not in message:
        raise ProtocolError("missing_deal_cursor")
    cursor = message["deal_cursor"]
    if cursor is not None and (
        not isinstance(cursor, dict) or set(cursor) != {"time_msc", "ticket"}
        or any(isinstance(cursor.get(key), bool) or not isinstance(cursor.get(key), int)
               or cursor[key] < 0 for key in ("time_msc", "ticket"))
    ):
        raise ProtocolError("invalid_deal_cursor")
    expected_fields = {
        "type", "protocol", "session_id", "client_nonce", "server_nonce",
        "login", "server_hex", "seq", "unix_time", "account", "positions",
        "pending_orders", "deals", "deal_cursor", "mac",
    }
    if set(message) != expected_fields:
        raise ProtocolError("incomplete_or_unknown_snapshot_field")
    return seq


def verify_server_challenge(key: bytes, challenge: dict[str, Any], *, login: int, server: str,
                            client_nonce: str) -> None:
    """EA-side reference check: the client must verify host before sending state."""
    verify(key, challenge)
    if challenge.get("type") != "CHALLENGE" or challenge.get("protocol") != PROTOCOL:
        raise ProtocolError("unsupported_challenge")
    expected = {
        "login": login, "server_hex": server.encode("utf-8").hex(),
        "client_nonce": client_nonce.lower(),
    }
    for name, value in expected.items():
        if challenge.get(name) != value:
            raise ProtocolError(f"challenge_binding_mismatch:{name}")
    for name, size in (("session_id", 32), ("server_nonce", 64)):
        value = challenge.get(name)
        if not isinstance(value, str) or len(value) != size:
            raise ProtocolError(f"invalid_{name}")
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            raise ProtocolError(f"invalid_{name}") from exc
