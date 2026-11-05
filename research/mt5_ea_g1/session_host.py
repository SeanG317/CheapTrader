"""Transport-neutral CTEA2 session and authenticated snapshot coordinator."""
from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from credentials import matches_current
from protocol import (
    MAX_FRAME_BYTES,
    ProtocolError,
    decode_line,
    encode_line,
    make_auth_ok,
    make_challenge,
    make_snapshot_ack,
    validate_snapshot,
    verify_auth,
)
from state_store import SnapshotStore
from transport import RecoverableAcceptError, ServerTransport

MAX_LINE = MAX_FRAME_BYTES
DEFAULT_HANDSHAKE_TIMEOUT_S = 3.0
DEFAULT_STALE_TIMEOUT_S = 8.0


def log_event(name: str, **fields) -> None:
    print(json.dumps({"utc": datetime.now(UTC).isoformat(), "event": name, **fields},
                     separators=(",", ":"), sort_keys=True), flush=True)


class LineReader:
    """Assemble bounded UTF-8 JSON Lines from an arbitrary byte-stream transport."""

    def __init__(self, transport, session):
        self.transport = transport
        self.session = session
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
            try:
                chunk = self.transport.read(self.session, remaining)
            except TimeoutError:
                # A syscall may time out before the absolute message deadline.
                # Continue with the original deadline; partial data cannot reset it.
                if time.monotonic() >= deadline:
                    raise TimeoutError("frame_deadline")
                continue
            if not chunk:
                return b""
            self.pending.extend(chunk)
            if len(self.pending) > MAX_LINE and b"\n" not in self.pending:
                raise ProtocolError("frame_too_large")


def receive_authenticated(transport, session, key: bytes, login: int, server: str,
                          *, emit: Callable[..., None] = log_event,
                          store: SnapshotStore,
                          credential_path: Path | None = None,
                          credential_check: Callable = matches_current,
                          handshake_timeout_s: float = DEFAULT_HANDSHAKE_TIMEOUT_S,
                          stale_timeout_s: float = DEFAULT_STALE_TIMEOUT_S) -> None:
    def ensure_credential_current() -> None:
        if credential_path is not None and not credential_check(credential_path, key, login, server):
            raise ProtocolError("credential_revoked_or_rotated")

    stream = LineReader(transport, session)
    ensure_credential_current()
    challenge = make_challenge(key, login, server)
    handshake_deadline = time.monotonic() + handshake_timeout_s

    def remaining(deadline: float, name: str) -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError(name)
        return value

    transport.write(session, encode_line(challenge.response),
                    timeout=remaining(handshake_deadline, "handshake_deadline"))
    auth = decode_line(stream.read(remaining(handshake_deadline, "handshake_deadline")))
    ensure_credential_current()
    verify_auth(key, challenge, auth)
    transport.write(session, encode_line(make_auth_ok(key, challenge, store.committed_cursor)),
                    timeout=remaining(handshake_deadline, "handshake_deadline"))
    store.mark_ipc_connected()
    emit("authenticated", login=login, server=server, session_id=challenge.session_id)

    last_seq = 0
    last_receive = time.monotonic()
    last_message: dict | None = None
    last_ack: dict | None = None
    while True:
        line = stream.read(max(0.0, stale_timeout_s - (time.monotonic() - last_receive)))
        if not line:
            raise OSError("client_disconnected_or_half_closed")
        ensure_credential_current()
        message = decode_line(line)
        if message == last_message and last_ack is not None:
            transport.write(session, encode_line(last_ack))
            last_receive = time.monotonic()
            emit("snapshot_ack_replayed", seq=message["seq"], snapshot_id=message["snapshot_id"])
            continue
        validation_started = time.monotonic()
        last_seq = validate_snapshot(key, message, challenge, last_seq)
        validation_seconds = time.monotonic() - validation_started
        persist_started = time.monotonic()
        reconciliation = store.apply(message)
        persist_seconds = time.monotonic() - persist_started
        ensure_credential_current()
        last_ack = make_snapshot_ack(key, challenge, message, store.committed_cursor)
        ack_started = time.monotonic()
        transport.write(session, encode_line(last_ack))
        ack_write_seconds = time.monotonic() - ack_started
        last_receive = time.monotonic()
        last_message = message
        emit("snapshot", seq=last_seq, positions=len(message["positions"]),
             pending_orders=len(message["pending_orders"]), deals=len(message.get("deals", [])),
             login=login, server=server, validation_seconds=round(validation_seconds, 6),
             persistence_seconds=round(persist_seconds, 6), ack_write_seconds=round(ack_write_seconds, 6),
             reconciliation=reconciliation)


def serve_transport(transport: ServerTransport, key: bytes, login: int, server: str,
                    max_clients: int | None = None, *, emit=log_event,
                    store: SnapshotStore,
                    credential_path: Path | None = None,
                    credential_check: Callable = matches_current,
                    handshake_timeout_s: float = DEFAULT_HANDSHAKE_TIMEOUT_S,
                    stale_timeout_s: float = DEFAULT_STALE_TIMEOUT_S) -> None:
    served = 0
    while max_clients is None or served < max_clients:
        create_session = getattr(transport, "new_session", None) or transport.new_pipe
        close_session = getattr(transport, "close_session", None) or transport.close_pipe
        session = create_session()
        try:
            try:
                transport.accept(session)
            except TimeoutError:
                continue
            except RecoverableAcceptError as exc:
                emit("transport_accept_recovered", error_code=exc.error_code, reason=str(exc))
                store.mark_stale()
                continue
            except OSError as exc:
                error = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
                emit("transport_accept_fatal", error_code=error, reason=str(exc))
                raise
            emit("client_connected")
            try:
                receive_authenticated(
                    transport, session, key, login, server, emit=emit, store=store,
                    credential_path=credential_path, credential_check=credential_check,
                    handshake_timeout_s=handshake_timeout_s, stale_timeout_s=stale_timeout_s,
                )
            except Exception as exc:  # noqa: BLE001 -- isolate every client failure from the listener
                store.mark_stale()
                emit("client_disconnected", error_type=type(exc).__name__, reason=str(exc))
            served += 1
        finally:
            close_session(session)
