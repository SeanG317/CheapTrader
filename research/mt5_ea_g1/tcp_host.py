"""Loopback-only TCP host for the read-only CTEA2 MT5 EA bridge.

The EA is the sole broker-state collector. This module only authenticates,
validates, persists and acknowledges snapshots; it contains no trade schema.
"""
from __future__ import annotations

import argparse
import os
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from credentials import (
    default_credential_path,
    load,
    provision,
    revoke,
)
from protocol import ProtocolError
from session_host import MAX_LINE, log_event, serve_transport
from state_store import SnapshotStore
from transport import RecoverableAcceptError

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 47631
DEFAULT_CONNECT_TIMEOUT_MS = 1000
DEFAULT_SEND_TIMEOUT_MS = 1000
DEFAULT_RECEIVE_TIMEOUT_MS = 1000
DEFAULT_HANDSHAKE_TIMEOUT_MS = 3000
DEFAULT_ACK_TIMEOUT_MS = 3000
DEFAULT_SNAPSHOT_SECONDS = 2
DEFAULT_STALE_SECONDS = 8
DEFAULT_RECONNECT_INITIAL_SECONDS = 2
DEFAULT_RECONNECT_MAX_SECONDS = 30
MAX_CLIENTS = 1
LISTEN_BACKLOG = 4


def validate_timeout(name: str, value: int, low: int = 50, high: int = 120_000) -> int:
    if isinstance(value, bool) or not low <= value <= high:
        raise ValueError(f"{name}_out_of_range:{low}..{high}")
    return value


def validate_endpoint(host: str, port: int) -> None:
    if host != DEFAULT_HOST:
        raise ValueError("host_must_be_ipv4_loopback_127.0.0.1")
    if isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port_out_of_range:1..65535")


@dataclass
class TcpClientSession:
    client: socket.socket | None = None
    peer: tuple[str, int] | None = None


class LoopbackTcpServer:
    """Single-client IPv4 loopback server implementing the G1 transport seam."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, *,
                 send_timeout_ms: int = DEFAULT_SEND_TIMEOUT_MS,
                 receive_timeout_ms: int = DEFAULT_RECEIVE_TIMEOUT_MS,
                 backlog: int = LISTEN_BACKLOG):
        if port == 0:
            if host != DEFAULT_HOST:
                raise ValueError("host_must_be_ipv4_loopback_127.0.0.1")
        else:
            validate_endpoint(host, port)
        self.send_timeout_ms = validate_timeout("send_timeout_ms", send_timeout_ms)
        self.receive_timeout_ms = validate_timeout("receive_timeout_ms", receive_timeout_ms)
        if not 1 <= backlog <= 16:
            raise ValueError("listen_backlog_out_of_range:1..16")
        self.host = host
        self.port = port
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            self.listener.bind((DEFAULT_HOST, port))
            self.listener.listen(backlog)
            self.port = self.listener.getsockname()[1]
        except OSError as exc:
            self.listener.close()
            raise OSError(f"tcp_loopback_bind_failed:{DEFAULT_HOST}:{port}:{exc}") from exc

    def new_pipe(self) -> TcpClientSession:
        # Name retained to satisfy the transport-neutral G1 session loop.
        return TcpClientSession()

    def new_session(self) -> TcpClientSession:
        return self.new_pipe()

    def accept(self, session: TcpClientSession, timeout: float = 1.0) -> None:
        self.listener.settimeout(timeout)
        try:
            client, peer = self.listener.accept()
        except OSError as exc:
            # Client reset/abort during the TCP handshake is transient; only
            # these platform-documented connection errors are recoverable.
            code = getattr(exc, "winerror", None) or exc.errno
            if code in {10052, 10053, 10054, 103, 104}:
                raise RecoverableAcceptError(code, f"tcp_accept_client_abort:{code}") from exc
            raise
        if peer[0] != DEFAULT_HOST:
            client.close()
            raise ProtocolError("non_loopback_peer_rejected")
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        client.settimeout(min(self.receive_timeout_ms, self.send_timeout_ms) / 1000)
        session.client = client
        session.peer = peer

    @staticmethod
    def _client(session: TcpClientSession) -> socket.socket:
        if session.client is None:
            raise OSError("tcp_client_not_connected")
        return session.client

    def read(self, session: TcpClientSession, timeout: float) -> bytes:
        client = self._client(session)
        if timeout <= 0:
            raise TimeoutError("tcp_receive_deadline")
        client.settimeout(min(timeout, self.receive_timeout_ms / 1000))
        try:
            data = client.recv(4096)
        except TimeoutError as exc:
            raise TimeoutError("tcp_receive_timeout") from exc
        if not data:
            return b""
        return data

    def write(self, session: TcpClientSession, data: bytes,
              timeout: float | None = None) -> None:
        client = self._client(session)
        if not data or len(data) > MAX_LINE:
            raise ProtocolError("invalid_or_oversize_tcp_write")
        budget = self.send_timeout_ms / 1000 if timeout is None else min(
            timeout, self.send_timeout_ms / 1000
        )
        deadline = time.monotonic() + budget
        sent = 0
        while sent < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"tcp_send_deadline:{sent}/{len(data)}")
            client.settimeout(remaining)
            try:
                count = client.send(data[sent:])
            except TimeoutError as exc:
                raise TimeoutError(f"tcp_send_timeout:{sent}/{len(data)}") from exc
            if count <= 0:
                raise OSError(f"tcp_send_closed:{sent}/{len(data)}")
            sent += count

    def close_pipe(self, session: TcpClientSession) -> None:
        client, session.client = session.client, None
        session.peer = None
        if client is not None:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()

    def close_session(self, session: TcpClientSession) -> None:
        self.close_pipe(session)

    def close(self) -> None:
        self.listener.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def serve_tcp(server: LoopbackTcpServer, key: bytes, login: int, account_server: str, *,
              store: SnapshotStore, credential_path: Path,
              handshake_timeout_ms: int = DEFAULT_HANDSHAKE_TIMEOUT_MS,
              stale_timeout_s: int = DEFAULT_STALE_SECONDS,
              max_clients: int | None = None, emit=log_event) -> None:
    validate_timeout("handshake_timeout_ms", handshake_timeout_ms)
    if not 1 <= stale_timeout_s <= 300:
        raise ValueError("stale_timeout_seconds_out_of_range:1..300")
    emit("tcp_listening", host=DEFAULT_HOST, port=server.port, max_clients=MAX_CLIENTS,
         handshake_timeout_ms=handshake_timeout_ms, stale_timeout_seconds=stale_timeout_s)
    try:
        serve_transport(
            server, key, login, account_server, max_clients=max_clients, emit=emit,
            store=store, credential_path=credential_path,
            handshake_timeout_s=handshake_timeout_ms / 1000,
            stale_timeout_s=stale_timeout_s,
        )
    finally:
        server.close()


def run() -> int:
    parser = argparse.ArgumentParser(description="Read-only CTEA2 localhost TCP bridge host")
    parser.add_argument("action", choices=("provision", "revoke", "serve"))
    parser.add_argument("--credential-file", type=os.path.abspath)
    parser.add_argument("--state-file", type=os.path.abspath)
    parser.add_argument("--login", type=int)
    parser.add_argument("--server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--send-timeout-ms", type=int, default=DEFAULT_SEND_TIMEOUT_MS)
    parser.add_argument("--receive-timeout-ms", type=int, default=DEFAULT_RECEIVE_TIMEOUT_MS)
    parser.add_argument("--handshake-timeout-ms", type=int, default=DEFAULT_HANDSHAKE_TIMEOUT_MS)
    parser.add_argument("--stale-seconds", type=int, default=DEFAULT_STALE_SECONDS)
    args = parser.parse_args()
    credential_path = Path(args.credential_file) if args.credential_file else default_credential_path()
    if args.action == "provision":
        if args.login is None or not args.server:
            parser.error("provision requires --login and --server")
        one_time_key = provision(credential_path, args.login, args.server)
        print("Provisioned encrypted host credential. Enter once in the Demo EA's shared-key input.")
        print("Do not save the EA inputs as .set or paste the key into logs/issues.")
        print(one_time_key, flush=True)
        return 0
    if args.action == "revoke":
        existed = revoke(credential_path)
        log_event("credential_revoked", credential_file=str(credential_path), existed=existed)
        return 0
    try:
        validate_endpoint(args.host, args.port)
        validate_timeout("send_timeout_ms", args.send_timeout_ms)
        validate_timeout("receive_timeout_ms", args.receive_timeout_ms)
        validate_timeout("handshake_timeout_ms", args.handshake_timeout_ms)
        credential = load(credential_path)
        state_path = Path(args.state_file) if args.state_file else Path(str(credential_path) + ".state.dpapi")
        store = SnapshotStore(state_path, credential["login"], credential["server"],
                              stale_after_s=args.stale_seconds)
        with LoopbackTcpServer(args.host, args.port,
                               send_timeout_ms=args.send_timeout_ms,
                               receive_timeout_ms=args.receive_timeout_ms) as host:
            serve_tcp(host, bytes.fromhex(credential["key_hex"]), credential["login"],
                      credential["server"], store=store, credential_path=credential_path,
                      handshake_timeout_ms=args.handshake_timeout_ms,
                      stale_timeout_s=args.stale_seconds)
    except KeyboardInterrupt:
        log_event("stopped")
        return 0
    except (OSError, ValueError, ProtocolError) as exc:
        log_event("tcp_host_fatal", error_type=type(exc).__name__, reason=str(exc))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
