"""Transport-neutral interface used by the read-only CTEA2 session handler."""
from __future__ import annotations

from typing import Protocol, TypeVar

Session = TypeVar("Session")


class RecoverableAcceptError(OSError):
    """A client reset/abort while the listening socket remains healthy."""

    def __init__(self, error_code: int, message: str):
        self.error_code = error_code
        self.winerror = error_code
        super().__init__(message)


class ServerTransport(Protocol[Session]):
    """One accepted client session at a time; implementations own their listener."""

    def new_session(self) -> Session: ...

    def accept(self, session: Session, timeout: float = ...) -> None: ...

    def read(self, session: Session, timeout: float) -> bytes: ...

    def write(self, session: Session, data: bytes, timeout: float = ...) -> None: ...

    def close_session(self, session: Session) -> None: ...


class ClientTransport(Protocol):
    """Message-oriented adapter presented to the protocol/session layer."""

    def read(self, timeout_s: float) -> bytes: ...

    def write(self, data: bytes, timeout_s: float) -> None: ...

    def close(self) -> None: ...
