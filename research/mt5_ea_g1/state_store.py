"""DPAPI-protected, read-only broker snapshot cache and reconnect reconciler."""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from credentials import _protect, _unprotect
from protocol import ProtocolError

MAX_RETAINED_DEALS = 50_000


class SnapshotStore:
    """Persist validated EA snapshots and deduplicate deal history across restarts.

    The cache is always stale after process startup or pipe disconnect. Only a
    newly authenticated full snapshot marks it fresh again. This class has no
    broker connection and cannot submit commands.
    """

    def __init__(self, path: Path, login: int, server: str):
        self.path = path
        self.login = login
        self.server = server
        self._state: dict[str, Any] = {
            "version": 1, "login": login, "server": server,
            "positions": [], "pending_orders": [], "deals": [],
            "deal_cursor": None, "session_id": None, "seq": 0,
            "received_unix": None,
        }
        self._fresh = False
        if path.exists():
            self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(_unprotect(self.path.read_bytes()).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, OSError) as exc:
            raise ProtocolError("snapshot_cache_unreadable") from exc
        if (raw.get("version") != 1 or raw.get("login") != self.login
                or raw.get("server") != self.server
                or not isinstance(raw.get("positions"), list)
                or not isinstance(raw.get("pending_orders"), list)
                or not isinstance(raw.get("deals"), list)):
            raise ProtocolError("snapshot_cache_identity_or_schema_mismatch")
        self._state = raw
        self._fresh = False

    def mark_stale(self) -> None:
        self._fresh = False

    @property
    def fresh(self) -> bool:
        return self._fresh

    @property
    def state(self) -> dict[str, Any]:
        result = dict(self._state)
        result["fresh"] = self._fresh
        result["age_seconds"] = (
            None if self._state["received_unix"] is None
            else max(0, round(time.time() - self._state["received_unix"], 3))
        )
        return result

    def apply(self, snapshot: dict[str, Any]) -> dict[str, int]:
        if (snapshot.get("login"), snapshot.get("account", {}).get("server")) != (self.login, self.server):
            raise ProtocolError("snapshot_store_account_mismatch")
        old_positions = {int(item["ticket"]): item for item in self._state["positions"]}
        old_orders = {int(item["ticket"]): item for item in self._state["pending_orders"]}
        positions = {int(item["ticket"]): item for item in snapshot["positions"]}
        orders = {int(item["ticket"]): item for item in snapshot["pending_orders"]}
        existing_deals = {int(item["ticket"]): item for item in self._state["deals"]}
        added_deals = 0
        for deal in snapshot["deals"]:
            ticket = int(deal["ticket"])
            prior = existing_deals.get(ticket)
            if prior is not None and prior != deal:
                raise ProtocolError("deal_ticket_payload_conflict")
            if prior is None:
                existing_deals[ticket] = deal
                added_deals += 1
        ordered_deals = sorted(
            existing_deals.values(), key=lambda item: (int(item["time_msc"]), int(item["ticket"]))
        )[-MAX_RETAINED_DEALS:]
        state = {
            "version": 1, "login": self.login, "server": self.server,
            "account": snapshot["account"],
            "positions": sorted(positions.values(), key=lambda item: int(item["ticket"])),
            "pending_orders": sorted(orders.values(), key=lambda item: int(item["ticket"])),
            "deals": ordered_deals,
            "deal_cursor": snapshot["deal_cursor"],
            "session_id": snapshot["session_id"], "seq": snapshot["seq"],
            "received_unix": int(time.time()),
        }
        self._persist(state)
        self._state = state
        self._fresh = True
        return {
            "positions_added": len(set(positions).difference(old_positions)),
            "positions_removed": len(set(old_positions).difference(positions)),
            "orders_added": len(set(orders).difference(old_orders)),
            "orders_removed": len(set(old_orders).difference(orders)),
            "deals_added": added_deals,
        }

    def _persist(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        clear = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           allow_nan=False).encode("utf-8")
        encrypted = _protect(clear)
        fd, temp_name = tempfile.mkstemp(prefix="ct-g1-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(encrypted)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp_name, self.path)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
