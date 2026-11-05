"""DPAPI-protected, read-only broker snapshot cache and reconnect reconciler."""
from __future__ import annotations

import ctypes
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
            "snapshot_id": None, "received_unix": None,
            "ipc_connected": False, "broker_connected": False,
            "stale_reason": "startup",
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
        raw.setdefault("snapshot_id", None)
        raw.setdefault("ipc_connected", False)
        raw.setdefault("broker_connected", False)
        raw.setdefault("stale_reason", "startup")
        self._state = raw
        self._fresh = False

    def mark_stale(self) -> None:
        self._fresh = False
        self._state["ipc_connected"] = False
        self._state["stale_reason"] = "ipc_disconnected_or_timeout"

    def mark_ipc_connected(self) -> None:
        self._state["ipc_connected"] = True

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

    @property
    def committed_cursor(self) -> dict[str, int] | None:
        cursor = self._state.get("deal_cursor")
        return None if cursor is None else dict(cursor)

    def apply(self, snapshot: dict[str, Any]) -> dict[str, int]:
        if (snapshot.get("login"), snapshot.get("account", {}).get("server")) != (self.login, self.server):
            raise ProtocolError("snapshot_store_account_mismatch")
        if snapshot.get("broker_connected") is not True:
            self.mark_stale()
            raise ProtocolError("broker_disconnected_snapshot")
        snapshot_id = snapshot["snapshot_id"]
        if (snapshot_id == self._state.get("snapshot_id")
                and snapshot.get("session_id") == self._state.get("session_id")
                and snapshot.get("seq") == self._state.get("seq")):
            return {"positions_added": 0, "positions_removed": 0,
                    "orders_added": 0, "orders_removed": 0, "deals_added": 0}
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
        previous_cursor = self._state.get("deal_cursor")
        new_cursor = snapshot["deal_cursor"]
        if previous_cursor is not None and new_cursor is None:
            raise ProtocolError("deal_cursor_regressed")
        if previous_cursor is not None and new_cursor is not None:
            old_key = (previous_cursor["time_msc"], previous_cursor["ticket"])
            new_key = (new_cursor["time_msc"], new_cursor["ticket"])
            if new_key < old_key:
                raise ProtocolError("deal_cursor_regressed")
        if snapshot["deals"] and new_cursor == previous_cursor and added_deals:
            raise ProtocolError("deal_cursor_did_not_advance")
        ordered_deals = sorted(
            existing_deals.values(), key=lambda item: (int(item["time_msc"]), int(item["ticket"]))
        )[-MAX_RETAINED_DEALS:]
        state = {
            "version": 1, "login": self.login, "server": self.server,
            "account": snapshot["account"],
            "positions": sorted(positions.values(), key=lambda item: int(item["ticket"])),
            "pending_orders": sorted(orders.values(), key=lambda item: int(item["ticket"])),
            "deals": ordered_deals,
            "deal_cursor": new_cursor,
            "session_id": snapshot["session_id"], "seq": snapshot["seq"],
            "snapshot_id": snapshot_id,
            "received_unix": int(time.time()),
            "ipc_connected": True, "broker_connected": True, "stale_reason": None,
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
                if os.name == "nt":
                    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                    kernel.FlushFileBuffers.argtypes = [ctypes.c_void_p]
                    kernel.FlushFileBuffers.restype = ctypes.c_int
                    import msvcrt
                    if not kernel.FlushFileBuffers(msvcrt.get_osfhandle(output.fileno())):
                        raise ctypes.WinError(ctypes.get_last_error())
            if os.name == "nt":
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.MoveFileExW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
                kernel.MoveFileExW.restype = ctypes.c_int
                flags = 0x1 | 0x8  # MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
                if not kernel.MoveFileExW(temp_name, str(self.path), flags):
                    raise ctypes.WinError(ctypes.get_last_error())
            else:
                os.replace(temp_name, self.path)
                directory_fd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
