"""Independent Python MT5 comparison source for manually checking the native EA.

This module never calls a trade method and is never imported by the G1 host.
It uses the existing adapter's bound account and position/deal mappers, plus a
read-only Python MT5 order mapper that preserves Stop Limit's two prices.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.broker.base import BrokerError
from app.broker.mt5_adapter import deal_from_mt5

from .protocol import MAX_DEALS


def _comparison_orders(adapter) -> list[dict[str, Any]]:
    """Map raw Python MT5 order records without changing adapter lifecycle.

    The production adapter's UI mapper intentionally omits Stop Limit orders;
    this comparison-only path reads the same read-only MT5 record and preserves
    both ORDER_PRICE_OPEN and ORDER_PRICE_STOPLIMIT for parity checks.
    """
    mt5 = adapter.module
    raw = mt5.orders_get()
    if raw is None:
        raise BrokerError(f"orders_get() failed: {mt5.last_error()}")
    mapping = {
        mt5.ORDER_TYPE_BUY_LIMIT: ("BUY", "BUY_LIMIT"),
        mt5.ORDER_TYPE_SELL_LIMIT: ("SELL", "SELL_LIMIT"),
        mt5.ORDER_TYPE_BUY_STOP: ("BUY", "BUY_STOP"),
        mt5.ORDER_TYPE_SELL_STOP: ("SELL", "SELL_STOP"),
        mt5.ORDER_TYPE_BUY_STOP_LIMIT: ("BUY", "BUY_STOP_LIMIT"),
        mt5.ORDER_TYPE_SELL_STOP_LIMIT: ("SELL", "SELL_STOP_LIMIT"),
    }
    output = []
    for row in raw:
        kind = mapping.get(int(row.type))
        if kind is None:
            raise BrokerError(f"Unknown active pending order type: {row.type}")
        output.append({
            "ticket": int(row.ticket), "symbol": str(row.symbol),
            "side": kind[0], "order_type": kind[1],
            "volume": str(getattr(row, "volume_current", getattr(row, "volume_initial", 0.0))),
            "price": str(row.price_open), "sl": str(row.sl), "tp": str(row.tp),
            "price_current": str(getattr(row, "price_current", 0.0)),
            "price_stop_limit": str(getattr(row, "price_stoplimit", 0.0)),
            "time": int(getattr(row, "time_setup", 0)), "comment": str(row.comment),
        })
    return output


def collect_snapshot(adapter, *, after_deal: tuple[int, int] | None = None,
                     seq: int, session_id: str) -> dict[str, Any]:
    """Build one full current-state snapshot and only incremental deal history.

    ``after_deal`` is ``(time_msc, ticket)``. A one-second overlap is fetched
    and deduplicated by that cursor so two deals sharing a timestamp are not
    lost. Empty MT5 results remain distinct from API failures via strict reads.
    """
    before = adapter.get_account()
    expected = (before.login, before.server)
    if expected[0] <= 0 or not expected[1]:
        raise BrokerError("Cannot snapshot an MT5 account without login and server.")
    if adapter._bound_account != expected:
        raise BrokerError("MT5 account differs from the pinned CheapTrader account; snapshot refused.")

    positions = adapter.get_positions(strict=True)
    pending_orders = _comparison_orders(adapter)

    mt5 = adapter.module
    if after_deal is None:
        # Bootstrap a bounded recent window; a durable cursor is expected on
        # later runs. Full account history is already available via the app's
        # existing adapter and must not be retransmitted on every snapshot.
        start = datetime.now(UTC) - timedelta(days=7)
    else:
        start = datetime.fromtimestamp(max(0, after_deal[0] // 1000 - 1), tz=UTC)
    raw_deals = mt5.history_deals_get(start, datetime.now(UTC) + timedelta(days=2))
    if raw_deals is None:
        raise BrokerError(f"history_deals_get() failed: {mt5.last_error()}")
    deals = [deal_from_mt5(row) for row in raw_deals]
    deals.sort(key=lambda item: (item.time_msc, item.ticket))
    if after_deal is not None:
        deals = [item for item in deals if (item.time_msc, item.ticket) > after_deal]
    deals_after_cursor = len(deals)
    deals = deals[:MAX_DEALS]

    # Detect a terminal account switch during collection. Never label a mixed
    # snapshot with either identity.
    after = adapter.get_account()
    if (after.login, after.server) != expected or adapter._bound_account != expected:
        raise BrokerError("MT5 account changed while collecting a read-only snapshot.")

    cursor = None if after_deal is None else {"time_msc": after_deal[0], "ticket": after_deal[1]}
    if deals:
        cursor = {"time_msc": deals[-1].time_msc, "ticket": deals[-1].ticket}
    terminal = adapter.get_terminal()
    if not terminal.connected:
        raise BrokerError("Python comparison source is disconnected; comparison snapshot refused.")
    if adapter.module.account_info() is None:
        raise BrokerError(f"account_info() failed: {adapter.module.last_error()}")
    return {
        "type": "SNAPSHOT",
        "protocol": "CTEA2",
        "session_id": session_id,
        "login": expected[0],
        "server_hex": expected[1].encode("utf-8").hex(),
        "seq": seq,
        "unix_time": int(time.time()),
        "snapshot_id": f"{session_id}:{seq}",
        "broker_connected": True,
        "account": before.model_dump(mode="json"),
        "positions": [item.model_dump(mode="json") for item in positions],
        "pending_orders": pending_orders,
        "deals": [item.model_dump(mode="json") for item in deals],
        "deal_cursor": cursor,
        "source_counts": {"positions": len(positions), "pending_orders": len(pending_orders),
                          "history_selected": len(raw_deals),
                          "deals_after_cursor": deals_after_cursor},
        "deals_more": deals_after_cursor > len(deals),
        "comparison_only": True,
    }
