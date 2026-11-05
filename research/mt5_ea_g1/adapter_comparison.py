"""Read-only snapshot mapping aligned with CheapTrader's existing MT5 adapter.

This module never calls a trade method. It reuses the current adapter's account,
position and pending-order mappers so the experiment tracks the app's established
schemas instead of introducing a second interpretation of broker state.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.broker.base import BrokerError
from app.broker.mt5_adapter import deal_from_mt5

from .protocol import MAX_DEALS


def collect_snapshot(adapter, *, after_deal: tuple[int, int] | None = None,
                     seq: int, session_id: str, client_nonce: str,
                     server_nonce: str) -> dict[str, Any]:
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
    pending_orders = adapter.get_orders(strict=True)

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
    deals = deals[:MAX_DEALS]

    # Detect a terminal account switch during collection. Never label a mixed
    # snapshot with either identity.
    after = adapter.get_account()
    if (after.login, after.server) != expected or adapter._bound_account != expected:
        raise BrokerError("MT5 account changed while collecting a read-only snapshot.")

    cursor = None
    if deals:
        cursor = {"time_msc": deals[-1].time_msc, "ticket": deals[-1].ticket}
    return {
        "type": "SNAPSHOT",
        "protocol": "CTEA2",
        "session_id": session_id,
        "client_nonce": client_nonce,
        "server_nonce": server_nonce,
        "login": expected[0],
        "server": expected[1],
        "seq": seq,
        "unix_time": int(time.time()),
        "account": before.model_dump(mode="json"),
        "positions": [item.model_dump(mode="json") for item in positions],
        "pending_orders": [item.model_dump(mode="json") for item in pending_orders],
        "deals": [item.model_dump(mode="json") for item in deals],
        "deal_cursor": cursor,
    }
