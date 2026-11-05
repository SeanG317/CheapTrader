"""Pure reference model for G1 deal paging; it is not a broker data source.

The MQL5 EA performs the native reads. This module makes the required ordering,
failure, scan-bound, and cursor semantics executable in protocol unit tests.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from protocol import MAX_DEALS, MAX_HISTORY_SCAN, ProtocolError


def build_deal_page(
    records: Sequence[Mapping[str, Any]] | None,
    committed_cursor: tuple[int, int] | None,
    *,
    scan_limit: int = MAX_HISTORY_SCAN,
    page_size: int = MAX_DEALS,
) -> dict[str, Any]:
    """Sort and page complete native-shaped records by (time_msc, ticket).

    ``None`` represents a failed HistorySelect/read operation, while an empty
    sequence is a successfully selected empty history. Invalid or unreadable
    entries abort the entire page, so no later cursor can skip them.
    """
    if records is None:
        raise ProtocolError("history_read_failed")
    if len(records) > scan_limit:
        raise ProtocolError("history_scan_limit_exceeded")
    by_ticket: dict[int, dict[str, Any]] = {}
    for index, raw in enumerate(records):
        if not isinstance(raw, Mapping):
            raise ProtocolError(f"history_record_read_failed:{index}")
        ticket = raw.get("ticket")
        time_msc = raw.get("time_msc")
        if (isinstance(ticket, bool) or not isinstance(ticket, int) or ticket <= 0
                or isinstance(time_msc, bool) or not isinstance(time_msc, int) or time_msc < 0):
            raise ProtocolError(f"history_record_read_failed:{index}")
        record = dict(raw)
        prior = by_ticket.get(ticket)
        if prior is not None and prior != record:
            raise ProtocolError("deal_ticket_payload_conflict")
        by_ticket[ticket] = record
    ordered = sorted(by_ticket.values(), key=lambda row: (row["time_msc"], row["ticket"]))
    after = [row for row in ordered if committed_cursor is None or
             (row["time_msc"], row["ticket"]) > committed_cursor]
    page = after[:page_size]
    cursor = committed_cursor if not page else (page[-1]["time_msc"], page[-1]["ticket"])
    return {
        "history_selected": len(records),
        "deals_after_cursor": len(after),
        "deals": page,
        "cursor": cursor,
        "more": len(after) > len(page),
    }
