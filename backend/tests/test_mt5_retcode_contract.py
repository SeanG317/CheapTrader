"""MT5 server retcode contract — verified against MetaQuotes documentation.

https://www.mql5.com/en/docs/constants/errorswarnings/enum_trade_return_codes
https://www.mql5.com/en/docs/python_metatrader5/mt5ordersend_py

Use a fake in-memory terminal: these tests never connect to an account.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.broker.mt5_adapter import MT5Adapter
from app.config import Settings


@pytest.mark.parametrize(
    "action,retcode,expected_ok,expected_message",
    [
        (5, 10008, True, None),          # TRADE_ACTION_PENDING + TRADE_RETCODE_PLACED
        (5, 10009, True, None),          # pending request completed
        (1, 10009, True, None),          # TRADE_ACTION_DEAL + completed
        (1, 10008, False, "not confirmed full execution"),
        (1, 10010, False, "partially filled"),
        (1, 10012, False, "execution status is uncertain"),
        (6, 10025, True, None),          # TRADE_ACTION_SLTP, unchanged
        (7, 10025, True, None),          # TRADE_ACTION_MODIFY, unchanged
        (1, 10025, False, "accepted by broker"),  # cannot count DEAL no-op as a fill
    ],
)
def test_mt5_return_code_semantics(action, retcode, expected_ok, expected_message) -> None:
    class FakeTerminal:
        TRADE_ACTION_DEAL = 1
        TRADE_ACTION_PENDING = 5
        TRADE_ACTION_SLTP = 6
        TRADE_ACTION_MODIFY = 7
        TRADE_RETCODE_DONE = 10009
        TRADE_RETCODE_PLACED = 10008
        TRADE_RETCODE_NO_CHANGES = 10025
        TRADE_RETCODE_REQUOTE = 10004
        TRADE_RETCODE_PRICE_CHANGED = 10020
        TRADE_RETCODE_PRICE_OFF = 10021
        TRADE_RETCODE_INVALID_FILL = 10030
        ORDER_FILLING_RETURN = 2
        ORDER_FILLING_FOK = 0
        ORDER_FILLING_IOC = 1

        def __init__(self):
            self.calls = 0

        def account_info(self):
            return SimpleNamespace(login=1, server="Fake-Demo")

        def order_send(self, payload):
            self.calls += 1
            return SimpleNamespace(
                retcode=retcode, order=123, deal=456, volume=0.05,
                price=1.2345, comment="accepted by broker",
            )

    mt5 = FakeTerminal()
    adapter = MT5Adapter(Settings(_env_file=None))
    adapter._mt5 = mt5
    adapter._bound_account = (1, "Fake-Demo")

    result = adapter._send({"action": action, "symbol": "EURUSD", "volume": 0.1})
    assert result.retcode == retcode
    assert result.ok is expected_ok
    assert result.order_id == 123 and result.deal_id == 456
    assert result.volume == 0.05
    assert mt5.calls == 1, "Do not retry uncertain or partially executed requests"
    if expected_message is None:
        assert result.error is None
    else:
        assert expected_message in (result.error or "")
