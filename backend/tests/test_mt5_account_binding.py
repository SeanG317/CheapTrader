"""Account identity must survive MT5 worker crashes, restarts, and terminal switches.

Uses the shared fake MetaTrader5 terminal from test_mt5_processes.py.
No actual broker account or MT5 installation is contacted.

MetaQuotes: https://www.mql5.com/en/docs/python_metatrader5/mt5accountinfo_py
"""

from __future__ import annotations

import time

import pytest

from app.broker.base import BrokerError
from app.schemas import OrderRequest
from tests.test_mt5_processes import make_adapter, make_trader, order, world  # noqa: F401


def test_worker_blocks_account_login_change_before_order_send(world) -> None:
    trader = make_trader(world)
    trader.pin_account(1, "Fake-Demo")
    trader.start()
    try:
        assert trader.call("place_order", order())["ok"]
        sent = len(world.read().get("orders", []))
        world.edit(account={"login": 2, "server": "Fake-Demo"})
        refused = trader.call("place_order", order())
        assert refused["ok"] is False
        assert "account identity changed" in (refused["error"] or "")
        assert len(world.read().get("orders", [])) == sent
    finally:
        trader.stop()


def test_worker_blocks_account_server_change_before_order_send(world) -> None:
    trader = make_trader(world)
    trader.pin_account(1, "Fake-Demo")
    trader.start()
    try:
        world.edit(account={"login": 1, "server": "Other-Broker-Live"})
        refused = trader.call("place_order", order())
        assert refused["ok"] is False
        assert "account identity changed" in (refused["error"] or "")
        assert world.read().get("orders", []) == []
    finally:
        trader.stop()


def test_restart_does_not_silently_rebind_to_new_mt5_account(world) -> None:
    trader = make_trader(world)
    trader.pin_account(1, "Fake-Demo")
    trader.start()
    try:
        trader._proc.kill()
        trader._proc.wait(timeout=5)
        time.sleep(0.1)
        world.edit(account={"login": 2, "server": "Fake-Demo"})
        with pytest.raises(BrokerError, match="authorized account"):
            trader.call("place_order", order())
        assert world.read().get("orders", []) == []
    finally:
        trader.stop()


def test_isolated_adapter_inherits_readers_account_identity(world) -> None:
    adapter = make_adapter(world)
    adapter.connect()
    try:
        assert adapter._trader._settings.mt5_expected_login == 1
        assert adapter._trader._settings.mt5_expected_server == "Fake-Demo"
        # connect() starts the trade worker asynchronously. Ensure it is ready
        # before switching the terminal account, so this tests the in-flight
        # execution guard rather than the separate startup-pin guard.
        adapter._trader.start()
        world.edit(account={"login": 2, "server": "Fake-Demo"})
        rejected = adapter.place_order(OrderRequest(symbol="EURUSD", side="BUY", volume=0.1))
        assert not rejected.ok
        assert "account identity changed" in (rejected.error or "")
        assert world.read().get("orders", []) == []
    finally:
        adapter.disconnect()


def test_child_pin_refuses_changed_identity_without_running_worker(world) -> None:
    trader = make_trader(world)
    trader.pin_account(1, "Fake-Demo")
    with pytest.raises(BrokerError, match="previously authorized"):
        trader.pin_account(2, "Fake-Demo")
    with pytest.raises(BrokerError, match="previously authorized"):
        trader.pin_account(1, "Other-Live")
    assert trader._settings.mt5_expected_login == 1
    assert trader._settings.mt5_expected_server == "Fake-Demo"
