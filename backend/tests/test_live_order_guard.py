"""Regression checks: disabling real trading blocks every broker order mutation.

The API and mock-trading paths remain usable, but no MT5 adapter call may
occur when the explicit live-trading permission is off.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

os.environ["CT_BROKER"] = "mock"

from app.api import routes  # noqa: E402
from app.main import app  # noqa: E402
from app.schemas import OrderResult  # noqa: E402

OPERATIONS = (
    ("POST", "/api/orders", {"symbol": "EURUSD", "side": "BUY", "volume": 0.1}, "place_order"),
    ("PATCH", "/api/orders", {"ticket": 111, "price": 1.1}, "modify_order"),
    ("DELETE", "/api/orders/111", None, "cancel_order"),
    ("PATCH", "/api/positions", {"ticket": 111, "sl": 1.09}, "modify_position"),
    ("DELETE", "/api/positions/111", None, "close_position"),
)


@pytest.mark.parametrize("method,path,payload,adapter_method", OPERATIONS)
@pytest.mark.parametrize(
    "broker,enabled,expected_status",
    (
        ("mt5", False, 403),
        ("mt5", True, 200),
        ("mock", False, 200),
    ),
)
def test_all_order_mutations_respect_live_permission(
    monkeypatch, method, path, payload, adapter_method, broker, enabled, expected_status
) -> None:
    methods = {
        key: Mock(return_value=OrderResult(ok=True))
        for key in ("place_order", "modify_order", "cancel_order", "modify_position", "close_position")
    }
    adapter = SimpleNamespace(name=broker, **methods)
    state = SimpleNamespace(
        broker=SimpleNamespace(adapter=adapter),
        hub=None,
        orders_allowed=lambda: enabled,
    )
    monkeypatch.setattr(routes, "get_state", lambda: state)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.request(method, path, json=payload)

    assert response.status_code == expected_status, response.text
    if expected_status == 403:
        assert "Live trading is disabled" in response.json()["detail"]
        for operation in methods.values():
            operation.assert_not_called()
    else:
        methods[adapter_method].assert_called_once()
        for key, operation in methods.items():
            if key != adapter_method:
                operation.assert_not_called()
