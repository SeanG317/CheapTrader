"""Verify cross-origin protection on all live-account mutation routes.

An attacker-controlled browser tab must be rejected by the ASGI middleware
before it can reach the broker, even when the broker is not connected.
These tests use the mock backend and never contact a live MT5 account.
"""

from __future__ import annotations

import os

os.environ["CT_BROKER"] = "mock"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

MUTATIONS = (
    ("POST", "/api/orders", {"symbol": "EURUSD", "side": "BUY", "volume": 0.1}),
    ("PATCH", "/api/orders", {"ticket": 14, "price": 1.10}),
    ("DELETE", "/api/orders/14", None),
    ("PATCH", "/api/positions", {"ticket": 14, "sl": 1.09}),
    ("DELETE", "/api/positions/14", None),
)


@pytest.mark.parametrize("method,path,payload", MUTATIONS)
def test_foreign_origin_cannot_mutate_broker(method, path, payload) -> None:
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.request(
            method, path, json=payload,
            headers={"Origin": "https://untrusted.example"},
        )

    assert response.status_code == 403
    assert "Another web page" in response.json()["detail"]


@pytest.mark.parametrize("method,path,payload", MUTATIONS)
def test_dns_rebinding_host_cannot_mutate_broker(method, path, payload) -> None:
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.request(
            method, path, json=payload,
            headers={"Host": "attacker.example:8765"},
        )

    assert response.status_code == 400
