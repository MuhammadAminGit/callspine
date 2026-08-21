"""End to end through the HTTP layer, with real signatures."""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from callspine.app import create_app
from callspine.providers.base import hmac_sha256_hex
from callspine.providers.retell import RetellAdapter, RetellConfig
from callspine.providers.vapi import VapiAdapter, VapiConfig
from callspine.store import Store

KEY = "test-key"


@pytest.fixture
def client() -> TestClient:
    app = create_app(
        store=Store(":memory:"),
        adapters={
            "vapi": VapiAdapter(VapiConfig(mode="hmac", secret=KEY)),
            "retell": RetellAdapter(RetellConfig(api_key=KEY)),
        },
    )
    return TestClient(app)


def retell_post(client: TestClient, payload: dict):
    body = json.dumps(payload).encode()
    ts = int(time.time() * 1000)
    digest = hmac_sha256_hex(KEY, body + str(ts).encode())
    return client.post(
        "/webhooks/retell",
        content=body,
        headers={"x-retell-signature": f"v={ts},d={digest}"},
    )


def test_healthz(client: TestClient):
    assert client.get("/healthz").json()["ok"] is True


def test_unsigned_webhook_is_401(client: TestClient):
    r = client.post("/webhooks/retell", content=b"{}")
    assert r.status_code == 401


def test_unknown_provider_is_404(client: TestClient):
    r = client.post("/webhooks/nope", content=b"{}")
    assert r.status_code == 404


def test_full_call_lifecycle(client: TestClient):
    for event in ("call_started", "call_ringing", "call_answered", "call_ended"):
        r = retell_post(client, {"event": event, "call": {"call_id": "e2e-1"}})
        assert r.status_code == 200

    detail = client.get("/api/calls/e2e-1").json()
    assert detail["state"] == "ended"
    assert len(detail["events"]) == 4


def test_authenticated_but_unparseable_returns_200_not_500(client: TestClient):
    """Returning 5xx here would make the provider retry a payload that can never work.

    One malformed event should not become an infinite retry loop. It becomes an
    anomaly row instead, which is visible without being self-inflicted load.
    """
    body = json.dumps({"event": "call_started"}).encode()  # no call_id
    ts = int(time.time() * 1000)
    digest = hmac_sha256_hex(KEY, body + str(ts).encode())
    r = client.post(
        "/webhooks/retell",
        content=body,
        headers={"x-retell-signature": f"v={ts},d={digest}"},
    )
    assert r.status_code == 200
    assert r.json()["accepted"] == 0

    kinds = [a["kind"] for a in client.get("/api/anomalies").json()]
    assert "unparseable_payload" in kinds


def test_tool_endpoint_rejects_slot_the_agent_invented(client: TestClient):
    """Models propose slots that were never offered. The tool is the last line."""
    r = client.post("/tools/book", json={"call_id": "e2e-2", "slot": "Sun 03:00"})
    assert r.json()["booked"] is False
    kinds = [a["kind"] for a in client.get("/api/anomalies").json()]
    assert "invalid_slot" in kinds


def test_tool_endpoint_accepts_offered_slot(client: TestClient):
    slots = client.post("/tools/check_availability", json={"call_id": "e2e-3"}).json()["slots"]
    r = client.post("/tools/book", json={"call_id": "e2e-3", "slot": slots[0]})
    assert r.json()["booked"] is True
