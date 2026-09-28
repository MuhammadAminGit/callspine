from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from callspine.app import create_app
from callspine.providers.base import hmac_sha256_hex
from callspine.providers.retell import RetellAdapter, RetellConfig
from callspine.providers.vapi import VapiAdapter, VapiConfig
from callspine.store import Store

KEY = "test-signing-key"
API_TOKEN = "test-api-token"
FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes().strip()


def with_call(raw: bytes, call_ref: str) -> bytes:
    """Re-point a fixture at another call, for tests that need several."""
    body = json.loads(raw)
    if "message" in body:
        body["message"]["call"]["id"] = call_ref
    else:
        body["call"]["call_id"] = call_ref
    return json.dumps(body).encode()


def now_ms() -> int:
    return int(time.time() * 1000)


def retell_headers(body: bytes, key: str = KEY, ts_ms: int | None = None) -> dict[str, str]:
    ts_ms = now_ms() if ts_ms is None else ts_ms
    digest = hmac_sha256_hex(key, body + str(ts_ms).encode())
    return {"x-retell-signature": f"v={ts_ms},d={digest}", "content-type": "application/json"}


def vapi_headers(body: bytes, secret: str = KEY) -> dict[str, str]:
    """Signs for the default VapiConfig: HMAC-SHA256 of the body in x-signature."""
    return {"x-signature": hmac_sha256_hex(secret, body), "content-type": "application/json"}


@pytest.fixture
def store() -> Store:
    return Store(":memory:")


def make_app(store: Store, api_token: str = API_TOKEN):
    return create_app(
        store=store,
        adapters={
            "vapi": VapiAdapter(VapiConfig(secret=KEY)),
            "retell": RetellAdapter(RetellConfig(api_key=KEY)),
        },
        api_token=api_token,
    )


@pytest.fixture
def client(store: Store) -> TestClient:
    """Carries the read-API token, so tests can inspect results through /api."""
    return TestClient(make_app(store), headers={"authorization": f"Bearer {API_TOKEN}"})
