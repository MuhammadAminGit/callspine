"""Signature verification, including the failure that only shows up in production."""

from __future__ import annotations

import json
import time

import pytest

from callspine.providers.base import SignatureError, hmac_sha256_hex
from callspine.providers.retell import RetellAdapter, RetellConfig, parse_signature_header
from callspine.providers.vapi import VapiAdapter, VapiConfig

SECRET = "shhh-not-a-real-secret"


def _now_ms() -> int:
    return int(time.time() * 1000)


# --- Vapi ------------------------------------------------------------------


def test_vapi_shared_secret_accepts_matching_header():
    adapter = VapiAdapter(VapiConfig(mode="shared_secret", secret=SECRET))
    adapter.verify(b"{}", {"x-vapi-secret": SECRET})


def test_vapi_shared_secret_accepts_bearer():
    adapter = VapiAdapter(VapiConfig(mode="shared_secret", secret=SECRET))
    adapter.verify(b"{}", {"authorization": f"Bearer {SECRET}"})


def test_vapi_shared_secret_rejects_wrong_value():
    adapter = VapiAdapter(VapiConfig(mode="shared_secret", secret=SECRET))
    with pytest.raises(SignatureError):
        adapter.verify(b"{}", {"x-vapi-secret": "wrong"})


def test_vapi_hmac_timestamped_roundtrip():
    adapter = VapiAdapter(VapiConfig(mode="hmac", secret=SECRET))
    body = b'{"message":{"type":"status-update"}}'
    ts = str(_now_ms())
    sig = hmac_sha256_hex(SECRET, ts.encode() + b"." + body)
    adapter.verify(body, {"x-vapi-signature": sig, "x-timestamp": ts})


def test_vapi_hmac_rejects_stale_timestamp():
    adapter = VapiAdapter(VapiConfig(mode="hmac", secret=SECRET))
    body = b"{}"
    ts = str(_now_ms() - 3_600_000)  # an hour old
    sig = hmac_sha256_hex(SECRET, ts.encode() + b"." + body)
    with pytest.raises(SignatureError, match="replay window"):
        adapter.verify(body, {"x-vapi-signature": sig, "x-timestamp": ts})


def test_vapi_body_only_format_ignores_timestamp():
    adapter = VapiAdapter(VapiConfig(mode="hmac", secret=SECRET, payload_format="{body}"))
    body = b'{"a":1}'
    adapter.verify(body, {"x-vapi-signature": hmac_sha256_hex(SECRET, body)})


def test_vapi_config_rejects_incoherent_setup():
    with pytest.raises(ValueError):
        VapiConfig(payload_format="{timestamp}.{body}", timestamp_header="")
    with pytest.raises(ValueError):
        VapiConfig(mode="magic")


# --- Retell ----------------------------------------------------------------


def _retell_headers(body: bytes, key: str, ts_ms: int | None = None) -> dict[str, str]:
    ts_ms = ts_ms if ts_ms is not None else _now_ms()
    digest = hmac_sha256_hex(key, body + str(ts_ms).encode())
    return {"x-retell-signature": f"v={ts_ms},d={digest}"}


def test_retell_roundtrip():
    adapter = RetellAdapter(RetellConfig(api_key=SECRET))
    body = b'{"event":"call_started","call":{"call_id":"c1"}}'
    adapter.verify(body, _retell_headers(body, SECRET))


def test_retell_rejects_tampered_body():
    adapter = RetellAdapter(RetellConfig(api_key=SECRET))
    body = b'{"event":"call_started","call":{"call_id":"c1"}}'
    headers = _retell_headers(body, SECRET)
    with pytest.raises(SignatureError):
        adapter.verify(body.replace(b"c1", b"c2"), headers)


def test_retell_enforces_replay_window_by_default():
    adapter = RetellAdapter(RetellConfig(api_key=SECRET))
    body = b"{}"
    old = _now_ms() - 3_600_000
    with pytest.raises(SignatureError, match="replay window"):
        adapter.verify(body, _retell_headers(body, SECRET, ts_ms=old))


def test_retell_replay_window_can_be_disabled_explicitly():
    """Disabling is allowed but must be a deliberate act, never a silent default."""
    adapter = RetellAdapter(RetellConfig(api_key=SECRET, enforce_replay_window=False))
    body = b"{}"
    old = _now_ms() - 3_600_000
    adapter.verify(body, _retell_headers(body, SECRET, ts_ms=old))


def test_retell_signature_parser_tolerates_spacing_and_order():
    ts, digest = parse_signature_header("d=abc123 , v=1700000000000")
    assert ts == 1700000000000
    assert digest == "abc123"


def test_retell_signature_parser_rejects_incomplete_header():
    with pytest.raises(SignatureError):
        parse_signature_header("v=123")


# --- The one that matters --------------------------------------------------


def test_reserialised_json_breaks_the_signature():
    """Why adapters take raw bytes and never a parsed dict.

    A caller named Zoë is enough to break a verifier that re-serialises the body before
    hashing. `json.dumps` escapes the non-ASCII character and changes the separators, so
    the bytes signed by the provider and the bytes hashed by the server differ.

    This test exists to pin that behaviour, because it passes in every test suite that
    only ever uses ASCII names and fails on the first real call.
    """
    original = '{"caller":"Zoë","amount":1.0}'.encode()
    reserialised = json.dumps(json.loads(original)).encode()

    assert original != reserialised
    assert hmac_sha256_hex(SECRET, original) != hmac_sha256_hex(SECRET, reserialised)

    adapter = RetellAdapter(RetellConfig(api_key=SECRET))
    headers = _retell_headers(original, SECRET)
    adapter.verify(original, headers)  # raw bytes: fine
    with pytest.raises(SignatureError):
        adapter.verify(reserialised, headers)  # round-tripped: broken
