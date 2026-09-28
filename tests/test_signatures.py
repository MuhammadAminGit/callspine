"""Signature verification for both providers, including the failure that only shows in production."""

from __future__ import annotations

import json

import pytest

from callspine.providers.base import SignatureError, hmac_sha256_hex
from callspine.providers.retell import RetellAdapter, RetellConfig, parse_signature_header
from callspine.providers.vapi import VapiAdapter, VapiConfig
from tests.conftest import KEY, now_ms, retell_headers, vapi_headers

# ---- Vapi ------------------------------------------------------------------------


def test_vapi_hmac_body_only_default():
    body = b'{"message":{"type":"status-update"}}'
    VapiAdapter(VapiConfig(secret=KEY)).verify(body, vapi_headers(body))


def test_vapi_hmac_rejects_wrong_secret():
    body = b'{"message":{}}'
    with pytest.raises(SignatureError, match="mismatch"):
        VapiAdapter(VapiConfig(secret=KEY)).verify(body, vapi_headers(body, secret="other"))


def test_vapi_signature_header_is_whatever_the_credential_says():
    """Vapi publishes no default header, so the configured one is the only one accepted."""
    body = b"{}"
    adapter = VapiAdapter(VapiConfig(secret=KEY, signature_header="X-Hook-Sig"))
    adapter.verify(body, {"x-hook-sig": hmac_sha256_hex(KEY, body)})
    with pytest.raises(SignatureError, match="missing"):
        adapter.verify(body, vapi_headers(body))


def test_vapi_timestamped_format_roundtrip():
    cfg = VapiConfig(secret=KEY, timestamp_header="x-timestamp", payload_format="{timestamp}.{body}")
    body, ts = b'{"a":1}', str(now_ms())
    sig = hmac_sha256_hex(KEY, ts.encode() + b"." + body)
    VapiAdapter(cfg).verify(body, {"x-signature": sig, "x-timestamp": ts})


def test_vapi_timestamped_format_rejects_replay():
    cfg = VapiConfig(secret=KEY, timestamp_header="x-timestamp", payload_format="{timestamp}.{body}")
    body, ts = b"{}", str(now_ms() - 3_600_000)
    sig = hmac_sha256_hex(KEY, ts.encode() + b"." + body)
    with pytest.raises(SignatureError, match="replay window"):
        VapiAdapter(cfg).verify(body, {"x-signature": sig, "x-timestamp": ts})


def test_vapi_shared_secret_header_and_bearer():
    adapter = VapiAdapter(VapiConfig(mode="shared_secret", secret=KEY))
    adapter.verify(b"{}", {"x-vapi-secret": KEY})
    adapter.verify(b"{}", {"authorization": f"Bearer {KEY}"})
    with pytest.raises(SignatureError):
        adapter.verify(b"{}", {"x-vapi-secret": "wrong"})


def test_vapi_config_refuses_incoherent_credentials():
    with pytest.raises(ValueError):
        VapiConfig(payload_format="{timestamp}.{body}", timestamp_header="")
    with pytest.raises(ValueError):
        VapiConfig(mode="magic")


# ---- Retell ----------------------------------------------------------------------


def test_retell_roundtrip():
    body = b'{"event":"call_started","call":{"call_id":"c1"}}'
    RetellAdapter(RetellConfig(api_key=KEY)).verify(body, retell_headers(body))


def test_retell_rejects_tampered_body():
    body = b'{"event":"call_started","call":{"call_id":"c1"}}'
    headers = retell_headers(body)
    with pytest.raises(SignatureError, match="mismatch"):
        RetellAdapter(RetellConfig(api_key=KEY)).verify(body.replace(b"c1", b"c2"), headers)


def test_retell_enforces_documented_five_minute_window():
    body = b"{}"
    adapter = RetellAdapter(RetellConfig(api_key=KEY))
    adapter.verify(body, retell_headers(body, ts_ms=now_ms() - 240_000))
    with pytest.raises(SignatureError, match="replay window"):
        adapter.verify(body, retell_headers(body, ts_ms=now_ms() - 360_000))


def test_retell_window_can_only_be_disabled_explicitly():
    body = b"{}"
    adapter = RetellAdapter(RetellConfig(api_key=KEY, enforce_replay_window=False))
    adapter.verify(body, retell_headers(body, ts_ms=now_ms() - 3_600_000))


def test_retell_signature_parser_tolerates_order_and_spacing():
    assert parse_signature_header("d=abc123 , v=1700000000000") == (1700000000000, "abc123")


def test_retell_signature_parser_rejects_incomplete_header():
    with pytest.raises(SignatureError):
        parse_signature_header("v=123")


# ---- The one that matters ------------------------------------------------------------


def test_reserialised_json_breaks_the_signature():
    """Why every adapter takes raw bytes, never a parsed dict.

    Retell's docs warn about this. A caller named Zoë is enough: `json.dumps` escapes the
    character and changes separators, so the bytes the provider signed and the bytes the
    server hashes differ. This passes in any suite that only uses ASCII names.
    """
    original = '{"caller":"Zoë","amount":1.0}'.encode()
    reserialised = json.dumps(json.loads(original)).encode()
    assert original != reserialised

    adapter = RetellAdapter(RetellConfig(api_key=KEY))
    headers = retell_headers(original)
    adapter.verify(original, headers)
    with pytest.raises(SignatureError):
        adapter.verify(reserialised, headers)
