"""Adapters against payloads shaped like each provider's documentation."""

from __future__ import annotations

import pytest

from callspine.domain import EventType, Provider
from callspine.providers.retell import RetellAdapter, RetellConfig
from callspine.providers.vapi import VapiAdapter, VapiConfig, is_tool_call
from tests.conftest import KEY, fixture, retell_headers

RETELL_CALL = "Jabr9TXYYJHfvl6Syypi88rdAHYHmcq6"
VAPI_CALL = "c7e0b6f2-3a51-4d7e-9a41-2f0d5a1b8e11"

retell = RetellAdapter(RetellConfig(api_key=KEY))
vapi = VapiAdapter(VapiConfig(secret=KEY))


def rnorm(name: str):
    raw = fixture(f"retell/{name}.json")
    [event] = retell.normalize(raw, retell_headers(raw), received_ts_ms=0)
    return event


def vnorm(name: str):
    [event] = vapi.normalize(fixture(f"vapi/{name}.json"), {}, received_ts_ms=0)
    return event


# ---- Retell: types and the documented idempotency keys -------------------------


@pytest.mark.parametrize(
    ("name", "etype", "key"),
    [
        ("call_started", EventType.CALL_STARTED, f"call_started:{RETELL_CALL}"),
        ("call_ended", EventType.CALL_ENDED, f"call_ended:{RETELL_CALL}"),
        ("call_analyzed", EventType.CALL_REPORT, f"call_analyzed:{RETELL_CALL}"),
    ],
)
def test_retell_lifecycle_keyed_on_event_and_call_id(name, etype, key):
    e = rnorm(name)
    assert (e.provider, e.call_ref, e.type, e.dedupe_key) == (Provider.RETELL, RETELL_CALL, etype, key)


def test_retell_transcript_updated_is_a_stream():
    """Retell's docs: treat each delivery as an incremental update, not a duplicate."""
    e = rnorm("transcript_updated")
    assert e.type is EventType.TRANSCRIPT and e.dedupe_key is None


def test_retell_transfer_key_includes_start_and_destination():
    e = rnorm("transfer_started")
    assert e.type is EventType.TRANSFER
    assert e.dedupe_key.startswith(f"transfer_started:{RETELL_CALL}:1714608475945:")
    assert "+14155550150" in e.dedupe_key


def test_retell_timestamp_comes_from_the_signature():
    raw = fixture("retell/call_started.json")
    [e] = retell.normalize(raw, retell_headers(raw, ts_ms=1_700_000_000_000), received_ts_ms=0)
    assert e.provider_ts_ms == 1_700_000_000_000


def test_retell_chat_events_are_refused_not_misfiled():
    """Voice only. A chat event has no call_id, and inventing one would be worse."""
    raw = fixture("retell/chat_started.json")
    with pytest.raises(ValueError, match="call_id"):
        retell.normalize(raw, retell_headers(raw), received_ts_ms=0)


def test_retell_function_call_has_no_invocation_id():
    inv = retell.parse_function_call(fixture("retell/function_book.json"))
    assert (inv.call_ref, inv.name, inv.args) == (RETELL_CALL, "book_appointment", {"slot": "Tue 10:00"})
    assert inv.invocation_id is None


def test_retell_function_call_in_args_only_mode_is_refused():
    with pytest.raises(ValueError, match="args only"):
        retell.parse_function_call(b'{"slot":"Tue 10:00"}')


# ---- Vapi: types and derived keys ------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "etype"),
    [
        ("status_queued", EventType.CALL_QUEUED),
        ("status_ringing", EventType.CALL_RINGING),
        ("status_in_progress", EventType.CALL_STARTED),
        ("status_ended", EventType.CALL_ENDED),
        ("end_of_call_report", EventType.CALL_REPORT),
    ],
)
def test_vapi_lifecycle_types(name, etype):
    e = vnorm(name)
    assert (e.provider, e.call_ref, e.type) == (Provider.VAPI, VAPI_CALL, etype)
    assert e.dedupe_key is not None


def test_vapi_each_status_is_its_own_event():
    assert vnorm("status_ringing").dedupe_key != vnorm("status_in_progress").dedupe_key


def test_vapi_assistant_speech_start_is_distinguished():
    assert vnorm("speech_assistant_started").type is EventType.AGENT_SPEECH_STARTED
    assert vnorm("speech_user_stopped").type is EventType.SPEECH


@pytest.mark.parametrize("name", ["transcript_final", "speech_assistant_started", "speech_user_stopped"])
def test_vapi_streams_are_never_deduplicated(name):
    assert vnorm(name).dedupe_key is None


def test_vapi_uninterpreted_type_is_kept_as_unknown():
    e = vnorm("hang")
    assert e.type is EventType.UNKNOWN and e.raw_type == "hang" and e.dedupe_key


def test_vapi_payload_timestamp_is_used_for_lag():
    assert vnorm("status_ringing").provider_ts_ms == 1714608475945


@pytest.mark.parametrize("name", ["tool_calls_book", "tool_calls_string_args"])
def test_vapi_tool_calls_parse_object_and_string_arguments(name):
    raw = fixture(f"vapi/{name}.json")
    assert is_tool_call(raw)
    [inv] = vapi.tool_calls(raw)
    assert inv.call_ref == VAPI_CALL and inv.name == "book_appointment"
    assert inv.invocation_id and isinstance(inv.args, dict) and "slot" in inv.args


def test_vapi_tool_call_without_id_is_refused():
    raw = (
        b'{"message":{"type":"tool-calls","call":{"id":"c"},'
        b'"toolCallList":[{"function":{"name":"x","arguments":{}}}]}}'
    )
    with pytest.raises(ValueError, match="without id"):
        vapi.tool_calls(raw)


def test_vapi_message_without_call_id_is_refused():
    with pytest.raises(ValueError, match="call.id"):
        vapi.normalize(b'{"message":{"type":"status-update","status":"ringing"}}', {}, 0)
