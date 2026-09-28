"""End to end through HTTP, with real signatures."""

from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN, fixture, make_app, retell_headers, vapi_headers, with_call


def kinds(client) -> list[str]:
    return [a["kind"] for a in client.get("/api/anomalies").json()]


def retell_post(client, raw: bytes, path: str = "/webhooks/retell"):
    return client.post(path, content=raw, headers=retell_headers(raw))


def vapi_post(client, raw: bytes):
    return client.post("/webhooks/vapi", content=raw, headers=vapi_headers(raw))


def test_healthz(client):
    assert client.get("/healthz").json()["ok"] is True


def test_unsigned_requests_are_401_and_write_nothing(client):
    """Unauthenticated traffic is logged, never stored, so it cannot fill the database."""
    for path in ("/webhooks/retell", "/webhooks/vapi", "/tools/retell"):
        assert client.post(path, content=b"{}").status_code == 401
    assert kinds(client) == []


def test_unknown_provider_is_404(client):
    assert client.post("/webhooks/twilio", content=b"{}").status_code == 404


def test_read_api_requires_the_token(store):
    anonymous = TestClient(make_app(store))
    assert anonymous.get("/api/calls").status_code == 401
    wrong = TestClient(make_app(store), headers={"authorization": "Bearer nope"})
    assert wrong.get("/api/calls").status_code == 401
    right = TestClient(make_app(store), headers={"authorization": f"Bearer {API_TOKEN}"})
    assert right.get("/api/calls").status_code == 200


def test_read_api_is_off_without_a_configured_token(store):
    """It exposes transcripts and phone numbers, so it never defaults to open."""
    assert TestClient(make_app(store, api_token="")).get("/api/calls").status_code == 403


def test_authenticated_but_unparseable_is_200_not_500(client):
    """A 5xx makes Retell retry a payload that can never succeed."""
    r = retell_post(client, b'{"event":"call_started","call":{}}')
    assert r.status_code == 200 and r.json()["accepted"] == 0
    assert "unparseable_payload" in kinds(client)


def test_unparseable_vapi_tool_call_still_gets_a_results_list(client):
    r = vapi_post(client, b'{"message":{"type":"tool-calls","toolCallList":[]}}')
    assert r.status_code == 200 and r.json() == {"results": []}


def test_retell_call_lifecycle_is_clean(client):
    for name in ("call_started", "transcript_updated", "transcript_updated", "call_ended", "call_analyzed"):
        assert retell_post(client, fixture(f"retell/{name}.json")).status_code == 200

    detail = client.get("/api/calls/Jabr9TXYYJHfvl6Syypi88rdAHYHmcq6").json()
    assert detail["state"] == "ended"
    assert len(detail["events"]) == 5
    assert kinds(client) == []


def test_retell_retry_of_call_ended_is_caught(client):
    for name in ("call_started", "call_ended", "call_ended"):
        retell_post(client, fixture(f"retell/{name}.json"))
    assert kinds(client) == ["duplicate_delivery"]


def test_vapi_tool_call_gets_the_response_vapi_waits_for(client):
    [result] = vapi_post(client, fixture("vapi/tool_calls_book.json")).json()["results"]
    assert result["toolCallId"] == "call_B7x1" and result["name"] == "book_appointment"
    assert '"booked": true' in result["result"]


def test_vapi_tool_call_redelivery_replays_and_books_once(client):
    raw = fixture("vapi/tool_calls_book.json")
    assert vapi_post(client, raw).json() == vapi_post(client, raw).json()
    assert len(client.get("/api/bookings").json()) == 1
    assert {"duplicate_delivery", "tool_call_replayed"} <= set(kinds(client))


def test_retell_function_retry_books_once(client):
    raw = fixture("retell/function_book.json")
    first = retell_post(client, raw, "/tools/retell").json()
    second = retell_post(client, raw, "/tools/retell").json()
    assert first == second == {"booked": True, "slot": "Tue 10:00"}
    assert len(client.get("/api/bookings").json()) == 1


def test_calls_are_kept_apart(client):
    for ref in ("call-a", "call-b"):
        vapi_post(client, with_call(fixture("vapi/status_in_progress.json"), ref))
    assert {c["call_ref"] for c in client.get("/api/calls").json()} == {"call-a", "call-b"}


def test_locked_database_is_503_and_commits_nothing(client, store, monkeypatch):
    """The write lock is database-wide. When it is not free, say so honestly."""
    def locked(*_):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "record_event", locked)
    r = retell_post(client, fixture("retell/call_started.json"))
    assert r.status_code == 503
    assert client.get("/api/calls").json() == []
