"""State, deduplication and latency under the delivery conditions both providers produce."""

from __future__ import annotations

import threading

import pytest

from callspine.domain import CallState, EventType, NormalizedEvent, Provider
from callspine.ingest import Ingestor, delivery_lag
from callspine.store import Store


def ev(
    etype: EventType,
    *,
    call: str = "call-1",
    key: str | None = "",
    provider: Provider = Provider.VAPI,
    provider_ts: int | None = None,
    received: int = 1_000,
) -> NormalizedEvent:
    return NormalizedEvent(
        provider=provider,
        call_ref=call,
        type=etype,
        dedupe_key=f"{etype.value}:{call}" if key == "" else key,
        provider_ts_ms=provider_ts,
        received_ts_ms=received,
        raw_type=etype.value,
    )


def kinds(store: Store) -> list[str]:
    return [a["kind"] for a in store.anomalies()]


# ---- deduplication ------------------------------------------------------------


def test_duplicate_lifecycle_event_is_counted_not_applied(store):
    ing = Ingestor(store)
    first = ing.handle([ev(EventType.CALL_STARTED)])
    again = ing.handle([ev(EventType.CALL_STARTED)])
    assert (first.accepted, again.duplicates) == (1, 1)
    assert len(store.events_for("call-1")) == 1
    assert "duplicate_delivery" in kinds(store)


def test_dedupe_is_scoped_per_provider(store):
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_STARTED, key="same", provider=Provider.VAPI)])
    r = ing.handle([ev(EventType.CALL_STARTED, key="same", provider=Provider.RETELL, call="call-2")])
    assert r.accepted == 1


def test_streams_are_always_stored(store):
    """Identical transcript deliveries are both kept; a stream has no duplicates."""
    ing = Ingestor(store)
    for _ in range(3):
        ing.handle([ev(EventType.TRANSCRIPT, key=None)])
    assert len(store.events_for("call-1")) == 3
    assert "duplicate_delivery" not in kinds(store)


# ---- ordering -----------------------------------------------------------------


def test_redelivered_start_cannot_reopen_an_ended_call(store):
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_STARTED), ev(EventType.CALL_ENDED)])
    late = ing.handle([ev(EventType.CALL_STARTED, key="late-retry")])
    assert late.rejected_transitions == 1
    assert store.get_state("call-1") is CallState.ENDED
    assert "illegal_transition" in kinds(store)


def test_ringing_arriving_after_answer_is_rejected(store):
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_STARTED)])
    ing.handle([ev(EventType.CALL_RINGING)])
    assert store.get_state("call-1") is CallState.IN_PROGRESS
    assert "illegal_transition" in kinds(store)


def test_report_after_end_is_normal(store):
    """Retell's call_analyzed and Vapi's end-of-call-report arrive after the end by design."""
    ing = Ingestor(store)
    ing.handle(
        [
            ev(EventType.CALL_STARTED),
            ev(EventType.AGENT_SPEECH_STARTED, key=None),
            ev(EventType.CALL_ENDED),
            ev(EventType.CALL_REPORT),
        ]
    )
    assert store.get_state("call-1") is CallState.ENDED
    assert kinds(store) == []


def test_agent_that_never_speaks_is_flagged(store):
    Ingestor(store).handle([ev(EventType.CALL_STARTED), ev(EventType.CALL_ENDED)])
    assert "span_open_at_end" in kinds(store)


def test_report_before_end_closes_the_call(store):
    """The report proves the call ended. The end event was lost or is still retrying."""
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_STARTED), ev(EventType.CALL_REPORT)])
    assert store.get_state("call-1") is CallState.ENDED
    assert "report_before_end" in kinds(store)

    late_end = ing.handle([ev(EventType.CALL_ENDED)])
    assert late_end.rejected_transitions == 1


def test_event_after_end_is_recorded_and_flagged(store):
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_ENDED), ev(EventType.TRANSCRIPT, key=None)])
    assert "event_after_end" in kinds(store)


def test_unknown_event_is_stored_not_dropped(store):
    r = Ingestor(store).handle([ev(EventType.UNKNOWN)])
    assert r.accepted == 1 and r.unknown_events == 1
    assert "unmapped_event" in kinds(store)


# ---- latency -------------------------------------------------------------------


def span(store: Store, name: str) -> dict:
    [s] = [s for s in store.spans_for("call-1") if s["name"] == name]
    return s


def test_ring_to_answer_and_time_to_first_word(store):
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_RINGING), ev(EventType.CALL_STARTED)])
    ing.handle([ev(EventType.AGENT_SPEECH_STARTED, key=None)])
    assert span(store, "ring_to_answer")["ended_ts_ms"] is not None
    assert span(store, "answer_to_first_word")["ended_ts_ms"] is not None


def test_first_word_delivered_before_the_answer_is_not_a_silent_agent(store):
    """Found by faultkit: a reordered speech event must not read as an agent that never spoke."""
    Ingestor(store).handle(
        [
            ev(EventType.AGENT_SPEECH_STARTED, key=None, provider_ts=5_400),
            ev(EventType.CALL_STARTED, provider_ts=5_000),
            ev(EventType.CALL_ENDED, provider_ts=9_000),
        ]
    )
    assert span(store, "answer_to_first_word")["duration_ms"] == 400
    assert "span_open_at_end" not in kinds(store)


def test_retell_calls_do_not_open_a_speech_span_they_can_never_close(store):
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_STARTED, provider=Provider.RETELL), ev(EventType.CALL_ENDED, provider=Provider.RETELL)])
    assert store.spans_for("call-1") == []
    assert "span_open_at_end" not in kinds(store)


def test_unanswered_call_is_flagged_by_its_open_span(store):
    Ingestor(store).handle([ev(EventType.CALL_RINGING), ev(EventType.CALL_ENDED)])
    assert span(store, "ring_to_answer")["ended_ts_ms"] is not None
    assert "span_open_at_end" in kinds(store)


def test_spans_use_the_provider_clock_not_arrival(store):
    """Delivery jitter must not show up as the caller waiting longer."""
    Ingestor(store).handle(
        [
            ev(EventType.CALL_RINGING, provider_ts=10_000, received=10_900),
            ev(EventType.CALL_STARTED, provider_ts=12_000, received=12_050),
        ]
    )
    assert span(store, "ring_to_answer")["duration_ms"] == 2_000


def test_a_span_cannot_be_opened_twice(store):
    assert store.open_span("call-1", "ring_to_answer", 1, {}) is True
    assert store.open_span("call-1", "ring_to_answer", 2, {}) is False
    assert len(store.spans_for("call-1")) == 1


def test_open_spans_survive_a_restart(store):
    """Open spans live in the database, so a new worker closes what an old one opened."""
    Ingestor(store).handle([ev(EventType.CALL_RINGING)])
    Ingestor(store).handle([ev(EventType.CALL_STARTED)])
    assert span(store, "ring_to_answer")["ended_ts_ms"] is not None


def test_delivery_lag_from_both_clocks(store):
    Ingestor(store).handle(
        [
            ev(EventType.CALL_STARTED, provider_ts=1_000, received=1_300),
            ev(EventType.TRANSCRIPT, key=None, provider_ts=2_000, received=6_000),
        ]
    )
    assert delivery_lag(store, "call-1") == {"samples": 2, "median_ms": 4_000, "max_ms": 4_000}


# ---- atomicity -----------------------------------------------------------------


def test_failure_mid_event_lets_the_retry_through(store, monkeypatch):
    """If processing fails after the event was recorded, the retry must not be a 'duplicate'.

    Recording the event and writing the call's state commit together, so a failure rolls
    back the dedupe row too, and the provider's retry is processed normally.
    """
    real = store.upsert_call
    monkeypatch.setattr(store, "upsert_call", lambda *a: (_ for _ in ()).throw(RuntimeError("disk")))
    with pytest.raises(RuntimeError):
        Ingestor(store).handle([ev(EventType.CALL_STARTED)])
    assert store.events_for("call-1") == []

    monkeypatch.setattr(store, "upsert_call", real)
    retry = Ingestor(store).handle([ev(EventType.CALL_STARTED)])
    assert retry.accepted == 1 and retry.duplicates == 0
    assert store.get_state("call-1") is CallState.IN_PROGRESS


def test_two_workers_cannot_reopen_an_ended_call(tmp_path, monkeypatch):
    """Two workers on one database race the start and the end of the same call.

    Worker A reads the call as ringing, then stalls for up to a second, which gives
    worker B every chance to process the end in between. Without the write lock, B ends
    the call and A then overwrites it with in_progress. With it, B cannot begin until A
    commits, so B applies the end on top of A's state and the call finishes ended.
    """
    path = str(tmp_path / "workers.db")
    store_a, store_b = Store(path), Store(path)
    Ingestor(store_a).handle([ev(EventType.CALL_RINGING)])

    a_has_read, b_finished = threading.Event(), threading.Event()
    real_get_state = store_a.get_state

    def stalling_get_state(call_ref):
        state = real_get_state(call_ref)
        a_has_read.set()
        b_finished.wait(timeout=1.0)
        return state

    monkeypatch.setattr(store_a, "get_state", stalling_get_state)

    def worker_b() -> None:
        a_has_read.wait()
        Ingestor(store_b).handle([ev(EventType.CALL_ENDED)])
        b_finished.set()

    b = threading.Thread(target=worker_b)
    b.start()
    Ingestor(store_a).handle([ev(EventType.CALL_STARTED)])
    b.join()

    assert Store(path).get_state("call-1") is CallState.ENDED


def test_first_word_is_the_earliest_spoken_not_the_first_delivered(store):
    """Turn 2 arriving before turn 1 must not stretch the span."""
    Ingestor(store).handle(
        [
            ev(EventType.AGENT_SPEECH_STARTED, key=None, provider_ts=7_000),
            ev(EventType.AGENT_SPEECH_STARTED, key=None, provider_ts=5_300),
            ev(EventType.CALL_STARTED, provider_ts=5_000),
        ]
    )
    assert span(store, "answer_to_first_word")["duration_ms"] == 300


def test_first_word_stamped_before_the_answer_is_flagged_not_hidden(store):
    Ingestor(store).handle(
        [
            ev(EventType.AGENT_SPEECH_STARTED, key=None, provider_ts=4_900),
            ev(EventType.CALL_STARTED, provider_ts=5_000),
        ]
    )
    assert span(store, "answer_to_first_word")["duration_ms"] == 0
    assert "clock_disagreement" in kinds(store)


def test_transactions_do_not_nest(store):
    with store.transaction(), pytest.raises(RuntimeError, match="do not nest"), store.transaction():
        pass
