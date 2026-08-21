"""Behaviour under the failures both providers actually produce."""

from __future__ import annotations

import pytest

from callspine.domain import (
    CallState,
    CallStateMachine,
    EventType,
    NormalizedEvent,
    Provider,
    TransitionRejected,
)
from callspine.ingest import Ingestor
from callspine.store import Store


@pytest.fixture
def store() -> Store:
    return Store(":memory:")


def ev(
    etype: EventType,
    *,
    call="call-1",
    eid=None,
    provider=Provider.VAPI,
    provider_ts=None,
    received=1_000,
) -> NormalizedEvent:
    return NormalizedEvent(
        provider=provider,
        provider_event_id=eid or f"{call}:{etype.value}",
        call_ref=call,
        type=etype,
        provider_ts_ms=provider_ts,
        received_ts_ms=received,
        payload={"raw_type": etype.value},
    )


# --- deduplication ---------------------------------------------------------


def test_duplicate_delivery_is_counted_not_applied(store: Store):
    ing = Ingestor(store)
    first = ing.handle([ev(EventType.CALL_RINGING)])
    second = ing.handle([ev(EventType.CALL_RINGING)])

    assert first.accepted == 1 and first.duplicates == 0
    assert second.accepted == 0 and second.duplicates == 1
    assert len(store.events_for("call-1")) == 1

    kinds = [a["kind"] for a in store.anomalies()]
    assert "duplicate_delivery" in kinds


def test_dedupe_is_scoped_per_provider(store: Store):
    """The same event id from two providers is two events, not a collision."""
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_RINGING, eid="shared-id", provider=Provider.VAPI)])
    r = ing.handle([ev(EventType.CALL_RINGING, eid="shared-id", provider=Provider.RETELL)])
    assert r.accepted == 1 and r.duplicates == 0


# --- ordering --------------------------------------------------------------


def test_event_after_hangup_does_not_reopen_the_call(store: Store):
    """The bug this whole layer exists to prevent.

    A provider redelivers `call.answered` after the call already ended. Assigning
    whatever the newest event implies would flip a finished call back to answered, and
    the dashboard and database would disagree from then on.
    """
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_RINGING)])
    ing.handle([ev(EventType.CALL_ANSWERED)])
    ing.handle([ev(EventType.CALL_ENDED)])
    assert store.get_state("call-1") is CallState.ENDED

    late = ing.handle([ev(EventType.CALL_ANSWERED, eid="late-answer")])

    assert late.rejected_transitions == 1
    assert store.get_state("call-1") is CallState.ENDED
    assert "illegal_transition" in [a["kind"] for a in store.anomalies()]


def test_transcript_after_hangup_is_recorded_as_anomaly(store: Store):
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_ENDED)])
    ing.handle([ev(EventType.TRANSCRIPT, eid="t-late")])
    assert "post_hangup_event" in [a["kind"] for a in store.anomalies()]


def test_state_machine_rejects_answer_before_ring_context():
    machine = CallStateMachine(state=CallState.ENDED)
    with pytest.raises(TransitionRejected):
        machine.apply(ev(EventType.CALL_ANSWERED))


def test_answered_progresses_to_in_progress_on_first_transcript():
    machine = CallStateMachine(state=CallState.ANSWERED)
    assert machine.apply(ev(EventType.TRANSCRIPT)) is CallState.IN_PROGRESS


# --- unmapped events -------------------------------------------------------


def test_unknown_event_is_stored_not_dropped(store: Store):
    ing = Ingestor(store)
    r = ing.handle([ev(EventType.UNKNOWN, eid="weird")])
    assert r.accepted == 1 and r.unknown_events == 1
    assert len(store.events_for("call-1")) == 1
    assert "unmapped_event" in [a["kind"] for a in store.anomalies()]


# --- spans -----------------------------------------------------------------


def test_ring_to_answer_span_opens_and_closes(store: Store):
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_RINGING)])
    ing.handle([ev(EventType.CALL_ANSWERED)])

    spans = [s for s in store.spans_for("call-1") if s["name"] == "ring_to_answer"]
    assert len(spans) == 1
    assert spans[0]["ended_ts_ms"] is not None


def test_open_span_is_closed_at_hangup_and_flagged(store: Store):
    """A dropped call must not leave a span that looks infinitely long."""
    ing = Ingestor(store)
    ing.handle([ev(EventType.CALL_RINGING)])
    ing.handle([ev(EventType.CALL_ENDED)])

    spans = store.spans_for("call-1")
    assert all(s["ended_ts_ms"] is not None for s in spans)
    assert "span_unclosed_at_hangup" in [a["kind"] for a in store.anomalies()]


def test_delivery_lag_is_derived_from_both_clocks():
    e = ev(EventType.TRANSCRIPT, provider_ts=1_000, received=4_500)
    assert e.delivery_lag_ms == 3_500


def test_delivery_lag_is_none_without_provider_clock():
    assert ev(EventType.TRANSCRIPT, provider_ts=None).delivery_lag_ms is None
