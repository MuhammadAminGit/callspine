"""The path every webhook takes: verify, normalize, dedupe, advance state, record.

Each stage can fail in a way that is *expected* rather than exceptional, and the
difference between a system you can debug and one you cannot is whether those
expected failures get written down. Duplicates, illegal transitions, unmapped event
types and post-hangup chatter all land in the anomalies table instead of being
swallowed or crashing the request.

Returning 200 for an authenticated-but-unprocessable event is deliberate. Both
providers retry non-2xx responses, so returning 500 for a payload that will never
parse turns one bad event into an infinite retry storm. Authentication failures do
return 401, because those should not be retried and should be loud.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from callspine.domain import (
    CallState,
    CallStateMachine,
    EventType,
    NormalizedEvent,
    TransitionRejected,
)
from callspine.store import Store, now_ms

# Events that open or close a measurable phase of the call.
_SPAN_OPENERS: dict[EventType, str] = {
    EventType.CALL_RINGING: "ring_to_answer",
    EventType.CALL_ANSWERED: "answer_to_first_speech",
    EventType.TOOL_INVOKED: "tool_roundtrip",
}
_SPAN_CLOSERS: dict[EventType, str] = {
    EventType.CALL_ANSWERED: "ring_to_answer",
    EventType.SPEECH_STARTED: "answer_to_first_speech",
    EventType.TOOL_RESULT: "tool_roundtrip",
}


@dataclass
class IngestResult:
    accepted: int = 0
    duplicates: int = 0
    rejected_transitions: int = 0
    unknown_events: int = 0
    call_state: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "duplicates": self.duplicates,
            "rejected_transitions": self.rejected_transitions,
            "unknown_events": self.unknown_events,
            "call_state": self.call_state,
        }


class Ingestor:
    def __init__(self, store: Store) -> None:
        self.store = store
        self._open_spans: dict[tuple[str, str], int] = {}

    def handle(self, events: list[NormalizedEvent]) -> IngestResult:
        result = IngestResult()
        for event in events:
            self._handle_one(event, result)
        return result

    def _handle_one(self, event: NormalizedEvent, result: IngestResult) -> None:
        provider = event.provider.value

        # 1. Dedupe first. Everything after this must be safe to skip entirely.
        if not self.store.record_event(event):
            result.duplicates += 1
            lag = event.delivery_lag_ms
            self.store.record_anomaly(
                provider,
                "duplicate_delivery",
                f"{event.type.value} redelivered"
                + (f" after {lag}ms" if lag is not None else ""),
                event.call_ref,
            )
            return

        result.accepted += 1

        if event.type is EventType.UNKNOWN:
            result.unknown_events += 1
            self.store.record_anomaly(
                provider,
                "unmapped_event",
                f"no mapping for provider type {event.payload.get('raw_type')!r}",
                event.call_ref,
            )

        # 2. Advance the call, refusing to clobber on out-of-order delivery.
        current = self.store.get_state(event.call_ref) or CallState.PENDING
        machine = CallStateMachine(state=current)
        try:
            new_state = machine.apply(event)
        except TransitionRejected as exc:
            result.rejected_transitions += 1
            self.store.record_anomaly(
                provider, "illegal_transition", str(exc), event.call_ref
            )
            result.call_state = current.value
            return

        for note in machine.anomalies:
            self.store.record_anomaly(provider, "post_hangup_event", note, event.call_ref)

        self.store.upsert_call(event.call_ref, provider, new_state)
        result.call_state = new_state.value

        # 3. Latency accounting.
        self._update_spans(event)

    def _update_spans(self, event: NormalizedEvent) -> None:
        closer = _SPAN_CLOSERS.get(event.type)
        if closer:
            span_id = self._open_spans.pop((event.call_ref, closer), None)
            if span_id is not None:
                self.store.close_span(span_id)

        opener = _SPAN_OPENERS.get(event.type)
        if opener and (event.call_ref, opener) not in self._open_spans:
            self._open_spans[(event.call_ref, opener)] = self.store.open_span(
                event.call_ref,
                opener,
                {"provider": event.provider.value, "opened_by": event.type.value},
            )

        if event.type is EventType.CALL_ENDED:
            # Close anything still open so a dropped call does not leave a span that
            # looks infinitely long in the dashboard.
            for (call_ref, name), span_id in list(self._open_spans.items()):
                if call_ref == event.call_ref:
                    self.store.close_span(span_id)
                    self._open_spans.pop((call_ref, name), None)
                    self.store.record_anomaly(
                        event.provider.value,
                        "span_unclosed_at_hangup",
                        f"{name} was still open when the call ended",
                        call_ref,
                    )


def observed_lag_summary(store: Store, call_ref: str) -> dict[str, Any]:
    """Delivery lag per event, which is how you tell a slow provider from a slow agent.

    A four-second silence on the call and a four-second webhook delivery lag are very
    different problems with the same symptom, and only one of them is yours to fix.
    """
    rows = store.events_for(call_ref)
    lags = [
        r["received_ts_ms"] - r["provider_ts_ms"]
        for r in rows
        if r["provider_ts_ms"] is not None
    ]
    return {
        "events": len(rows),
        "with_provider_timestamp": len(lags),
        "max_delivery_lag_ms": max(lags) if lags else None,
        "median_delivery_lag_ms": sorted(lags)[len(lags) // 2] if lags else None,
        "generated_ts_ms": now_ms(),
    }
