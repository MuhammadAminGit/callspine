"""The path every webhook takes: dedupe, advance state, measure, record.

Several stages fail in ways that are expected rather than exceptional: duplicates,
illegal transitions, unmapped event types, chatter after hangup. The difference between
a system you can debug and one you cannot is whether those get written down. They all
land in the anomalies table instead of being swallowed or crashing the request.

Each event is processed in a single transaction. If anything fails partway, the event is
not left marked as seen, so the provider's retry is processed rather than discarded as a
duplicate. The transaction also holds SQLite's write lock, which is what makes it safe
for several workers to share one database: two events for the same call cannot both
read the old state and both write over each other. That lock is database-wide, so every
event is serialized, not only those for the same call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from callspine.domain import (
    CallState,
    CallStateMachine,
    EventType,
    NormalizedEvent,
    Provider,
    TransitionRejected,
)
from callspine.store import Store

# Only Vapi reports when the assistant starts speaking, so only Vapi calls can measure
# time to first word. Opening that span for Retell would flag every call as unfinished.
_REPORTS_AGENT_SPEECH = frozenset({Provider.VAPI})


@dataclass
class IngestResult:
    accepted: int = 0
    duplicates: int = 0
    rejected_transitions: int = 0
    unknown_events: int = 0
    call_state: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class Ingestor:
    def __init__(self, store: Store) -> None:
        self.store = store

    def handle(self, events: list[NormalizedEvent]) -> IngestResult:
        result = IngestResult()
        for event in events:
            with self.store.transaction():
                self._handle_one(event, result)
        return result

    def _handle_one(self, event: NormalizedEvent, result: IngestResult) -> None:
        provider = event.provider.value

        if not self.store.record_event(event):
            result.duplicates += 1
            self.store.record_anomaly(
                provider, "duplicate_delivery", f"{event.raw_type} delivered again", event.call_ref
            )
            return

        result.accepted += 1

        if event.type is EventType.UNKNOWN:
            result.unknown_events += 1
            self.store.record_anomaly(
                provider, "unmapped_event", f"no mapping for {event.raw_type!r}", event.call_ref
            )

        current = self.store.get_state(event.call_ref) or CallState.PENDING
        machine = CallStateMachine(state=current)
        try:
            new_state = machine.apply(event)
        except TransitionRejected as exc:
            result.rejected_transitions += 1
            self.store.record_anomaly(provider, "illegal_transition", str(exc), event.call_ref)
            result.call_state = current.value
            return

        for kind, detail in machine.notes:
            self.store.record_anomaly(provider, kind, detail, event.call_ref)

        self.store.upsert_call(event.call_ref, provider, new_state)
        result.call_state = new_state.value

        ended_now = current is not CallState.ENDED and new_state is CallState.ENDED
        self._update_spans(event, ended_now=ended_now)

    def _update_spans(self, event: NormalizedEvent, *, ended_now: bool) -> None:
        # The provider's clock where it sends one, so delivery jitter stays out of the
        # measurement. Either way this is webhook timing: a close proxy for what the
        # caller experienced, not a measurement of the audio.
        ts = event.provider_ts_ms if event.provider_ts_ms is not None else event.received_ts_ms
        ref, attrs = event.call_ref, {"provider": event.provider.value}

        if event.type is EventType.CALL_RINGING:
            self.store.open_span(ref, "ring_to_answer", ts, attrs)
        elif event.type is EventType.CALL_STARTED:
            self.store.close_span(ref, "ring_to_answer", ts)
            if event.provider in _REPORTS_AGENT_SPEECH:
                spoke = self.store.first_event_ts(ref, EventType.AGENT_SPEECH_STARTED.value)
                if spoke is None:
                    self.store.open_span(ref, "answer_to_first_word", ts, attrs)
                else:
                    # The agent's first word was delivered before the answer event. The
                    # span is already complete; opening it now would leave it open forever
                    # and wrongly report an agent that never spoke.
                    if spoke < ts:
                        self.store.record_anomaly(
                            event.provider.value, "clock_disagreement",
                            f"first word timestamped {ts - spoke}ms before the call was "
                            "answered; recording a zero-length span",
                            ref,
                        )
                    self.store.record_span(
                        ref, "answer_to_first_word", ts, max(spoke, ts),
                        {**attrs, "delivered_out_of_order": True},
                    )
        elif event.type is EventType.AGENT_SPEECH_STARTED:
            self.store.close_span(ref, "answer_to_first_word", ts)

        if ended_now:
            # A span still open at the end means something: ring_to_answer means nobody
            # picked up, answer_to_first_word means the agent never spoke.
            for name in self.store.close_all_spans(ref, ts):
                self.store.record_anomaly(
                    event.provider.value, "span_open_at_end",
                    f"{name} was still open when the call ended", ref,
                )


def delivery_lag(store: Store, call_ref: str) -> dict[str, Any]:
    """Time from the provider's timestamp to arrival, per event.

    A four-second silence on the call and a four-second webhook delay have the same
    symptom and different owners. For Retell the provider timestamp is the signature's,
    so a retried delivery measures its own attempt, not the original send.
    """
    lags = sorted(
        r["received_ts_ms"] - r["provider_ts_ms"]
        for r in store.events_for(call_ref)
        if r["provider_ts_ms"] is not None
    )
    return {
        "samples": len(lags),
        "median_ms": lags[len(lags) // 2] if lags else None,
        "max_ms": lags[-1] if lags else None,
    }
