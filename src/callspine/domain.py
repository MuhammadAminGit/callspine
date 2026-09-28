"""Provider-neutral call model.

Vapi and Retell both describe the same thing, a phone call that starts, exchanges turns,
maybe invokes tools, ends, and gets analysed afterwards. They disagree on event names,
payload shape, which events exist at all, and whether they tell you how to deduplicate.

Everything below is written in terms of the call, and provider adapters translate into
these types. Downstream code depends on the provider in exactly two places, both about
what a platform can do rather than how it phrases it: only Vapi reports agent speech,
and only Vapi expects a synchronous tool-call response.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Provider(str, enum.Enum):
    VAPI = "vapi"
    RETELL = "retell"


class CallState(str, enum.Enum):
    PENDING = "pending"
    RINGING = "ringing"
    IN_PROGRESS = "in_progress"
    ENDED = "ended"


class EventType(str, enum.Enum):
    """Normalized vocabulary, deliberately smaller than either vendor's.

    Not every provider emits every type. Retell's webhooks start at `call_started`, so a
    Retell call never passes through RINGING. Only Vapi reports when the assistant starts
    speaking. The state machine accepts both shapes.
    """

    CALL_QUEUED = "call.queued"
    CALL_RINGING = "call.ringing"
    CALL_STARTED = "call.started"
    CALL_ENDED = "call.ended"
    # Post-call analysis. Arrives after the end by design, so it is never an anomaly there.
    CALL_REPORT = "call.report"
    TRANSFER = "transfer"
    TOOL_CALL = "tool.call"
    TRANSCRIPT = "transcript"
    AGENT_SPEECH_STARTED = "agent.speech_started"
    SPEECH = "speech"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class NormalizedEvent:
    """One webhook delivery, translated out of vendor vocabulary.

    `dedupe_key` is the identity of the underlying event, which is not the same thing as
    the delivery. Two deliveries with the same key are one event delivered twice.

    It is None for streams: incremental updates such as transcripts, where every delivery
    is legitimately new information. Retell's docs say this explicitly for
    `transcript_updated`, and deduplicating a stream would drop real updates.

    `provider_ts_ms` is the provider's clock and `received_ts_ms` is ours. Keeping both is
    what separates a slow provider from a slow agent.
    """

    provider: Provider
    call_ref: str
    type: EventType
    dedupe_key: str | None
    provider_ts_ms: int | None
    received_ts_ms: int
    raw_type: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def delivery_lag_ms(self) -> int | None:
        if self.provider_ts_ms is None:
            return None
        return self.received_ts_ms - self.provider_ts_ms


class TransitionRejected(Exception):
    """An event cannot legally move the call from its current state.

    Expected, not exceptional. Out-of-order delivery is normal with both providers, so the
    caller records the anomaly and keeps the call where it was.
    """

    def __init__(self, event: NormalizedEvent, current: CallState) -> None:
        self.event = event
        self.current = current
        super().__init__(
            f"{event.type.value} ({event.provider.value} {event.raw_type!r}) is not valid "
            f"while the call is {current.value}"
        )


_ALLOWED_FROM: dict[EventType, frozenset[CallState]] = {
    EventType.CALL_QUEUED: frozenset({CallState.PENDING}),
    EventType.CALL_RINGING: frozenset({CallState.PENDING, CallState.RINGING}),
    EventType.CALL_STARTED: frozenset({CallState.PENDING, CallState.RINGING}),
    EventType.CALL_ENDED: frozenset(
        {CallState.PENDING, CallState.RINGING, CallState.IN_PROGRESS}
    ),
}

_RESULTING_STATE: dict[EventType, CallState] = {
    EventType.CALL_QUEUED: CallState.PENDING,
    EventType.CALL_RINGING: CallState.RINGING,
    EventType.CALL_STARTED: CallState.IN_PROGRESS,
    EventType.CALL_ENDED: CallState.ENDED,
}


@dataclass
class CallStateMachine:
    """Applies events to a call, refusing illegal transitions instead of clobbering.

    The naive version assigns whatever state the newest event implies. That quietly
    reopens ended calls when a provider redelivers, and it is the usual reason a dashboard
    and a database disagree about whether a call is still live.
    """

    state: CallState = CallState.PENDING
    notes: list[tuple[str, str]] = field(default_factory=list)

    def apply(self, event: NormalizedEvent) -> CallState:
        etype = event.type

        if etype is EventType.CALL_REPORT:
            # A post-call report is proof the call ended. If the end event itself has not
            # arrived, it was lost or is still being retried, so the report closes the call
            # rather than being rejected.
            if self.state is not CallState.ENDED:
                self.notes.append(
                    (
                        "report_before_end",
                        (
                            f"post-call report arrived while the call was {self.state.value}; "
                            "closing it from the report"
                        ),
                    )
                )
            self.state = CallState.ENDED
            return self.state

        if etype in _ALLOWED_FROM:
            if self.state not in _ALLOWED_FROM[etype]:
                raise TransitionRejected(event, self.state)
            self.state = _RESULTING_STATE[etype]
            return self.state

        # Everything else records without moving the call.
        if self.state is CallState.ENDED:
            self.notes.append(("event_after_end", f"{etype.value} arrived after the call ended"))
        return self.state
