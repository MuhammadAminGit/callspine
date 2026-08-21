"""Provider-neutral call model.

Vapi and Retell both describe the same underlying thing: a phone call that rings,
gets answered, exchanges turns, maybe invokes a tool, and ends. They disagree on
almost everything else — event names, payload shape, ordering guarantees, and what
they do when your endpoint is slow.

Everything below is written in terms of the call, not the vendor. Provider adapters
translate into these types and nothing downstream knows which platform it came from.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Provider(str, enum.Enum):
    VAPI = "vapi"
    RETELL = "retell"


class CallState(str, enum.Enum):
    """Lifecycle of a single call.

    ENDED is terminal. Anything arriving after it is late, not new — see
    `CallStateMachine.apply`.
    """

    PENDING = "pending"
    RINGING = "ringing"
    ANSWERED = "answered"
    IN_PROGRESS = "in_progress"
    ENDED = "ended"


class EventType(str, enum.Enum):
    """Normalized event vocabulary.

    Deliberately smaller than either vendor's. Events we cannot map to something
    actionable become UNKNOWN and are stored verbatim rather than dropped, so an
    unmapped event is a visible gap instead of silent data loss.
    """

    CALL_STARTED = "call.started"
    CALL_RINGING = "call.ringing"
    CALL_ANSWERED = "call.answered"
    SPEECH_STARTED = "speech.started"
    TRANSCRIPT = "transcript"
    TOOL_INVOKED = "tool.invoked"
    TOOL_RESULT = "tool.result"
    TRANSFER_STARTED = "transfer.started"
    TRANSFER_FAILED = "transfer.failed"
    CALL_ENDED = "call.ended"
    UNKNOWN = "unknown"


# Which states each event is allowed to move the call into. An event whose type is
# not a key here does not advance state (transcripts, tool calls) — it only records.
_TRANSITIONS: dict[EventType, tuple[CallState, ...]] = {
    EventType.CALL_STARTED: (CallState.PENDING,),
    EventType.CALL_RINGING: (CallState.PENDING, CallState.RINGING),
    EventType.CALL_ANSWERED: (CallState.PENDING, CallState.RINGING),
    EventType.CALL_ENDED: (
        CallState.PENDING,
        CallState.RINGING,
        CallState.ANSWERED,
        CallState.IN_PROGRESS,
    ),
}

_RESULTING_STATE: dict[EventType, CallState] = {
    EventType.CALL_STARTED: CallState.RINGING,
    EventType.CALL_RINGING: CallState.RINGING,
    EventType.CALL_ANSWERED: CallState.ANSWERED,
    EventType.CALL_ENDED: CallState.ENDED,
}


@dataclass(frozen=True)
class NormalizedEvent:
    """One webhook delivery, translated out of vendor vocabulary.

    `provider_event_id` is what we deduplicate on. When a provider does not supply a
    stable id, the adapter synthesises one from the payload — see
    `providers.base.synthetic_event_id` for why that is a compromise and not a fix.

    `provider_ts_ms` is the vendor's clock; `received_ts_ms` is ours. Keeping both is
    what makes it possible to tell a late delivery apart from a late event.
    """

    provider: Provider
    provider_event_id: str
    call_ref: str
    type: EventType
    provider_ts_ms: int | None
    received_ts_ms: int
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def delivery_lag_ms(self) -> int | None:
        """How long the provider took to get this to us, when it tells us enough to know."""
        if self.provider_ts_ms is None:
            return None
        return self.received_ts_ms - self.provider_ts_ms


class TransitionRejected(Exception):
    """Raised when an event cannot legally advance the call from its current state.

    This is not an error condition in the usual sense. Out-of-order delivery is normal
    with both providers, so callers are expected to catch this, record the anomaly, and
    keep the call's state as it was.
    """

    def __init__(self, event: NormalizedEvent, current: CallState) -> None:
        self.event = event
        self.current = current
        super().__init__(
            f"{event.type.value} from {event.provider.value} is not valid in state "
            f"{current.value} (call {event.call_ref})"
        )


@dataclass
class CallStateMachine:
    """Applies events to a call, refusing illegal transitions rather than clobbering.

    The naive version of this assigns whatever state the newest event implies. That
    quietly reopens ended calls when a provider redelivers, and it is the usual reason
    a dashboard and a database disagree about whether a call is still live.
    """

    state: CallState = CallState.PENDING
    anomalies: list[str] = field(default_factory=list)

    def apply(self, event: NormalizedEvent) -> CallState:
        if event.type not in _TRANSITIONS:
            # Recording-only event. Legal at any point except after the call ended,
            # where it means the provider is still talking about a finished call.
            if self.state is CallState.ENDED:
                self.anomalies.append(f"{event.type.value} arrived after call ended")
            elif self.state is CallState.ANSWERED:
                self.state = CallState.IN_PROGRESS
            return self.state

        if self.state not in _TRANSITIONS[event.type]:
            raise TransitionRejected(event, self.state)

        self.state = _RESULTING_STATE[event.type]
        return self.state
