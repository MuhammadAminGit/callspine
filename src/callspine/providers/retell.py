"""Retell adapter.

Retell's scheme is fixed, which makes it easier to get right and easier to get subtly
wrong in exactly one way.

Fixed parts:
- HMAC-SHA256, keyed with your Retell **API key** (the one carrying the webhook badge,
  not just any key).
- Header `x-retell-signature`, shaped `v={unix_ms_timestamp},d={hex_digest}`.
- The digest covers the raw body together with that timestamp, so the timestamp is
  bound into the signature and cannot be edited independently.

The one way to get it wrong: treating the replay window as optional. The timestamp is
*authenticated*, but nothing forces you to look at it. Skip the window check and a
captured request stays replayable for as long as the API key lives. This adapter
enforces it by default and makes disabling it an explicit argument, because a default
that silently weakens security is worse than no default.

Compare `vapi.py`, where the scheme itself is yours to define.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from callspine.domain import EventType, NormalizedEvent, Provider
from callspine.providers.base import (
    SignatureError,
    constant_time_eq,
    hmac_sha256_hex,
    synthetic_event_id,
    within_replay_window,
)

_EVENT_MAP: dict[str, EventType] = {
    "call_started": EventType.CALL_STARTED,
    "call_ringing": EventType.CALL_RINGING,
    "call_answered": EventType.CALL_ANSWERED,
    "call_ended": EventType.CALL_ENDED,
    "call_analyzed": EventType.UNKNOWN,  # post-call analysis, not a lifecycle change
    "agent_response": EventType.TRANSCRIPT,
    "transcript_update": EventType.TRANSCRIPT,
    "tool_call": EventType.TOOL_INVOKED,
    "tool_result": EventType.TOOL_RESULT,
}

SIGNATURE_HEADER = "x-retell-signature"


@dataclass
class RetellConfig:
    api_key: str = ""
    enforce_replay_window: bool = True
    replay_window_seconds: int = 300


def parse_signature_header(value: str) -> tuple[int, str]:
    """Pull the timestamp and digest out of `v={ts},d={digest}`.

    Tolerates whitespace and reordering, because a parser that only accepts the exact
    documented byte sequence breaks the first time a vendor adds a field.
    """
    parts = [p.strip() for p in value.split(",") if p.strip()]
    ts: int | None = None
    digest: str | None = None
    for part in parts:
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = key.strip().lower()
        if key == "v":
            try:
                ts = int(val.strip())
            except ValueError as exc:
                raise SignatureError("retell signature timestamp is not an integer") from exc
        elif key == "d":
            digest = val.strip().lower()
    if ts is None or digest is None:
        raise SignatureError("retell signature header missing v= or d=")
    return ts, digest


class RetellAdapter:
    name = "retell"

    def __init__(self, config: RetellConfig) -> None:
        self.config = config

    def verify(self, raw_body: bytes, headers: dict[str, str]) -> None:
        if not self.config.api_key:
            raise SignatureError("no retell api key configured")

        header = headers.get(SIGNATURE_HEADER)
        if not header:
            raise SignatureError(f"missing {SIGNATURE_HEADER}")

        ts_ms, presented = parse_signature_header(header)

        if self.config.enforce_replay_window and not within_replay_window(
            ts_ms, self.config.replay_window_seconds
        ):
            raise SignatureError("retell signature outside replay window")

        expected = hmac_sha256_hex(self.config.api_key, raw_body + str(ts_ms).encode())
        if not constant_time_eq(presented, expected):
            raise SignatureError("retell signature mismatch")

    def normalize(
        self, raw_body: bytes, headers: dict[str, str], received_ts_ms: int
    ) -> list[NormalizedEvent]:
        body: dict[str, Any] = json.loads(raw_body)

        raw_type = str(body.get("event", ""))
        etype = _EVENT_MAP.get(raw_type, EventType.UNKNOWN)

        call = body.get("call") or {}
        call_ref = str(call.get("call_id") or body.get("call_id") or "")
        if not call_ref:
            raise ValueError("retell payload has no call_id")

        # The signature timestamp looks like an obvious idempotency key and is a trap.
        # A redelivery is re-signed at the moment it is retried, so the same event
        # arrives twice carrying two different timestamps. Keying on it makes every
        # retry look like a fresh event, which is exactly the double-booking bug this
        # layer exists to prevent. Found by faultkit, not by reading the docs.
        #
        # So dedupe on the body, like Vapi. The known cost is that two genuinely
        # distinct events with byte-identical payloads collapse into one. In this
        # vocabulary that means a repeated identical transcript line, which is a far
        # cheaper failure than a duplicated booking.
        event_id = synthetic_event_id(self.name, raw_body)

        # The timestamp is still worth keeping: signed by the provider, it gives a
        # trustworthy provider-side clock for measuring delivery lag.
        try:
            provider_ts_ms: int | None = parse_signature_header(
                headers.get(SIGNATURE_HEADER, "")
            )[0]
        except SignatureError:
            provider_ts_ms = None

        return [
            NormalizedEvent(
                provider=Provider.RETELL,
                provider_event_id=event_id,
                call_ref=call_ref,
                type=etype,
                provider_ts_ms=provider_ts_ms,
                received_ts_ms=received_ts_ms,
                payload={"raw_type": raw_type, "body": body},
            )
        ]
