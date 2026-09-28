"""Retell adapter.

Everything here follows Retell's own documentation, linked in the README.

Authentication. HMAC-SHA256 keyed with the Retell API key (the one carrying the webhook
badge), sent as `x-retell-signature: v={unix_ms},d={hex_digest}`, where the digest covers
the raw body followed by the timestamp. Retell documents a five-minute replay window. The
timestamp is bound into the signature, but nothing forces a receiver to check its age, so
this adapter enforces the window by default and makes disabling it an explicit choice.

Idempotency. Retell is unusually specific, and its guidance differs by event class:

- lifecycle events (`call_started`, `call_ended`, `call_analyzed`): `event` + `call_id`
- transfer events: `event` + `call_id` + `start_timestamp`, and `transfer_destination`
  if needed
- `transcript_updated`: do not deduplicate by `call_id` at all; it is a stream of
  incremental updates

One ambiguity: the docs do not say whether a transfer's `start_timestamp` is the
transfer's or the call's. This adapter prefers a top-level one and falls back to the
call's. If it is the call's, two transfer attempts to the same destination in one call
would share a key.

The obvious-looking alternative, the signature timestamp, is not documented as stable
across deliveries, and a sender that signs at send time gives every retry a new one.
Keying on it makes each retry look like a new event.

Tools. Retell custom functions carry no per-invocation id and may be retried up to five
times, and Retell's docs say the endpoint "must be idempotent". So exactly-once for Retell
cannot be done by remembering an id; it has to be a property of the operation itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from callspine.domain import EventType, NormalizedEvent, Provider
from callspine.providers.base import (
    SignatureError,
    ToolInvocation,
    body_hash_key,
    constant_time_eq,
    hmac_sha256_hex,
    within_replay_window,
)

SIGNATURE_HEADER = "x-retell-signature"

_EVENT_MAP: dict[str, EventType] = {
    "call_started": EventType.CALL_STARTED,
    "call_ended": EventType.CALL_ENDED,
    "call_analyzed": EventType.CALL_REPORT,
    "transcript_updated": EventType.TRANSCRIPT,
    "transfer_started": EventType.TRANSFER,
    "transfer_bridged": EventType.TRANSFER,
    "transfer_cancelled": EventType.TRANSFER,
    "transfer_ended": EventType.TRANSFER,
}

_LIFECYCLE = frozenset({"call_started", "call_ended", "call_analyzed"})
_TRANSFER = frozenset({"transfer_started", "transfer_bridged", "transfer_cancelled", "transfer_ended"})
_STREAM = frozenset({"transcript_updated"})


@dataclass
class RetellConfig:
    api_key: str = ""
    enforce_replay_window: bool = True
    replay_window_seconds: int = 300


def parse_signature_header(value: str) -> tuple[int, str]:
    """Pull the timestamp and digest out of `v={ts},d={digest}`.

    Tolerates whitespace and field order, because a parser that accepts only the exact
    documented byte sequence breaks the first time a vendor adds a field.
    """
    ts: int | None = None
    digest: str | None = None
    for part in (p.strip() for p in value.split(",")):
        key, sep, val = part.partition("=")
        if not sep:
            continue
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
        """Used for both webhooks and custom-function calls; Retell signs them the same way."""
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
        event = str(body.get("event", ""))
        call: dict[str, Any] = body.get("call") or {}

        call_ref = str(call.get("call_id") or "")
        if not call_ref:
            raise ValueError(f"retell {event!r} payload has no call.call_id")

        return [
            NormalizedEvent(
                provider=Provider.RETELL,
                call_ref=call_ref,
                type=_EVENT_MAP.get(event, EventType.UNKNOWN),
                dedupe_key=_dedupe_key(event, call_ref, body, call, raw_body),
                provider_ts_ms=_signed_timestamp(headers),
                received_ts_ms=received_ts_ms,
                raw_type=event,
                payload=body,
            )
        ]

    def parse_function_call(self, raw_body: bytes) -> ToolInvocation:
        """Read a custom-function request: `{"name", "args", "call"}`.

        Requires Retell's default payload mode. With "args only" enabled the body carries
        neither the function name nor the call, so there is nothing to attribute it to.
        """
        body: dict[str, Any] = json.loads(raw_body)
        name = body.get("name")
        call = body.get("call") or {}
        if not name or not call.get("call_id"):
            raise ValueError(
                "retell function request needs name and call.call_id; "
                "is 'args only' payload mode enabled?"
            )
        args = body.get("args") or {}
        return ToolInvocation(
            call_ref=str(call["call_id"]),
            name=str(name),
            args=args if isinstance(args, dict) else {},
            invocation_id=None,
        )


def _dedupe_key(
    event: str, call_ref: str, body: dict[str, Any], call: dict[str, Any], raw_body: bytes
) -> str | None:
    if event in _STREAM:
        return None
    if event in _LIFECYCLE:
        return f"{event}:{call_ref}"
    if event in _TRANSFER:
        start = body.get("start_timestamp", call.get("start_timestamp", ""))
        dest = body.get("transfer_destination")
        dest_part = json.dumps(dest, sort_keys=True) if dest is not None else ""
        return f"{event}:{call_ref}:{start}:{dest_part}"
    return body_hash_key(event, raw_body)


def _signed_timestamp(headers: dict[str, str]) -> int | None:
    """Retell's signature timestamp: authenticated, so trustworthy for measuring lag."""
    try:
        return parse_signature_header(headers.get(SIGNATURE_HEADER, ""))[0]
    except SignatureError:
        return None
