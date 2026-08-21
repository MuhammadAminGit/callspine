"""Vapi adapter.

Vapi gives you a choice of two authentication styles, and the second one has no fixed
shape:

- **Shared secret.** Vapi sends the value you configured, verbatim, in a header
  (`x-vapi-secret`, or as a bearer token). Simple, and it means every request from Vapi
  carries the same credential — capture one and you can replay it forever.

- **HMAC.** The algorithm, signature header name, timestamp header name and *payload
  format* are all things you choose when you create the credential. Vapi's own default
  format signs `{timestamp}.{body}`, but `{body}` alone is equally valid configuration.

That configurability is the trap. There is no single correct verification routine for
"a Vapi webhook" — there is only the routine matching the credential you created. This
adapter therefore takes the format as configuration rather than pretending a default is
universal, and refuses to start if the pieces are inconsistent.

Compare `retell.py`, where the format is fixed and the only decision left is whether you
remembered to enforce the replay window.
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

# Vapi's message `type` field, mapped to our vocabulary. Anything absent from this map
# is preserved as UNKNOWN rather than discarded.
_EVENT_MAP: dict[str, EventType] = {
    "status-update": EventType.CALL_STARTED,  # refined below by the status value
    "speech-update": EventType.SPEECH_STARTED,
    "transcript": EventType.TRANSCRIPT,
    "function-call": EventType.TOOL_INVOKED,
    "tool-calls": EventType.TOOL_INVOKED,
    "end-of-call-report": EventType.CALL_ENDED,
    "transfer-destination-request": EventType.TRANSFER_STARTED,
    "hang": EventType.TRANSFER_FAILED,
}

# `status-update` carries the real lifecycle signal in a nested field.
_STATUS_MAP: dict[str, EventType] = {
    "queued": EventType.CALL_STARTED,
    "ringing": EventType.CALL_RINGING,
    "in-progress": EventType.CALL_ANSWERED,
    "forwarding": EventType.TRANSFER_STARTED,
    "ended": EventType.CALL_ENDED,
}


@dataclass
class VapiConfig:
    """Mirrors the credential you configured in Vapi. Getting this wrong fails closed."""

    mode: str = "hmac"  # "hmac" or "shared_secret"
    secret: str = ""
    signature_header: str = "x-vapi-signature"
    timestamp_header: str = "x-timestamp"
    # "{timestamp}.{body}" (Vapi's default) or "{body}"
    payload_format: str = "{timestamp}.{body}"
    shared_secret_header: str = "x-vapi-secret"
    enforce_replay_window: bool = True

    def __post_init__(self) -> None:
        if self.mode not in {"hmac", "shared_secret"}:
            raise ValueError(f"unknown vapi mode {self.mode!r}")
        if self.payload_format not in {"{timestamp}.{body}", "{body}"}:
            raise ValueError(f"unsupported vapi payload_format {self.payload_format!r}")
        if self.payload_format == "{timestamp}.{body}" and not self.timestamp_header:
            raise ValueError("payload_format includes {timestamp} but no timestamp_header is set")


class VapiAdapter:
    name = "vapi"

    def __init__(self, config: VapiConfig) -> None:
        self.config = config

    def verify(self, raw_body: bytes, headers: dict[str, str]) -> None:
        cfg = self.config
        if not cfg.secret:
            raise SignatureError("no vapi secret configured")

        if cfg.mode == "shared_secret":
            presented = headers.get(cfg.shared_secret_header) or _bearer(headers)
            if presented is None:
                raise SignatureError("missing vapi shared secret header")
            if not constant_time_eq(presented, cfg.secret):
                raise SignatureError("vapi shared secret mismatch")
            # Nothing else to check. A captured request stays valid indefinitely, which
            # is precisely why the HMAC mode exists.
            return

        presented_sig = headers.get(cfg.signature_header)
        if not presented_sig:
            raise SignatureError(f"missing {cfg.signature_header}")

        if cfg.payload_format == "{body}":
            signed = raw_body
        else:
            ts = headers.get(cfg.timestamp_header)
            if not ts:
                raise SignatureError(f"missing {cfg.timestamp_header}")
            if cfg.enforce_replay_window:
                try:
                    ts_ms = int(ts)
                except ValueError as exc:
                    raise SignatureError("vapi timestamp header is not an integer") from exc
                if not within_replay_window(ts_ms):
                    raise SignatureError("vapi timestamp outside replay window")
            signed = ts.encode() + b"." + raw_body

        expected = hmac_sha256_hex(cfg.secret, signed)
        if not constant_time_eq(presented_sig.strip().lower(), expected):
            raise SignatureError("vapi signature mismatch")

    def normalize(
        self, raw_body: bytes, headers: dict[str, str], received_ts_ms: int
    ) -> list[NormalizedEvent]:
        body = json.loads(raw_body)
        message: dict[str, Any] = body.get("message") or body

        raw_type = str(message.get("type", ""))
        etype = _EVENT_MAP.get(raw_type, EventType.UNKNOWN)
        if raw_type == "status-update":
            status = str(message.get("status", ""))
            etype = _STATUS_MAP.get(status, EventType.UNKNOWN)

        call = message.get("call") or {}
        call_ref = str(call.get("id") or message.get("callId") or "")
        if not call_ref:
            # Without a call reference we cannot attach this to anything. Surfacing it
            # as an error beats inventing a call.
            raise ValueError("vapi payload has no call id")

        # Vapi does not send a per-event id, so redelivery of a byte-identical payload
        # is the only duplicate we can reliably detect.
        event_id = synthetic_event_id(self.name, raw_body)

        provider_ts = message.get("timestamp")
        provider_ts_ms = int(provider_ts) if isinstance(provider_ts, (int, float)) else None

        return [
            NormalizedEvent(
                provider=Provider.VAPI,
                provider_event_id=event_id,
                call_ref=call_ref,
                type=etype,
                provider_ts_ms=provider_ts_ms,
                received_ts_ms=received_ts_ms,
                payload={"raw_type": raw_type, "message": message},
            )
        ]


def _bearer(headers: dict[str, str]) -> str | None:
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:]
    return None
