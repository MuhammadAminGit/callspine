"""Vapi adapter.

Authentication. Vapi offers a shared secret (sent verbatim in `x-vapi-secret`, or as a
bearer token) or an HMAC credential. For HMAC, Vapi's docs name the fields you configure
(`signatureHeader`, an optional `timestampHeader`, `algorithm`, `payloadFormat`) but do not
publish defaults, and show `x-signature` only as an example. So there is no single correct
verifier for "a Vapi webhook", only the one matching the credential you created.
`VapiConfig` mirrors that credential and refuses incoherent combinations at startup.

A shared secret is replayable forever once captured, and so is an HMAC over the body
alone, which is this adapter's default only because Vapi's timestamp header is optional.
Configure a timestamp header and `{timestamp}.{body}` to get replay protection; the
adapter then enforces a five-minute window.

Assumptions Vapi's docs do not state, which fail closed if wrong: SHA-256 only, the
digest is bare lowercase hex, and the timestamp header is integer milliseconds.

Idempotency. Vapi documents no delivery id and no deduplication guidance. The keys below
are derived from what each message means: a call passes through each status once, and
has one end-of-call report. Transcripts and speech updates are streams and are never
deduplicated.

Tools. `tool-calls` is not informational: Vapi waits for
`{"results": [{"name", "toolCallId", "result"}]}` and speaks the result. Each tool call
carries its own `id`, which is what makes exact replay on retry possible.
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

_STATUS_MAP: dict[str, EventType] = {
    "scheduled": EventType.CALL_QUEUED,
    "queued": EventType.CALL_QUEUED,
    "ringing": EventType.CALL_RINGING,
    "in-progress": EventType.CALL_STARTED,
    "forwarding": EventType.TRANSFER,
    "ended": EventType.CALL_ENDED,
}

_TYPE_MAP: dict[str, EventType] = {
    "end-of-call-report": EventType.CALL_REPORT,
    "tool-calls": EventType.TOOL_CALL,
    "transcript": EventType.TRANSCRIPT,
    "conversation-update": EventType.TRANSCRIPT,
    "speech-update": EventType.SPEECH,
    "user-interrupted": EventType.SPEECH,
    "transfer-update": EventType.TRANSFER,
}

_STREAM = frozenset(
    {"transcript", "conversation-update", "speech-update", "user-interrupted"}
)


@dataclass
class VapiConfig:
    """Mirror of the credential configured in Vapi. Mismatch fails closed."""

    mode: str = "hmac"  # "hmac" or "shared_secret"
    secret: str = ""
    signature_header: str = "x-signature"
    timestamp_header: str = ""  # optional in Vapi; set it to get replay protection
    payload_format: str = "{body}"  # or "{timestamp}.{body}"
    shared_secret_header: str = "x-vapi-secret"
    replay_window_seconds: int = 300

    def __post_init__(self) -> None:
        self.signature_header = self.signature_header.lower()
        self.timestamp_header = self.timestamp_header.lower()
        if self.mode not in {"hmac", "shared_secret"}:
            raise ValueError(f"unknown vapi mode {self.mode!r}")
        if self.payload_format not in {"{body}", "{timestamp}.{body}"}:
            raise ValueError(f"unsupported vapi payload_format {self.payload_format!r}")
        if self.payload_format == "{timestamp}.{body}" and not self.timestamp_header:
            raise ValueError("payload_format signs a timestamp but no timestamp_header is set")


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
                raise SignatureError("missing vapi shared secret")
            if not constant_time_eq(presented, cfg.secret):
                raise SignatureError("vapi shared secret mismatch")
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
            try:
                ts_ms = int(ts)
            except ValueError as exc:
                raise SignatureError("vapi timestamp header is not an integer") from exc
            if not within_replay_window(ts_ms, cfg.replay_window_seconds):
                raise SignatureError("vapi timestamp outside replay window")
            signed = ts.encode() + b"." + raw_body

        expected = hmac_sha256_hex(cfg.secret, signed)
        if not constant_time_eq(presented_sig.strip().lower(), expected):
            raise SignatureError("vapi signature mismatch")

    def normalize(
        self, raw_body: bytes, headers: dict[str, str], received_ts_ms: int
    ) -> list[NormalizedEvent]:
        message = _message(raw_body)
        raw_type = str(message.get("type", ""))
        call_ref = _call_ref(message, raw_type)

        etype = _TYPE_MAP.get(raw_type, EventType.UNKNOWN)
        if raw_type == "status-update":
            etype = _STATUS_MAP.get(str(message.get("status", "")), EventType.UNKNOWN)
        elif (
            raw_type == "speech-update"
            and message.get("status") == "started"
            and message.get("role") == "assistant"
        ):
            etype = EventType.AGENT_SPEECH_STARTED

        ts = message.get("timestamp")
        return [
            NormalizedEvent(
                provider=Provider.VAPI,
                call_ref=call_ref,
                type=etype,
                dedupe_key=_dedupe_key(raw_type, call_ref, message, raw_body),
                provider_ts_ms=int(ts) if isinstance(ts, (int, float)) else None,
                received_ts_ms=received_ts_ms,
                raw_type=raw_type,
                payload=message,
            )
        ]

    def tool_calls(self, raw_body: bytes) -> list[ToolInvocation]:
        """Extract the invocations from a `tool-calls` message.

        `arguments` arrives as an object or as a JSON string depending on the model, so
        both are accepted. An invocation without an id is refused: without one there is no
        way to answer a retry with the original result.
        """
        message = _message(raw_body)
        call_ref = _call_ref(message, "tool-calls")
        out: list[ToolInvocation] = []
        for item in message.get("toolCallList") or []:
            fn = item.get("function") or {}
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                args = json.loads(args) if args.strip() else {}
            tool_call_id = item.get("id")
            if not tool_call_id or not fn.get("name"):
                raise ValueError("vapi tool call without id or function name")
            out.append(
                ToolInvocation(
                    call_ref=call_ref,
                    name=str(fn["name"]),
                    args=args if isinstance(args, dict) else {},
                    invocation_id=str(tool_call_id),
                )
            )
        return out


def is_tool_call(raw_body: bytes) -> bool:
    try:
        return _message(raw_body).get("type") == "tool-calls"
    except (ValueError, TypeError, AttributeError):
        return False


def _message(raw_body: bytes) -> dict[str, Any]:
    body = json.loads(raw_body)
    message = body.get("message")
    if not isinstance(message, dict):
        raise TypeError("vapi payload has no message object")
    return message


def _call_ref(message: dict[str, Any], raw_type: str) -> str:
    call = message.get("call") or {}
    call_ref = str(call.get("id") or "")
    if not call_ref:
        raise ValueError(f"vapi {raw_type!r} message has no call.id")
    return call_ref


def _dedupe_key(
    raw_type: str, call_ref: str, message: dict[str, Any], raw_body: bytes
) -> str | None:
    if raw_type in _STREAM:
        return None
    if raw_type == "status-update":
        return f"status-update:{call_ref}:{message.get('status', '')}"
    if raw_type == "end-of-call-report":
        return f"end-of-call-report:{call_ref}"
    if raw_type == "tool-calls":
        ids = sorted(str(t.get("id", "")) for t in message.get("toolCallList") or [])
        return f"tool-calls:{call_ref}:{','.join(ids)}"
    return body_hash_key(raw_type, raw_body)


def _bearer(headers: dict[str, str]) -> str | None:
    auth = headers.get("authorization", "")
    return auth[7:] if auth.lower().startswith("bearer ") else None
