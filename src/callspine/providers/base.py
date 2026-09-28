"""Shared machinery for provider adapters.

Two rules apply to every adapter here:

1. Signatures are verified against the raw request body, never a re-serialised JSON
   string. `json.dumps(json.loads(body))` is not `body`: key order, unicode escaping and
   separator whitespace all drift. Retell's documentation warns about exactly this, and
   `tests/test_signatures.py` pins it with a non-ASCII payload.

2. Comparison is constant-time. `==` on a hex digest leaks timing information.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any, Protocol

from callspine.domain import NormalizedEvent


class SignatureError(Exception):
    """Request failed authentication. Never include the expected digest in the message."""


@dataclass(frozen=True)
class ToolInvocation:
    """An agent asking the backend to do something mid-call.

    `invocation_id` is the provider's id for this specific call of the tool, when the
    provider supplies one. Vapi does (`toolCallId`). Retell custom functions do not, which
    is why exactly-once for Retell has to live in the tool itself; see `callspine.tools`.
    """

    call_ref: str
    name: str
    args: dict[str, Any]
    invocation_id: str | None


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def hmac_sha256_hex(secret: str, message: bytes) -> str:
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def body_hash_key(raw_type: str, raw_body: bytes) -> str:
    """Fallback identity for events whose semantics we do not interpret.

    It only catches byte-identical redelivery. That is the right amount of confidence for
    an event type we have not mapped: enough to avoid storing an exact retry twice, not
    enough to pretend we know when two different payloads describe the same event.
    """
    return f"{raw_type}:sha256:{hashlib.sha256(raw_body).hexdigest()}"


def within_replay_window(timestamp_ms: int, window_seconds: int = 300) -> bool:
    """Reject signatures older than the window, and ones meaningfully in the future.

    A future timestamp means clock skew worth knowing about, or a forged header.
    """
    age_ms = int(time.time() * 1000) - timestamp_ms
    return -30_000 <= age_ms <= window_seconds * 1000


class ProviderAdapter(Protocol):
    """What every provider must do.

    Adapters are pure: headers and bytes in, events out. No I/O and no database, so tests
    and the fault-injection harness can drive them with fixtures and no network.
    """

    name: str

    def verify(self, raw_body: bytes, headers: dict[str, str]) -> None: ...

    def normalize(
        self, raw_body: bytes, headers: dict[str, str], received_ts_ms: int
    ) -> list[NormalizedEvent]: ...


def lower_headers(headers: Any) -> dict[str, str]:
    """Header names are case-insensitive on the wire but dict keys are not."""
    return {str(k).lower(): str(v) for k, v in dict(headers).items()}
