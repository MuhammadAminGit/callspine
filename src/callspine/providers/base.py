"""Shared machinery for provider adapters.

Two rules apply to every adapter here, and both exist because getting them wrong
produces bugs that only appear in production:

1. Signatures are verified against the **raw request body**, never a re-serialised
   JSON string. `json.dumps(json.loads(body))` is not `body` — key order, unicode
   escaping and separator whitespace all drift, and the HMAC stops matching for
   payloads that happen to contain a non-ASCII character or a float.

2. Comparison is constant-time. A `==` on a hex digest leaks timing information that
   can be used to forge one byte at a time.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, Protocol

from callspine.domain import NormalizedEvent


class SignatureError(Exception):
    """Webhook failed authentication. Never include the expected digest in the message."""


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def hmac_sha256_hex(secret: str, message: bytes) -> str:
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def synthetic_event_id(provider: str, raw_body: bytes) -> str:
    """Derive a dedupe key when the provider does not supply a stable event id.

    This is a compromise, not a fix. It deduplicates *identical* redeliveries, which is
    the common retry case. It cannot distinguish two genuinely distinct events with
    byte-identical payloads — two `speech.started` events in one call, say, where the
    provider omits both an id and a timestamp.

    Where a provider does give a real id, adapters use it and never call this.
    """
    return f"{provider}:sha256:{hashlib.sha256(raw_body).hexdigest()}"


def within_replay_window(timestamp_ms: int, window_seconds: int = 300) -> bool:
    """Reject signatures older than the window, to blunt replay of a captured request.

    Also rejects timestamps meaningfully in the future, which indicates either clock
    skew worth knowing about or a forged header.
    """
    age_ms = int(time.time() * 1000) - timestamp_ms
    return -30_000 <= age_ms <= window_seconds * 1000


class ProviderAdapter(Protocol):
    """What every provider must be able to do.

    Adapters are pure: they read headers and bytes and return events. They do no I/O
    and touch no database, so the fault-injection harness can drive them directly with
    captured payloads and no network.
    """

    name: str

    def verify(self, raw_body: bytes, headers: dict[str, str]) -> None:
        """Raise SignatureError if the request is not authentic."""
        ...

    def normalize(self, raw_body: bytes, headers: dict[str, str], received_ts_ms: int) -> list[NormalizedEvent]:
        """Translate one delivery into zero or more provider-neutral events."""
        ...


def lower_headers(headers: Any) -> dict[str, str]:
    """Header names are case-insensitive on the wire but dicts are not."""
    return {str(k).lower(): str(v) for k, v in dict(headers).items()}
