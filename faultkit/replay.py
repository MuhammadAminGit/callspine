"""Fire realistic webhook sequences at a running callspine, with faults injected.

Both Vapi and Retell deliver over the public internet with at-least-once semantics.
That means duplicates, reordering and late arrivals are not edge cases you might hit,
they are the normal operating condition. The only question is whether your backend was
written as though they were.

This harness makes those conditions reproducible. Point it at a running server and it
replays a scripted call while doing the things the internet does:

    python faultkit/replay.py --provider retell --fault duplicate
    python faultkit/replay.py --provider vapi --fault reorder
    python faultkit/replay.py --provider retell --fault all --calls 5

Then read /api/anomalies and see whether the system noticed. A backend that survives
this cleanly is one you can put a business's phone number on.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections.abc import Callable
from typing import Any

import httpx

from callspine.providers.base import hmac_sha256_hex

FAULTS = ("none", "duplicate", "reorder", "delay", "tamper", "all")


def now_ms() -> int:
    return int(time.time() * 1000)


# --- payload builders -------------------------------------------------------


def vapi_sequence(call_id: str) -> list[dict[str, Any]]:
    def msg(mtype: str, **extra: Any) -> dict[str, Any]:
        return {
            "message": {
                "type": mtype,
                "timestamp": now_ms(),
                "call": {"id": call_id},
                **extra,
            }
        }

    return [
        msg("status-update", status="queued"),
        msg("status-update", status="ringing"),
        msg("status-update", status="in-progress"),
        msg("speech-update", role="assistant"),
        msg("transcript", transcript="hi, I'd like to book an appointment"),
        msg("tool-calls", toolCalls=[{"name": "check_availability"}]),
        msg("transcript", transcript="Tuesday at ten works"),
        msg("status-update", status="ended"),
        msg("end-of-call-report", endedReason="customer-ended-call"),
    ]


def retell_sequence(call_id: str) -> list[dict[str, Any]]:
    def msg(event: str, **extra: Any) -> dict[str, Any]:
        return {"event": event, "call": {"call_id": call_id}, **extra}

    return [
        msg("call_started"),
        msg("call_ringing"),
        msg("call_answered"),
        msg("agent_response", response="thanks for calling, how can I help?"),
        msg("transcript_update", transcript="I need an appointment"),
        msg("tool_call", tool="check_availability"),
        msg("tool_result", result={"slots": 5}),
        msg("call_ended", disconnection_reason="user_hangup"),
    ]


# --- signing ----------------------------------------------------------------


def sign_vapi(body: bytes, secret: str) -> dict[str, str]:
    ts = str(now_ms())
    return {
        "x-timestamp": ts,
        "x-vapi-signature": hmac_sha256_hex(secret, ts.encode() + b"." + body),
        "content-type": "application/json",
    }


def sign_retell(body: bytes, api_key: str) -> dict[str, str]:
    ts = now_ms()
    digest = hmac_sha256_hex(api_key, body + str(ts).encode())
    return {
        "x-retell-signature": f"v={ts},d={digest}",
        "content-type": "application/json",
    }


# --- fault injection --------------------------------------------------------


def apply_faults(
    payloads: list[dict[str, Any]], fault: str, rng: random.Random
) -> list[tuple[dict[str, Any], bool]]:
    """Return (payload, tamper) pairs in delivery order.

    `duplicate` redelivers a middle event, mimicking a provider retry after our 200
    arrived too slowly to be recorded on their side.

    `reorder` swaps two adjacent events, which is what happens when two deliveries take
    different paths and the later one wins the race.
    """
    items: list[tuple[dict[str, Any], bool]] = [(p, False) for p in payloads]

    do = {f: fault in (f, "all") for f in ("duplicate", "reorder", "tamper")}

    if do["duplicate"] and len(items) > 3:
        idx = rng.randrange(1, len(items) - 1)
        items.insert(idx + 1, items[idx])

    if do["reorder"] and len(items) > 4:
        i = rng.randrange(1, len(items) - 2)
        items[i], items[i + 1] = items[i + 1], items[i]

    if do["tamper"] and items:
        idx = rng.randrange(len(items))
        items[idx] = (items[idx][0], True)

    return items


def deliver(
    client: httpx.Client,
    base_url: str,
    provider: str,
    payload: dict[str, Any],
    signer: Callable[[bytes], dict[str, str]],
    tamper: bool,
) -> tuple[int, str]:
    body = json.dumps(payload).encode()
    headers = signer(body)
    if tamper:
        # Sign the real body, then send a different one. This is exactly what a
        # man-in-the-middle or a buggy proxy that rewrites JSON looks like.
        body = body.replace(b"call_id", b"call_1d").replace(b'"id"', b'"1d"')
    resp = client.post(f"{base_url}/webhooks/{provider}", content=body, headers=headers)
    return resp.status_code, resp.text[:200]


def run(args: argparse.Namespace) -> int:
    rng = random.Random(args.seed)
    builder = vapi_sequence if args.provider == "vapi" else retell_sequence
    secret = args.secret
    signer = (
        (lambda b: sign_vapi(b, secret))
        if args.provider == "vapi"
        else (lambda b: sign_retell(b, secret))
    )

    totals = {"sent": 0, "2xx": 0, "401": 0, "other": 0}

    with httpx.Client(timeout=10.0) as client:
        try:
            client.get(f"{args.base_url}/healthz")
        except httpx.ConnectError:
            print(f"no server at {args.base_url}. start it with: make dev", file=sys.stderr)
            return 2

        for n in range(args.calls):
            call_id = f"{args.provider}-{args.seed}-{n}"
            items = apply_faults(builder(call_id), args.fault, rng)
            print(f"\ncall {call_id}  ({len(items)} deliveries, fault={args.fault})")

            for payload, tamper in items:
                if args.fault in ("delay", "all") and rng.random() < 0.3:
                    time.sleep(rng.uniform(0.2, 1.2))

                status, snippet = deliver(
                    client, args.base_url, args.provider, payload, signer, tamper
                )
                totals["sent"] += 1
                if 200 <= status < 300:
                    totals["2xx"] += 1
                elif status == 401:
                    totals["401"] += 1
                else:
                    totals["other"] += 1

                label = "TAMPERED " if tamper else ""
                print(f"  {label}{status}  {snippet}")

        anomalies = client.get(f"{args.base_url}/api/anomalies").json()

    print(f"\ndelivered={totals['sent']}  2xx={totals['2xx']}  "
          f"401={totals['401']}  other={totals['other']}")

    by_kind: dict[str, int] = {}
    for a in anomalies:
        by_kind[a["kind"]] = by_kind.get(a["kind"], 0) + 1
    print("\nanomalies recorded:")
    if not by_kind:
        print("  (none)")
    for kind, count in sorted(by_kind.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>4}  {kind}")

    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--provider", choices=("vapi", "retell"), default="retell")
    p.add_argument("--fault", choices=FAULTS, default="none")
    p.add_argument("--calls", type=int, default=1)
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--secret", default="dev-secret", help="VAPI_SECRET or RETELL_API_KEY")
    p.add_argument("--seed", type=int, default=1)
    return run(p.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
