"""Replay realistic call sequences at a running callspine, with delivery faults injected.

Retell retries any webhook that does not get a 2xx within ten seconds, up to three times,
and retries custom functions up to five times if configured to. Vapi documents no retry
policy. Separately from the transport, an LLM can simply call the same tool twice. The
question is only whether the backend was written as if all of that were normal.

    python faultkit/replay.py --provider vapi   --fault retry-tool --calls 5
    python faultkit/replay.py --provider retell --fault all        --calls 10

Faults:

    duplicate    redeliver one lifecycle webhook
    retry-tool   redeliver the tool invocation, same id (a transport retry)
    reissue-tool the model calls the tool again with a new id (Vapi only)
    reorder      swap two adjacent deliveries
    delay        sleep between some deliveries
    tamper       sign one body and send another
    all          every one of the above

The check is exactly-once, not at-most-once: every call whose booking request got
through must end up with exactly one booking, and no call may have two. Exit codes:
0 held, 1 violated, 2 no server, 3 inconclusive (a slot was already taken by an earlier
run; use a fresh database), 4 setup error such as a missing or wrong API token. Setup
problems get their own code so a misconfigured CI job never reads as a correctness bug.
Anomaly counts cover this run's calls only.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from dataclasses import dataclass
from typing import Any

import httpx

from callspine.providers.base import hmac_sha256_hex
from callspine.tools import SLOTS

FAULTS = ("none", "duplicate", "retry-tool", "reissue-tool", "reorder", "delay", "tamper", "all")

# Each provider books from its own half of the week, so runs against one database do
# not compete for slots.
SLOT_OFFSET = {"vapi": 0, "retell": len(SLOTS) // 2}


@dataclass
class Delivery:
    path: str
    body: dict[str, Any]
    is_tool: bool = False
    is_lifecycle: bool = False
    tamper: bool = False


def now_ms() -> int:
    return int(time.time() * 1000)


# ---- sequences, shaped like each provider's documentation ------------------------------


def vapi_call(call_id: str, slot: str) -> list[Delivery]:
    def msg(mtype: str, **extra: Any) -> dict[str, Any]:
        return {"message": {"type": mtype, "timestamp": now_ms(),
                            "call": {"id": call_id, "type": "inboundPhoneCall"}, **extra}}

    def status(s: str) -> Delivery:
        return Delivery("/webhooks/vapi", msg("status-update", status=s), is_lifecycle=True)

    tool = {"id": f"tc_{call_id}", "type": "function",
            "function": {"name": "book_appointment", "arguments": {"slot": slot}}}
    return [
        status("queued"),
        status("ringing"),
        status("in-progress"),
        Delivery("/webhooks/vapi", msg("speech-update", status="started", role="assistant", turn=1)),
        Delivery("/webhooks/vapi", msg("transcript", role="user", transcriptType="final",
                                       transcript=f"{slot} works for me")),
        Delivery("/webhooks/vapi", msg("tool-calls", toolCallList=[tool]), is_tool=True),
        status("ended"),
        Delivery("/webhooks/vapi", msg("end-of-call-report", endedReason="customer-ended-call"),
                 is_lifecycle=True),
    ]


def retell_call(call_id: str, slot: str) -> list[Delivery]:
    call = {"call_id": call_id, "agent_id": "agent_demo", "start_timestamp": now_ms()}

    def event(name: str, **extra: Any) -> dict[str, Any]:
        return {"event": name, "call": {**call, **extra}}

    return [
        Delivery("/webhooks/retell", event("call_started", call_status="ongoing"), is_lifecycle=True),
        Delivery("/webhooks/retell", event("transcript_updated", transcript="Agent: Hi.")),
        Delivery("/tools/retell", {"name": "book_appointment", "args": {"slot": slot}, "call": call},
                 is_tool=True),
        Delivery("/webhooks/retell", event("transcript_updated", transcript=f"User: {slot}.")),
        Delivery("/webhooks/retell", event("call_ended", call_status="ended"), is_lifecycle=True),
        Delivery("/webhooks/retell", event("call_analyzed", call_status="ended"), is_lifecycle=True),
    ]


# ---- signing ---------------------------------------------------------------------------


def sign(provider: str, body: bytes, secret: str) -> dict[str, str]:
    """Signed at send time, as a real sender would sign each attempt."""
    if provider == "vapi":
        return {"x-signature": hmac_sha256_hex(secret, body), "content-type": "application/json"}
    ts = now_ms()
    digest = hmac_sha256_hex(secret, body + str(ts).encode())
    return {"x-retell-signature": f"v={ts},d={digest}", "content-type": "application/json"}


# ---- faults ------------------------------------------------------------------------------


def inject(items: list[Delivery], fault: str, rng: random.Random) -> list[Delivery]:
    items = list(items)
    on = {f: fault in (f, "all") for f in ("duplicate", "retry-tool", "reissue-tool", "reorder", "tamper")}

    if on["duplicate"]:
        i = rng.choice([n for n, d in enumerate(items) if d.is_lifecycle])
        items.insert(i + 1, items[i])

    if on["retry-tool"]:
        i = next(n for n, d in enumerate(items) if d.is_tool)
        items.insert(i + 1, items[i])

    if on["reissue-tool"] and items[0].path == "/webhooks/vapi":
        i = next(n for n, d in enumerate(items) if d.is_tool)
        again = json.loads(json.dumps(items[i].body))
        call = again["message"]["toolCallList"][0]
        call["id"] = call["id"] + "-again"
        items.insert(i + 1, Delivery(items[i].path, again, is_tool=True))

    if on["reorder"]:
        i = rng.randrange(1, len(items) - 1)
        items[i], items[i + 1] = items[i + 1], items[i]

    if on["tamper"]:
        i = rng.randrange(len(items))
        d = items[i]
        items[i] = Delivery(d.path, d.body, d.is_tool, d.is_lifecycle, tamper=True)

    return items


def _read(client: httpx.Client, path: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    r = client.get(path, headers=headers)
    r.raise_for_status()
    return r.json()


def run(args: argparse.Namespace) -> int:
    rng = random.Random(args.seed)
    build = vapi_call if args.provider == "vapi" else retell_call
    sent = {"2xx": 0, "401": 0, "other": 0}
    call_ids: list[str] = []
    slots: dict[str, str] = {}
    expected: dict[str, bool] = {}

    auth = {"authorization": f"Bearer {args.api_token}"}
    with httpx.Client(base_url=args.base_url, timeout=15.0) as client:
        try:
            client.get("/healthz")
        except httpx.ConnectError:
            print(f"no server at {args.base_url}; start one with `make dev`", file=sys.stderr)
            return 2

        for n in range(args.calls):
            call_id = f"{args.provider}-{args.seed}-{n}"
            call_ids.append(call_id)
            slot = SLOTS[(SLOT_OFFSET[args.provider] + args.seed + n) % len(SLOTS)]
            slots[call_id] = slot
            plan = inject(build(call_id, slot), args.fault, rng)
            # A call should book if at least one of its booking requests was not tampered.
            expected[call_id] = any(d.is_tool and not d.tamper for d in plan)
            print(f"\n{call_id}  {len(plan)} deliveries  fault={args.fault}")

            for d in plan:
                if args.fault in ("delay", "all") and rng.random() < 0.25:
                    time.sleep(rng.uniform(0.1, 0.8))
                body = json.dumps(d.body).encode()
                headers = sign(args.provider, body, args.secret)
                if d.tamper:
                    body = body.replace(b"call", b"cal1", 1)
                r = client.post(d.path, content=body, headers=headers)
                bucket = "2xx" if r.is_success else "401" if r.status_code == 401 else "other"
                sent[bucket] += 1
                label = ("TAMPERED " if d.tamper else "") + ("tool " if d.is_tool else "")
                print(f"  {r.status_code}  {label}{d.path}  {r.text[:90]}")

        try:
            bookings = _read(client, "/api/bookings", auth)
            anomalies = _read(client, "/api/anomalies", auth)
        except httpx.HTTPStatusError as exc:
            print(f"\nSETUP ERROR: {exc.request.url.path} returned {exc.response.status_code}: "
                  f"{exc.response.text[:120]}\nIs the server's CALLSPINE_API_TOKEN the same as "
                  "--api-token?", file=sys.stderr)
            return 4

    print(f"\nsent  2xx={sent['2xx']}  401={sent['401']}  other={sent['other']}")

    mine = {c: [b for b in bookings if b["call_ref"] == c] for c in call_ids}
    owner = {b["slot"]: b["call_ref"] for b in bookings}

    counts: dict[str, int] = {}
    for a in anomalies:
        if a["call_ref"] in mine:
            counts[a["kind"]] = counts.get(a["kind"], 0) + 1
    print("\nanomalies recorded for these calls:")
    for kind, count in sorted(counts.items(), key=lambda kv: -kv[1]) or [("(none)", 0)]:
        print(f"  {count:>4}  {kind}")

    doubled = [c for c in call_ids if len(mine[c]) > 1]
    missing = [c for c in call_ids if expected[c] and not mine[c] and slots[c] not in owner]
    blocked = [c for c in call_ids if expected[c] and not mine[c] and slots[c] in owner]
    booked = sum(1 for c in call_ids if len(mine[c]) == 1)
    should = sum(expected.values())

    print(f"\nbookings: {booked} of {should} expected, {len(doubled)} doubled, {len(missing)} missing")
    if doubled or missing:
        print(f"EXACTLY-ONCE VIOLATED: doubled={doubled} missing={missing}")
        return 1
    if blocked:
        print(f"INCONCLUSIVE: slots already booked by an earlier run for {blocked}; use a fresh database")
        return 3
    print("exactly-once: held")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--provider", choices=("vapi", "retell"), default="vapi")
    p.add_argument("--fault", choices=FAULTS, default="all")
    p.add_argument("--calls", type=int, default=3)
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--secret", default="dev-secret", help="VAPI_SECRET or RETELL_API_KEY")
    p.add_argument("--api-token", default="dev-token", help="CALLSPINE_API_TOKEN")
    p.add_argument("--seed", type=int, default=1)
    return run(p.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
