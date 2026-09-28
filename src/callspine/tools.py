"""Tools the agent calls mid-conversation, executed exactly once.

A tool call is where a duplicate stops being harmless. A repeated transcript is noise; a
repeated booking, or a repeated promise-to-pay record, is a real-world mistake. There are
two ways the same request reaches the backend twice, and they need different defences:

- **The same invocation delivered again.** Retell retries custom functions up to five
  times when configured to, and its docs say the endpoint must be idempotent. Vapi
  documents no retry policy, but a request that times out on the way back is still a
  request the caller may resend. Vapi puts an id on every invocation, so the stored
  result is replayed. Retell provides no id, so there is nothing to look up.

- **The model asking again.** An LLM that did not hear the first answer, or decided to
  confirm, issues a *new* invocation with a *new* id. No id-based check can see that. Only
  an operation that is itself idempotent can: a slot is booked once, and the same call
  asking again is told it succeeded.

So both layers are always on. The id lookup makes replay exact where an id exists; the
idempotent operation catches everything else.

Each invocation runs in one transaction: look up the stored result, run the tool, store
the result. Either all of it happened or none of it did, so a crash can never leave a
booking without its stored result, or a result without its booking. The lookup is only
safe because the transaction holds the write lock; the primary key on tool results is
the backstop if that were ever not true.

Two consequences. The write lock is database-wide, so a tool's run time delays every
other webhook, and tools here must stay fast. And a tool calling an external API cannot
be rolled back: it would need to claim the invocation in its own short transaction,
call out, and record the result in another, with a lease so a crash does not strand the
claim. None of the tools here call out.
"""

from __future__ import annotations

import json
from typing import Any

from callspine.providers.base import ToolInvocation
from callspine.store import Store, now_ms

# A week of hourly slots. Stands in for whatever calendar a real deployment talks to.
SLOTS: list[str] = [
    f"{day} {hour:02d}:00"
    for day in ("Mon", "Tue", "Wed", "Thu", "Fri")
    for hour in range(9, 17)
]


def _available(store: Store, limit: int = 5) -> list[str]:
    taken = store.booked_slots()
    return [s for s in SLOTS if s not in taken][:limit]


def run_tool(store: Store, provider: str, inv: ToolInvocation) -> dict[str, Any]:
    """The operations themselves. Each is safe to repeat."""
    if inv.name == "check_availability":
        return {"available": _available(store)}

    if inv.name == "book_appointment":
        slot = str(inv.args.get("slot", "")).strip()
        if slot not in SLOTS:
            # Models propose times that were never offered. The tool is the last line.
            store.record_anomaly(
                provider, "invalid_slot", f"agent asked for {slot!r}, which was never offered",
                inv.call_ref,
            )
            return {"booked": False, "reason": "that time is not available",
                    "available": _available(store)}

        outcome = store.book(slot, inv.call_ref)
        if outcome == "taken":
            return {"booked": False, "reason": "that time was just taken",
                    "available": _available(store)}
        if outcome == "already_yours":
            store.record_anomaly(
                provider, "repeat_booking_absorbed",
                f"{slot} requested again by the same call; no second booking made",
                inv.call_ref,
            )
        return {"booked": True, "slot": slot}

    store.record_anomaly(provider, "unknown_tool", f"no tool named {inv.name!r}", inv.call_ref)
    return {"error": f"unknown tool {inv.name}"}


def execute_once(store: Store, provider: str, inv: ToolInvocation) -> tuple[str, bool]:
    """Run a tool at most once per invocation. Returns (result_json, was_replayed)."""
    with store.transaction():
        started = now_ms()  # after the lock is held, so waiting for it is not tool time
        if inv.invocation_id is not None:
            stored = store.tool_result(provider, inv.invocation_id)
            if stored is not None:
                store.record_anomaly(
                    provider, "tool_call_replayed",
                    f"{inv.name} {inv.invocation_id} delivered again; "
                    "answered from the stored result",
                    inv.call_ref,
                )
                _span(store, inv, started, replayed=True)
                return stored, True

        result = json.dumps(run_tool(store, provider, inv))
        if inv.invocation_id is not None:
            store.save_tool_result(
                provider, inv.invocation_id, inv.call_ref, inv.name, inv.args, result
            )
        _span(store, inv, started, replayed=False)
        return result, False


def _span(store: Store, inv: ToolInvocation, started: int, *, replayed: bool) -> None:
    store.record_span(
        inv.call_ref, f"tool:{inv.name}", started, now_ms(),
        {"invocation_id": inv.invocation_id, "replayed": replayed},
    )
