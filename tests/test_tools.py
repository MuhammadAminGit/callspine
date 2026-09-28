"""Exactly-once tool execution: redelivered invocations, and the model asking again."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from callspine.providers.base import ToolInvocation
from callspine.store import Store
from callspine.tools import SLOTS, execute_once


def book(slot: str, *, call: str = "call-1", inv_id: str | None = "tc_1") -> ToolInvocation:
    return ToolInvocation(call_ref=call, name="book_appointment", args={"slot": slot}, invocation_id=inv_id)


def kinds(store: Store) -> list[str]:
    return [a["kind"] for a in store.anomalies()]


# ---- the same invocation delivered again ---------------------------------------


def test_redelivery_is_answered_from_the_stored_result(store):
    first, replayed_1 = execute_once(store, "vapi", book("Tue 10:00"))
    second, replayed_2 = execute_once(store, "vapi", book("Tue 10:00"))
    assert (replayed_1, replayed_2) == (False, True)
    assert first == second
    assert len(store.bookings()) == 1
    assert "tool_call_replayed" in kinds(store)


def test_concurrent_redeliveries_execute_once(tmp_path):
    """Twenty simultaneous deliveries of one invocation across twenty connections."""
    store = Store(str(tmp_path / "race.db"))
    with ThreadPoolExecutor(max_workers=20) as pool:
        outcomes = list(pool.map(lambda _: execute_once(store, "vapi", book("Wed 14:00")), range(20)))
    assert [replayed for _, replayed in outcomes].count(False) == 1
    assert len({result for result, _ in outcomes}) == 1
    assert len(store.bookings()) == 1


def test_failure_after_booking_leaves_nothing_behind(store, monkeypatch):
    """The booking and its stored result commit together or not at all.

    Storing the result fails after the slot was booked. Without one transaction this
    leaves a booking with no result, and every retry is then answered wrongly.
    """
    real = store.save_tool_result
    monkeypatch.setattr(store, "save_tool_result", lambda *a: (_ for _ in ()).throw(RuntimeError("disk")))
    with pytest.raises(RuntimeError):
        execute_once(store, "vapi", book("Tue 10:00"))
    assert store.bookings() == [] and store.tool_result("vapi", "tc_1") is None

    monkeypatch.setattr(store, "save_tool_result", real)
    result, replayed = execute_once(store, "vapi", book("Tue 10:00"))
    assert not replayed and json.loads(result) == {"booked": True, "slot": "Tue 10:00"}
    assert len(store.bookings()) == 1


# ---- the model asking again, with a new id ----------------------------------------


def test_new_invocation_for_the_same_booking_is_absorbed(store):
    """What id-based dedupe cannot see: the model re-issues the tool with a fresh id."""
    execute_once(store, "vapi", book("Tue 10:00", inv_id="tc_1"))
    r, replayed = execute_once(store, "vapi", book("Tue 10:00", inv_id="tc_2"))
    assert not replayed and json.loads(r)["booked"] is True
    assert len(store.bookings()) == 1
    assert "repeat_booking_absorbed" in kinds(store)


def test_no_invocation_id_relies_on_the_operation(store):
    """Retell custom functions carry no id, so only the operation protects them."""
    r1, _ = execute_once(store, "retell", book("Tue 10:00", inv_id=None))
    r2, _ = execute_once(store, "retell", book("Tue 10:00", inv_id=None))
    assert json.loads(r1) == json.loads(r2) == {"booked": True, "slot": "Tue 10:00"}
    assert len(store.bookings()) == 1


def test_slot_taken_by_another_call_is_a_real_conflict(store):
    execute_once(store, "retell", book("Tue 10:00", call="call-1", inv_id=None))
    r, _ = execute_once(store, "retell", book("Tue 10:00", call="call-2", inv_id=None))
    assert json.loads(r)["booked"] is False
    assert [b["call_ref"] for b in store.bookings()] == ["call-1"]


# ---- the operations ----------------------------------------------------------------


def test_invented_slot_is_refused_and_flagged(store):
    r, _ = execute_once(store, "vapi", book("Sun 03:00"))
    assert json.loads(r)["booked"] is False
    assert "invalid_slot" in kinds(store)


def test_availability_excludes_booked_slots(store):
    execute_once(store, "vapi", book(SLOTS[0]))
    inv = ToolInvocation(call_ref="call-1", name="check_availability", args={}, invocation_id="tc_2")
    r, _ = execute_once(store, "vapi", inv)
    assert SLOTS[0] not in json.loads(r)["available"]


def test_unknown_tool(store):
    inv = ToolInvocation(call_ref="call-1", name="launch_rockets", args={}, invocation_id="tc_3")
    r, _ = execute_once(store, "vapi", inv)
    assert "error" in json.loads(r) and "unknown_tool" in kinds(store)
