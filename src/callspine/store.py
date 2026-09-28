"""Persistence for calls, events, spans, tool results and bookings.

SQLite, so the repo runs with no infrastructure. The SQL is SQLite's dialect
(`INSERT OR IGNORE`, pragmas); moving to Postgres would mean rewriting those statements.

Two rules hold throughout:

1. **Anything that must happen once is enforced by the database**, never by an unlocked
   "have I seen this?" check, because a check-then-insert races. Events, bookings and
   open spans use a UNIQUE constraint. Tool results use a lookup inside a write-locked
   transaction, with the primary key as a backstop.

2. **Anything that must happen together is one transaction.** Processing an event means
   recording it, reading the call's state, and writing the new state. If those commit
   separately, a failure halfway leaves the event marked as seen but never applied, and
   the provider's retry is then thrown away as a duplicate. `transaction()` opens with
   `BEGIN IMMEDIATE`, which takes SQLite's write lock up front. The lock is database-wide,
   so all writes are serialized, which is what stops two workers both reading a call's
   old state. The price is that anything slow inside a transaction delays everyone.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from callspine.domain import CallState, NormalizedEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
    call_ref      TEXT PRIMARY KEY,
    provider      TEXT NOT NULL,
    state         TEXT NOT NULL,
    created_ts_ms INTEGER NOT NULL,
    updated_ts_ms INTEGER NOT NULL
);

-- dedupe_key is NULL for stream events. SQLite treats NULLs as distinct in a UNIQUE
-- index, so streams are always stored and never collide.
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    provider       TEXT NOT NULL,
    dedupe_key     TEXT,
    call_ref       TEXT NOT NULL,
    type           TEXT NOT NULL,
    raw_type       TEXT NOT NULL,
    provider_ts_ms INTEGER,
    received_ts_ms INTEGER NOT NULL,
    payload        TEXT NOT NULL,
    UNIQUE (provider, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_events_call ON events (call_ref, received_ts_ms);

CREATE TABLE IF NOT EXISTS spans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    call_ref      TEXT NOT NULL,
    name          TEXT NOT NULL,
    started_ts_ms INTEGER NOT NULL,
    ended_ts_ms   INTEGER,
    attributes    TEXT NOT NULL DEFAULT '{}'
);
-- At most one open span of each name per call.
CREATE UNIQUE INDEX IF NOT EXISTS uq_spans_open ON spans (call_ref, name)
    WHERE ended_ts_ms IS NULL;

-- A tool invocation's result, keyed by the provider's invocation id. Written in the same
-- transaction as whatever the tool did, so a stored result always means it happened.
CREATE TABLE IF NOT EXISTS tool_results (
    provider        TEXT NOT NULL,
    invocation_id   TEXT NOT NULL,
    call_ref        TEXT NOT NULL,
    name            TEXT NOT NULL,
    args            TEXT NOT NULL,
    result          TEXT NOT NULL,
    created_ts_ms   INTEGER NOT NULL,
    PRIMARY KEY (provider, invocation_id)
);

-- The business-level guarantee. A slot is booked once, whatever the transport did.
CREATE TABLE IF NOT EXISTS bookings (
    slot          TEXT PRIMARY KEY,
    call_ref      TEXT NOT NULL,
    created_ts_ms INTEGER NOT NULL
);

-- What the system noticed but could not act on. Only authenticated traffic lands here,
-- so the table cannot be filled by anyone who can reach the endpoint.
CREATE TABLE IF NOT EXISTS anomalies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    call_ref      TEXT,
    provider      TEXT NOT NULL,
    kind          TEXT NOT NULL,
    detail        TEXT NOT NULL,
    noticed_ts_ms INTEGER NOT NULL
);
"""


def now_ms() -> int:
    return int(time.time() * 1000)


def _rows(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(r) for r in cur.fetchall()]


@dataclass
class Store:
    path: str = "callspine.db"
    _local: threading.local = field(default_factory=threading.local, init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        self._shared: sqlite3.Connection | None = None
        if self.path == ":memory:":
            # An in-memory database dies with its connection, so it gets one shared one,
            # guarded by a lock.
            self._shared = self._connect()
        else:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            with self.conn() as c:
                c.execute("PRAGMA journal_mode=WAL")
        with self.conn() as c:
            c.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        # isolation_level=None: autocommit, with transactions opened explicitly below.
        c = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=5000")
        return c

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        """The current transaction's connection if there is one, else a short-lived one."""
        tx = getattr(self._local, "tx", None)
        if tx is not None:
            yield tx
            return
        if self._shared is not None:
            with self._lock:
                yield self._shared
            return
        c = self._connect()
        try:
            yield c
        finally:
            c.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Everything inside commits together or not at all, holding the write lock.

        SQLite has one write lock for the whole database, so this serializes every
        transaction, not only those touching the same call. Waiting longer than the busy
        timeout raises `sqlite3.OperationalError`.

        Transactions do not nest. Joining an outer one would let an inner failure, if a
        caller caught it, commit half of the inner transaction's writes.
        """
        if getattr(self._local, "tx", None) is not None:
            raise RuntimeError("transactions do not nest")
        shared = self._shared is not None
        if shared:
            self._lock.acquire()
        c = self._shared if shared else self._connect()
        try:
            c.execute("BEGIN IMMEDIATE")
            self._local.tx = c
            try:
                yield
                c.execute("COMMIT")
            except BaseException:
                # SQLite may already have rolled back by itself (disk full, I/O error);
                # an unconditional ROLLBACK would then raise and hide the real error.
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
        finally:
            self._local.tx = None
            if shared:
                self._lock.release()
            else:
                c.close()

    # ---- events -------------------------------------------------------------

    def record_event(self, event: NormalizedEvent) -> bool:
        """Store an event. False means an event with this identity was already stored."""
        with self.conn() as c:
            cur = c.execute(
                """
                INSERT OR IGNORE INTO events
                    (provider, dedupe_key, call_ref, type, raw_type,
                     provider_ts_ms, received_ts_ms, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.provider.value,
                    event.dedupe_key,
                    event.call_ref,
                    event.type.value,
                    event.raw_type,
                    event.provider_ts_ms,
                    event.received_ts_ms,
                    json.dumps(event.payload),
                ),
            )
            return cur.rowcount == 1

    def first_event_ts(self, call_ref: str, event_type: str) -> int | None:
        """When the earliest event of a type happened, by the provider's clock where known.

        Earliest by timestamp, not first delivered: if turn 2 is delivered before turn 1,
        turn 1 is still the first word.
        """
        with self.conn() as c:
            row = c.execute(
                "SELECT MIN(COALESCE(provider_ts_ms, received_ts_ms)) AS ts FROM events "
                "WHERE call_ref = ? AND type = ?",
                (call_ref, event_type),
            ).fetchone()
            return row["ts"]

    def events_for(self, call_ref: str) -> list[dict[str, Any]]:
        with self.conn() as c:
            return _rows(
                c.execute(
                    "SELECT * FROM events WHERE call_ref = ? ORDER BY received_ts_ms, id",
                    (call_ref,),
                )
            )

    # ---- calls --------------------------------------------------------------

    def get_state(self, call_ref: str) -> CallState | None:
        with self.conn() as c:
            row = c.execute("SELECT state FROM calls WHERE call_ref = ?", (call_ref,)).fetchone()
            return CallState(row["state"]) if row else None

    def upsert_call(self, call_ref: str, provider: str, state: CallState) -> None:
        ts = now_ms()
        with self.conn() as c:
            c.execute(
                """
                INSERT INTO calls (call_ref, provider, state, created_ts_ms, updated_ts_ms)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(call_ref) DO UPDATE SET
                    state = excluded.state, updated_ts_ms = excluded.updated_ts_ms
                """,
                (call_ref, provider, state.value, ts, ts),
            )

    def list_calls(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.conn() as c:
            return _rows(
                c.execute("SELECT * FROM calls ORDER BY updated_ts_ms DESC LIMIT ?", (limit,))
            )

    # ---- spans --------------------------------------------------------------

    def open_span(self, call_ref: str, name: str, ts_ms: int, attributes: dict[str, Any]) -> bool:
        """Open a span unless one of that name is already open. The partial index decides."""
        with self.conn() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO spans (call_ref, name, started_ts_ms, attributes) "
                "VALUES (?, ?, ?, ?)",
                (call_ref, name, ts_ms, json.dumps(attributes)),
            )
            return cur.rowcount == 1

    def close_span(self, call_ref: str, name: str, ts_ms: int) -> bool:
        with self.conn() as c:
            cur = c.execute(
                "UPDATE spans SET ended_ts_ms = ? "
                "WHERE call_ref = ? AND name = ? AND ended_ts_ms IS NULL",
                (ts_ms, call_ref, name),
            )
            return cur.rowcount > 0

    def close_all_spans(self, call_ref: str, ts_ms: int) -> list[str]:
        """Close every open span on a call and return the names that were still open."""
        with self.conn() as c:
            names = [
                r["name"]
                for r in c.execute(
                    "SELECT name FROM spans WHERE call_ref = ? AND ended_ts_ms IS NULL",
                    (call_ref,),
                )
            ]
            c.execute(
                "UPDATE spans SET ended_ts_ms = ? WHERE call_ref = ? AND ended_ts_ms IS NULL",
                (ts_ms, call_ref),
            )
            return names

    def record_span(
        self, call_ref: str, name: str, started_ts_ms: int, ended_ts_ms: int,
        attributes: dict[str, Any],
    ) -> None:
        """Store a span measured in one place, such as a tool execution."""
        with self.conn() as c:
            c.execute(
                "INSERT INTO spans (call_ref, name, started_ts_ms, ended_ts_ms, attributes) "
                "VALUES (?, ?, ?, ?, ?)",
                (call_ref, name, started_ts_ms, ended_ts_ms, json.dumps(attributes)),
            )

    def spans_for(self, call_ref: str) -> list[dict[str, Any]]:
        with self.conn() as c:
            return _rows(
                c.execute(
                    "SELECT *, ended_ts_ms - started_ts_ms AS duration_ms FROM spans "
                    "WHERE call_ref = ? ORDER BY started_ts_ms, id",
                    (call_ref,),
                )
            )

    # ---- tool results -------------------------------------------------------

    def tool_result(self, provider: str, invocation_id: str) -> str | None:
        with self.conn() as c:
            row = c.execute(
                "SELECT result FROM tool_results WHERE provider = ? AND invocation_id = ?",
                (provider, invocation_id),
            ).fetchone()
            return row["result"] if row else None

    def save_tool_result(
        self, provider: str, invocation_id: str, call_ref: str, name: str,
        args: dict[str, Any], result: str,
    ) -> None:
        with self.conn() as c:
            c.execute(
                "INSERT INTO tool_results "
                "(provider, invocation_id, call_ref, name, args, result, created_ts_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (provider, invocation_id, call_ref, name, json.dumps(args), result, now_ms()),
            )

    def tool_results_for(self, call_ref: str) -> list[dict[str, Any]]:
        with self.conn() as c:
            return _rows(
                c.execute(
                    "SELECT * FROM tool_results WHERE call_ref = ? ORDER BY created_ts_ms",
                    (call_ref,),
                )
            )

    # ---- bookings -----------------------------------------------------------

    def book(self, slot: str, call_ref: str) -> str:
        """Book a slot once. Returns "booked", "already_yours" or "taken"."""
        with self.conn() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO bookings (slot, call_ref, created_ts_ms) VALUES (?, ?, ?)",
                (slot, call_ref, now_ms()),
            )
            if cur.rowcount == 1:
                return "booked"
            owner = c.execute("SELECT call_ref FROM bookings WHERE slot = ?", (slot,)).fetchone()
            return "already_yours" if owner["call_ref"] == call_ref else "taken"

    def booked_slots(self) -> set[str]:
        with self.conn() as c:
            return {r["slot"] for r in c.execute("SELECT slot FROM bookings")}

    def bookings(self, call_ref: str | None = None) -> list[dict[str, Any]]:
        with self.conn() as c:
            if call_ref is None:
                return _rows(c.execute("SELECT * FROM bookings ORDER BY created_ts_ms"))
            return _rows(
                c.execute(
                    "SELECT * FROM bookings WHERE call_ref = ? ORDER BY created_ts_ms", (call_ref,)
                )
            )

    # ---- anomalies ----------------------------------------------------------

    def record_anomaly(self, provider: str, kind: str, detail: str, call_ref: str | None) -> None:
        with self.conn() as c:
            c.execute(
                "INSERT INTO anomalies (call_ref, provider, kind, detail, noticed_ts_ms) "
                "VALUES (?, ?, ?, ?, ?)",
                (call_ref, provider, kind, detail, now_ms()),
            )

    def anomalies(self, limit: int = 500) -> list[dict[str, Any]]:
        with self.conn() as c:
            return _rows(
                c.execute(
                    "SELECT * FROM anomalies ORDER BY noticed_ts_ms DESC, id DESC LIMIT ?",
                    (limit,),
                )
            )
