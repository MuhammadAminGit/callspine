"""Persistence for calls, events and spans.

SQLite so the repo runs with no infrastructure, but the schema and queries are plain
enough to move to Postgres by swapping the connection.

The important design choice is that **deduplication is enforced by the database**, not
by an application-level "have I seen this?" check. A check-then-insert races: two
workers handling a duplicate delivery simultaneously both see "not seen", both insert,
and the call gets double-counted. A UNIQUE constraint cannot race. `record_event`
returns whether the row was new, and every caller branches on that.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
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

CREATE TABLE IF NOT EXISTS events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    provider          TEXT NOT NULL,
    provider_event_id TEXT NOT NULL,
    call_ref          TEXT NOT NULL,
    type              TEXT NOT NULL,
    provider_ts_ms    INTEGER,
    received_ts_ms    INTEGER NOT NULL,
    payload           TEXT NOT NULL,
    UNIQUE (provider, provider_event_id)
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

CREATE INDEX IF NOT EXISTS idx_spans_call ON spans (call_ref, started_ts_ms);

-- Anything the system noticed but could not act on: duplicates, illegal transitions,
-- events after hangup, unmapped types. This table is the product, not a debug aid.
CREATE TABLE IF NOT EXISTS anomalies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    call_ref     TEXT,
    provider     TEXT NOT NULL,
    kind         TEXT NOT NULL,
    detail       TEXT NOT NULL,
    noticed_ts_ms INTEGER NOT NULL
);
"""


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class Store:
    path: str = "callspine.db"

    def __post_init__(self) -> None:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._shared: sqlite3.Connection | None = None
        if self.path == ":memory:":
            # An in-memory database vanishes when its connection closes, so tests need
            # one long-lived connection rather than one per operation.
            self._shared = sqlite3.connect(self.path, check_same_thread=False)
            self._shared.row_factory = sqlite3.Row
        self.migrate()

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        if self._shared is not None:
            yield self._shared
            self._shared.commit()
            return
        c = sqlite3.connect(self.path, check_same_thread=False)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()

    def migrate(self) -> None:
        with self.conn() as c:
            c.executescript(SCHEMA)

    # ---- events -------------------------------------------------------------

    def record_event(self, event: NormalizedEvent) -> bool:
        """Insert an event. Returns True if it was new, False if it was a duplicate.

        The UNIQUE constraint does the work. `INSERT OR IGNORE` plus `rowcount` gives us
        the answer atomically, with no read-modify-write window for a concurrent
        redelivery to slip through.
        """
        with self.conn() as c:
            cur = c.execute(
                """
                INSERT OR IGNORE INTO events
                    (provider, provider_event_id, call_ref, type,
                     provider_ts_ms, received_ts_ms, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.provider.value,
                    event.provider_event_id,
                    event.call_ref,
                    event.type.value,
                    event.provider_ts_ms,
                    event.received_ts_ms,
                    json.dumps(event.payload),
                ),
            )
            return cur.rowcount == 1

    def events_for(self, call_ref: str) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM events WHERE call_ref = ? ORDER BY received_ts_ms, id",
                (call_ref,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ---- calls --------------------------------------------------------------

    def get_state(self, call_ref: str) -> CallState | None:
        with self.conn() as c:
            row = c.execute(
                "SELECT state FROM calls WHERE call_ref = ?", (call_ref,)
            ).fetchone()
            return CallState(row["state"]) if row else None

    def upsert_call(self, call_ref: str, provider: str, state: CallState) -> None:
        ts = now_ms()
        with self.conn() as c:
            c.execute(
                """
                INSERT INTO calls (call_ref, provider, state, created_ts_ms, updated_ts_ms)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(call_ref) DO UPDATE SET
                    state = excluded.state,
                    updated_ts_ms = excluded.updated_ts_ms
                """,
                (call_ref, provider, state.value, ts, ts),
            )

    def list_calls(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM calls ORDER BY updated_ts_ms DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ---- spans --------------------------------------------------------------

    def open_span(self, call_ref: str, name: str, attributes: dict | None = None) -> int:
        with self.conn() as c:
            cur = c.execute(
                "INSERT INTO spans (call_ref, name, started_ts_ms, attributes) VALUES (?, ?, ?, ?)",
                (call_ref, name, now_ms(), json.dumps(attributes or {})),
            )
            return int(cur.lastrowid or 0)

    def close_span(self, span_id: int) -> None:
        with self.conn() as c:
            c.execute("UPDATE spans SET ended_ts_ms = ? WHERE id = ?", (now_ms(), span_id))

    def spans_for(self, call_ref: str) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM spans WHERE call_ref = ? ORDER BY started_ts_ms, id",
                (call_ref,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ---- anomalies ----------------------------------------------------------

    def record_anomaly(self, provider: str, kind: str, detail: str, call_ref: str | None) -> None:
        with self.conn() as c:
            c.execute(
                """
                INSERT INTO anomalies (call_ref, provider, kind, detail, noticed_ts_ms)
                VALUES (?, ?, ?, ?, ?)
                """,
                (call_ref, provider, kind, detail, now_ms()),
            )

    def anomalies(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM anomalies ORDER BY noticed_ts_ms DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
