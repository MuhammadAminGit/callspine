"""HTTP surface: provider webhooks, the Retell function endpoint, and a read API.

Handlers read `await request.body()` and pass those exact bytes to the adapter. A
signature computed over re-serialised JSON will not match any payload containing a
non-ASCII character or a float that round-trips differently.

Status codes are chosen for what the provider does next:

- 401 for authentication failures. These should be loud and never retried. They are
  logged, not stored, so unauthenticated traffic cannot fill the database.
- 503 when the database write lock is not free within the busy timeout. Nothing was
  committed, so the delivery is safe to repeat.
- 200 for an authenticated payload we cannot parse. Retell retries anything that is not
  a 2xx within ten seconds, so a 500 here turns one malformed event into a retry storm.
  The anomaly row is the alarm instead.

Database work and tool execution run in a threadpool, so a slow tool or a busy lock
never stalls the event loop that every other request is waiting on.

The read API exposes transcripts and phone numbers, so it requires a bearer token and is
disabled entirely when none is configured.

Run with `uvicorn --factory callspine.app:create_app`.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from callspine.ingest import Ingestor, delivery_lag
from callspine.providers.base import SignatureError, constant_time_eq, lower_headers
from callspine.providers.retell import RetellAdapter, RetellConfig
from callspine.providers.vapi import VapiAdapter, VapiConfig, is_tool_call
from callspine.store import Store, now_ms
from callspine.tools import execute_once

log = logging.getLogger("callspine")


def adapters_from_env() -> dict[str, Any]:
    return {
        "vapi": VapiAdapter(
            VapiConfig(
                mode=os.getenv("VAPI_MODE", "hmac"),
                secret=os.getenv("VAPI_SECRET", ""),
                signature_header=os.getenv("VAPI_SIGNATURE_HEADER", "x-signature"),
                timestamp_header=os.getenv("VAPI_TIMESTAMP_HEADER", ""),
                payload_format=os.getenv("VAPI_PAYLOAD_FORMAT", "{body}"),
            )
        ),
        "retell": RetellAdapter(RetellConfig(api_key=os.getenv("RETELL_API_KEY", ""))),
    }


def create_app(
    store: Store | None = None,
    adapters: dict[str, Any] | None = None,
    api_token: str | None = None,
) -> FastAPI:
    app = FastAPI(title="callspine", version="0.2.0")
    store = store or Store(os.getenv("CALLSPINE_DB", "callspine.db"))
    adapters = adapters if adapters is not None else adapters_from_env()
    api_token = api_token if api_token is not None else os.getenv("CALLSPINE_API_TOKEN", "")
    ingestor = Ingestor(store)

    def unauthorized(provider: str, exc: SignatureError) -> JSONResponse:
        log.warning("rejected %s request: %s", provider, exc)
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    def busy(exc: sqlite3.OperationalError) -> JSONResponse:
        # The write lock is database-wide and was not free within the busy timeout.
        # Nothing was committed, so the delivery is safe to repeat.
        log.warning("database busy: %s", exc)
        return JSONResponse({"error": "busy, retry"}, status_code=503)

    def require_token(request: Request) -> None:
        if not api_token:
            raise HTTPException(403, "read API disabled; set CALLSPINE_API_TOKEN to enable it")
        presented = request.headers.get("authorization", "")
        if not constant_time_eq(presented, f"Bearer {api_token}"):
            raise HTTPException(401, "unauthorized")

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"ok": True, "ts_ms": now_ms()}

    @app.post("/webhooks/{provider}")
    async def webhook(provider: str, request: Request) -> JSONResponse:
        adapter = adapters.get(provider)
        if adapter is None:
            return JSONResponse({"error": "unknown provider"}, status_code=404)

        raw = await request.body()
        headers = lower_headers(request.headers)
        try:
            adapter.verify(raw, headers)
        except SignatureError as exc:
            return unauthorized(provider, exc)

        try:
            return await process_webhook(provider, adapter, raw, headers)
        except sqlite3.OperationalError as exc:
            return busy(exc)

    async def process_webhook(
        provider: str, adapter: Any, raw: bytes, headers: dict[str, str]
    ) -> JSONResponse:
        vapi_tools = provider == "vapi" and is_tool_call(raw)
        try:
            events = adapter.normalize(raw, headers, now_ms())
        except Exception as exc:  # noqa: BLE001 - see module docstring on 200 vs 500
            await run_in_threadpool(
                store.record_anomaly, provider, "unparseable_payload",
                f"{type(exc).__name__}: {exc}", None,
            )
            # Vapi is waiting for a results list on tool calls, even an empty one.
            return JSONResponse({"results": []} if vapi_tools else {"accepted": 0})

        outcome = await run_in_threadpool(ingestor.handle, events)

        if vapi_tools:
            # Vapi waits on this response and speaks the result. A duplicate delivery
            # still gets an answer: the stored one.
            results = await run_in_threadpool(_run_vapi_tools, store, adapter, raw)
            return JSONResponse({"results": results})

        return JSONResponse(outcome.as_dict())

    @app.post("/tools/retell")
    async def retell_function(request: Request) -> JSONResponse:
        """Retell custom-function endpoint. Signed exactly like Retell's webhooks."""
        adapter: RetellAdapter = adapters["retell"]
        raw = await request.body()
        try:
            adapter.verify(raw, lower_headers(request.headers))
        except SignatureError as exc:
            return unauthorized("retell", exc)

        try:
            return await process_function(adapter, raw)
        except sqlite3.OperationalError as exc:
            return busy(exc)

    async def process_function(adapter: RetellAdapter, raw: bytes) -> JSONResponse:
        try:
            inv = adapter.parse_function_call(raw)
        except Exception as exc:  # noqa: BLE001
            await run_in_threadpool(
                store.record_anomaly, "retell", "unparseable_function_call", str(exc), None
            )
            return JSONResponse({"error": "could not read the function call"})

        try:
            result, _ = await run_in_threadpool(execute_once, store, "retell", inv)
        except sqlite3.OperationalError:
            raise
        except Exception as exc:  # noqa: BLE001
            await run_in_threadpool(
                store.record_anomaly, "retell", "tool_failed", f"{inv.name}: {exc}", inv.call_ref
            )
            return JSONResponse({"error": "that did not work, please try again"})
        return JSONResponse(json.loads(result))

    api = APIRouter(prefix="/api", dependencies=[Depends(require_token)])

    @api.get("/calls")
    def calls() -> list[dict[str, Any]]:
        return store.list_calls()

    @api.get("/calls/{call_ref}")
    def call_detail(call_ref: str) -> dict[str, Any]:
        state = store.get_state(call_ref)
        return {
            "call_ref": call_ref,
            "state": state.value if state else None,
            "events": store.events_for(call_ref),
            "spans": store.spans_for(call_ref),
            "tool_results": store.tool_results_for(call_ref),
            "bookings": store.bookings(call_ref),
            "delivery_lag": delivery_lag(store, call_ref),
        }

    @api.get("/anomalies")
    def anomalies() -> list[dict[str, Any]]:
        return store.anomalies()

    @api.get("/bookings")
    def bookings() -> list[dict[str, Any]]:
        return store.bookings()

    app.include_router(api)
    return app


def _run_vapi_tools(store: Store, adapter: VapiAdapter, raw: bytes) -> list[dict[str, Any]]:
    try:
        invocations = adapter.tool_calls(raw)
    except Exception as exc:  # noqa: BLE001
        store.record_anomaly("vapi", "unparseable_tool_call", str(exc), None)
        return []

    results = []
    for inv in invocations:
        try:
            result, _ = execute_once(store, "vapi", inv)
        except sqlite3.OperationalError:
            raise  # the webhook answers 503; nothing was committed
        except Exception as exc:  # noqa: BLE001
            store.record_anomaly("vapi", "tool_failed", f"{inv.name}: {exc}", inv.call_ref)
            result = json.dumps({"error": "that did not work, please try again"})
        results.append({"name": inv.name, "toolCallId": inv.invocation_id, "result": result})
    return results
