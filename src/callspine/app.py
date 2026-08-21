"""HTTP surface: two webhook endpoints, one tool endpoint, and a small read API.

The webhook handlers read `await request.body()` and pass those exact bytes to the
adapter. They never hand the adapter a parsed dict, because a signature computed over
re-serialised JSON will not match for any payload containing a non-ASCII character or
a float that round-trips differently. This is the single most common reason webhook
verification "works in testing" and fails on a real call with a caller named Zoë.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.responses import JSONResponse

from callspine.ingest import Ingestor, observed_lag_summary
from callspine.providers.base import SignatureError, lower_headers
from callspine.providers.retell import RetellAdapter, RetellConfig
from callspine.providers.vapi import VapiAdapter, VapiConfig
from callspine.store import Store, now_ms


def build_adapters() -> dict[str, Any]:
    vapi = VapiAdapter(
        VapiConfig(
            mode=os.getenv("VAPI_MODE", "hmac"),
            secret=os.getenv("VAPI_SECRET", ""),
            signature_header=os.getenv("VAPI_SIGNATURE_HEADER", "x-vapi-signature"),
            timestamp_header=os.getenv("VAPI_TIMESTAMP_HEADER", "x-timestamp"),
            payload_format=os.getenv("VAPI_PAYLOAD_FORMAT", "{timestamp}.{body}"),
        )
    )
    retell = RetellAdapter(RetellConfig(api_key=os.getenv("RETELL_API_KEY", "")))
    return {"vapi": vapi, "retell": retell}


def create_app(store: Store | None = None, adapters: dict[str, Any] | None = None) -> FastAPI:
    app = FastAPI(
        title="callspine",
        description="Reliability layer under hosted voice-agent platforms.",
        version="0.1.0",
    )
    app.state.store = store or Store(os.getenv("CALLSPINE_DB", "callspine.db"))
    app.state.adapters = adapters if adapters is not None else build_adapters()
    app.state.ingestor = Ingestor(app.state.store)

    app.include_router(_webhooks())
    app.include_router(_tools())
    app.include_router(_read_api())

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"ok": True, "ts_ms": now_ms()}

    return app


def _webhooks() -> APIRouter:
    router = APIRouter(prefix="/webhooks", tags=["webhooks"])

    @router.post("/{provider}")
    async def receive(provider: str, request: Request) -> Response:
        adapters = request.app.state.adapters
        adapter = adapters.get(provider)
        if adapter is None:
            return JSONResponse({"error": "unknown provider"}, status_code=404)

        raw = await request.body()
        headers = lower_headers(request.headers)

        try:
            adapter.verify(raw, headers)
        except SignatureError as exc:
            # 401, not 500: this must not be retried, and it must be visible.
            request.app.state.store.record_anomaly(
                provider, "signature_rejected", str(exc), None
            )
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        try:
            events = adapter.normalize(raw, headers, now_ms())
        except Exception as exc:  # noqa: BLE001 - deliberately broad, see module docstring
            # Authenticated but unparseable. Returning 200 stops an infinite retry loop
            # over a payload that will never succeed; the anomaly row is the alarm.
            request.app.state.store.record_anomaly(
                provider, "unparseable_payload", f"{type(exc).__name__}: {exc}", None
            )
            return JSONResponse({"accepted": 0, "error": "unparseable"}, status_code=200)

        result = request.app.state.ingestor.handle(events)
        return JSONResponse(result.as_dict(), status_code=200)

    return router


def _tools() -> APIRouter:
    """The endpoint an agent calls mid-conversation.

    Deliberately trivial in behaviour and careful in shape: agents call this while a
    human is waiting, so it answers immediately and never blocks on anything slow.
    """
    router = APIRouter(prefix="/tools", tags=["tools"])

    _SLOTS = ["Tue 10:00", "Tue 14:30", "Wed 09:00", "Wed 16:00", "Thu 11:15"]

    @router.post("/check_availability")
    async def check_availability(request: Request) -> dict[str, Any]:
        body = await request.json()
        call_ref = str(body.get("call_id") or body.get("call_ref") or "unknown")
        store: Store = request.app.state.store
        span = store.open_span(call_ref, "tool_check_availability", {"tool": "availability"})
        try:
            return {"slots": _SLOTS, "call_ref": call_ref}
        finally:
            store.close_span(span)

    @router.post("/book")
    async def book(request: Request) -> dict[str, Any]:
        body = await request.json()
        call_ref = str(body.get("call_id") or body.get("call_ref") or "unknown")
        slot = str(body.get("slot", ""))
        store: Store = request.app.state.store
        if slot not in _SLOTS:
            store.record_anomaly(
                "tool", "invalid_slot", f"agent proposed unavailable slot {slot!r}", call_ref
            )
            return {"booked": False, "reason": "slot not available", "slots": _SLOTS}
        return {"booked": True, "slot": slot, "call_ref": call_ref}

    return router


def _read_api() -> APIRouter:
    router = APIRouter(prefix="/api", tags=["read"])

    @router.get("/calls")
    def calls(request: Request) -> list[dict[str, Any]]:
        return request.app.state.store.list_calls()

    @router.get("/calls/{call_ref}")
    def call_detail(call_ref: str, request: Request) -> dict[str, Any]:
        store: Store = request.app.state.store
        return {
            "call_ref": call_ref,
            "state": (s.value if (s := store.get_state(call_ref)) else None),
            "events": store.events_for(call_ref),
            "spans": store.spans_for(call_ref),
            "lag": observed_lag_summary(store, call_ref),
        }

    @router.get("/anomalies")
    def anomalies(request: Request) -> list[dict[str, Any]]:
        return request.app.state.store.anomalies()

    return router


app = create_app()
