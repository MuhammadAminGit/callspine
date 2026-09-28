# callspine

The reliability layer under a hosted voice agent.

Vapi and Retell will get an agent answering a phone in an afternoon. What they leave to
you is everything that goes wrong between their servers and yours: webhooks that arrive
twice, out of order, or after the call has ended, and tool calls that book something
twice because a request was retried or the model simply asked again.

callspine is one backend serving the same agent on both platforms, written so those
conditions are handled on purpose and recorded when they happen.

```
                 ┌── Vapi ────┐                       ┌─ verify signature (raw bytes)
 phone number ───┤            ├──▶ /webhooks/{p} ─────┼─ dedupe on event identity ──▶ state machine
                 └── Retell ──┘                       └─ latency spans
                        │                                  (one transaction per event)
                        └─ tool call ─▶ execute exactly once ──▶ bookings
                                        (one transaction per invocation)

                 anything unexpected ──▶ anomalies table ──▶ GET /api/anomalies
```

## What the two platforms actually give you

Everything in this table comes from each provider's documentation (links at the bottom).

| | Retell | Vapi |
|---|---|---|
| Webhook auth | HMAC-SHA256 with your API key, `x-retell-signature: v={ms},d={hex}`, 5 minute window | Shared secret, or an HMAC credential whose header, timestamp and payload format **you** configure. No published defaults. |
| Idempotency guidance | Explicit, and different per event class | None |
| Retry policy | Webhooks: up to 3 retries if no 2xx in 10s. Custom functions: up to 5 if enabled | Not documented |
| Tool invocation id | **None.** Docs say the endpoint "must be idempotent" | **Yes**, `toolCallId` on every call |
| Tool response | Any 2xx body | Required: `{"results": [{"name", "toolCallId", "result"}]}` |

The rest of this README is what those differences force you to do.

### A tool call must happen once, and there are two ways it doesn't

A duplicated transcript is noise. A duplicated booking, or a duplicated promise to pay,
is a real-world mistake. The same request can reach the backend twice in two different
ways, and each needs its own defence.

**The same invocation, delivered again.** Retell retries custom functions when configured
to. Vapi documents no retry policy, but a response lost on the way back is a request the
sender may reasonably resend. Vapi gives every invocation an id, so the stored result is
replayed without running anything. Retell gives no id, so there is nothing to look up.

**The model asking again.** An LLM that did not hear the first answer, or wanted to
confirm, issues a *new* invocation with a *new* id. No id-based check can see that. For
a Vapi deployment this is arguably the more likely duplicate. Only an operation that is
itself idempotent catches it: a slot is booked once, and the same call asking again is
told it succeeded.

So both layers are always on. Each invocation runs as one transaction: look up any
stored result, run the tool, store the result. Either all of it happened or none of it
did, so a crash can never leave a booking without its result or a result without its
booking. `test_concurrent_redeliveries_execute_once` fires twenty simultaneous deliveries
of one invocation across twenty connections and asserts exactly one executes.

That works because these tools only touch this database. A tool that calls an external
API cannot be rolled back and would need a lease on the claim instead.

### Processing an event is one transaction

Recording an event, reading the call's state and writing the new state commit together.
Commit them separately and a failure halfway leaves the event marked as seen but never
applied, so the provider's retry is thrown away as a duplicate and the call is stuck.

The transaction opens with `BEGIN IMMEDIATE`, taking SQLite's write lock up front. That
is what makes several workers on one database safe: without it, two events for the same
call both read the old state, and an `in_progress` written second reopens a call that
had already ended. `test_two_workers_cannot_reopen_an_ended_call` forces exactly that
interleaving.

The lock is database-wide, so every event and every tool call is serialized, not only
those for the same call. That is simple and correct, and it is the real limit of this
design: a slow tool holds up every other webhook. The tools here take milliseconds. A
request that cannot get the lock within five seconds gets a 503, and since nothing was
committed it is safe for the provider to repeat.

### The signature timestamp is not an idempotency key

It is the most tempting field in the request: unique-looking, authenticated, always
present. The first version of this repo keyed on it. But neither provider documents it
as stable across deliveries, and a sender that signs each attempt at send time (as this
repo's fault harness does) gives every retry a new one. Keyed that way, every retry
looks like a new event.

So identity comes from what the event *means*. Retell documents it: `event` + `call_id`
for lifecycle events, `event` + `call_id` + `start_timestamp` for transfers. Vapi
documents nothing, so the keys are derived: a call passes through each status once and
has one end-of-call report.

### Streams are not duplicates

Retell's docs say `transcript_updated` must not be deduplicated by call: each delivery is
new information. The same holds for Vapi's transcripts and speech updates. Streams get no
dedupe key and are always stored.

### Post-call reports arrive after the end

Retell's `call_analyzed` and Vapi's `end-of-call-report` arrive after the call ended, by
design, so they are never flagged. A report arriving *before* the end event means the end
delivery was lost or is still retrying. The report proves the call ended, so it closes
the call, and the late end event is then rejected rather than applied twice.

### Verify against the raw bytes

`json.dumps(json.loads(body))` is not `body`. Retell's docs warn about exactly this.
`test_reserialised_json_breaks_the_signature` pins it with a caller named Zoë, the kind
of payload that passes every ASCII-only test suite and fails on a real call.

### Status codes are chosen for what the provider does next

An authenticated payload that will never parse gets a 200 and an anomaly row, because
Retell retries anything that is not a 2xx and a 500 would turn it into a retry storm.
Authentication failures get a 401 and are logged rather than stored, so nobody who can
reach the endpoint can fill the database. A database that is too busy gets a 503 rather
than an unhandled 500.

## faultkit

`faultkit/replay.py` replays realistic call sequences at a running server while doing
what networks and models do: redeliver a webhook, retry the tool call with the same id,
re-issue it with a new id, reorder deliveries, delay them, and tamper with a body.

The check is exactly-once, not at-most-once. Every call whose booking request got
through must end up with exactly one booking, and none may have two. It exits 1 on a
violation and 4 on a setup problem such as a mismatched API token, so a misconfigured CI
job never reads as a correctness bug. And it does fail when it should: against a server patched to drop bookings it reports five
missing, and against one patched to double-book it reports three doubled.

```bash
make dev                                        # in one terminal
python faultkit/replay.py --provider vapi   --fault all --calls 5
python faultkit/replay.py --provider retell --fault all --calls 5
```

Output of those commands, on a fresh database (seeded, so it reproduces):

```
vapi                                        retell

sent  2xx=50  401=5  other=0               sent  2xx=35  401=5  other=0

anomalies recorded for these calls:        anomalies recorded for these calls:
     9  duplicate_delivery                      4  duplicate_delivery
     4  tool_call_replayed                      4  repeat_booking_absorbed
     3  repeat_booking_absorbed                 1  report_before_end
     2  span_open_at_end                        1  event_after_end

bookings: 5 of 5 expected,                 bookings: 5 of 5 expected,
          0 doubled, 0 missing                       0 doubled, 0 missing
exactly-once: held                         exactly-once: held
```

On the Vapi side, `tool_call_replayed` is a redelivered invocation answered from its
stored result, and `repeat_booking_absorbed` is the model re-issuing the tool with a new
id, which only the idempotent booking can catch. On the Retell side there is no id at
all, so every repeat is absorbed by the booking. `span_open_at_end` marks the two calls
where the tamper fault got the agent's first speech event rejected, so as far as the
server knows the agent never spoke.

faultkit has already caught one real bug this way. A reordered run delivered the agent's
first word *before* the call's answer event, and the first-word span was opened after the
speech it was waiting for, so a call where the agent did speak was reported as one where
it did not. The span is now completed from the earlier event, and
`test_first_word_delivered_before_the_answer_is_not_a_silent_agent` pins it.

## Latency

| Span | Opens | Closes | Tells you |
|---|---|---|---|
| `ring_to_answer` | ringing | in progress | how long the call rang |
| `answer_to_first_word` | in progress | assistant starts speaking | silence after pickup (Vapi only; Retell does not report speech) |
| `tool:{name}` | invocation received | result returned | tool latency, and whether it was a replay |

Spans use the provider's timestamp when it sends one, so delivery jitter stays out of
the measurement. They are still webhook timing: a close proxy for what the caller
experienced, not a measurement of the audio. A span still open when the call ends is
closed and flagged, because it means nobody answered or the agent never spoke. Open
spans live in the database, and a partial unique index allows at most one open span of
each name per call.

Separately, `delivery_lag` compares the provider's timestamp with arrival time, which is
how you tell a slow agent from a slow webhook.

## What is verified, and what is not

**Checked against provider docs:** both signature schemes, Retell's event names and
idempotency guidance, Vapi's message types and tool-call response format, Retell's
custom-function request shape.

**Tested:** 85 tests, no network or credentials. The race and atomicity tests were
checked by removing the transactions and confirming they fail. faultkit runs in CI
against a live local server.

**Not yet done, or assumed:**
- Not run against live Vapi or Retell accounts. The fixtures in `tests/fixtures` are
  built from documented shapes, not captured traffic.
- Vapi's HMAC details are not published. This assumes SHA-256, a bare hex digest and an
  integer-millisecond timestamp, and fails closed if any is wrong. The default signs the
  body alone, which never expires; configure a timestamp header for replay protection.
- Retell's docs do not say whether a transfer's `start_timestamp` is the transfer's or
  the call's. If it is the call's, two transfer attempts to the same destination in one
  call would share a dedupe key.
- Retell chat events are refused (voice only). Vapi's `assistant-request` is not
  implemented, so the phone number needs a saved assistant.
- SQLite only, with one writer at a time across the whole database. Fine for tools that
  take milliseconds; a tool calling an external API would need its own short claim and
  record transactions instead of holding the lock while it waits. The SQL uses SQLite's
  dialect, so Postgres would mean rewriting it.

## Quick start

```bash
make setup
make test
make dev      # port 8000, with dev credentials that match faultkit's defaults
make fault    # PROVIDER=retell FAULT=reissue-tool CALLS=10 to vary it
```

The read API exposes transcripts and phone numbers, so it needs a bearer token and is
disabled when `CALLSPINE_API_TOKEN` is unset. `make dev` sets it to `dev-token`:

```bash
curl -H "Authorization: Bearer dev-token" localhost:8000/api/anomalies
curl -H "Authorization: Bearer dev-token" localhost:8000/api/calls/<call id>
```

## Wiring it to real numbers

```bash
export RETELL_API_KEY=...                 # the key with the webhook badge
export VAPI_SECRET=...
export VAPI_SIGNATURE_HEADER=x-signature  # whatever your Vapi credential uses
export VAPI_TIMESTAMP_HEADER=x-timestamp  # optional, but it is what enables replay protection
export VAPI_PAYLOAD_FORMAT='{timestamp}.{body}'
export CALLSPINE_API_TOKEN=...            # long and random
```

- Retell webhook URL: `/webhooks/retell`
- Retell custom function URL: `/tools/retell` (default payload mode, not "args only")
- Vapi server URL: `/webhooks/vapi`
- Tools: `check_availability` and `book_appointment(slot)`

## Layout

| Path | |
|---|---|
| `src/callspine/domain.py` | Provider-neutral call model; state machine that refuses illegal transitions |
| `src/callspine/providers/` | One adapter per provider. Pure functions of bytes and headers |
| `src/callspine/ingest.py` | Dedupe, advance state, measure, record: one transaction per event |
| `src/callspine/tools.py` | Exactly-once tool execution: one transaction per invocation |
| `src/callspine/store.py` | SQLite. "Once" is a UNIQUE constraint or a write-locked lookup; "together" is a transaction |
| `src/callspine/app.py` | Webhooks, the Retell function endpoint, the authenticated read API |
| `faultkit/replay.py` | Fault injection against a running server |

## Sources

- Retell webhooks, events and idempotency: https://docs.retellai.com/features/webhook
- Retell signature verification: https://docs.retellai.com/features/secure-webhook
- Retell custom functions: https://docs.retellai.com/build/conversation-flow/custom-function
- Vapi server events: https://docs.vapi.ai/server-url/events
- Vapi server authentication: https://docs.vapi.ai/server-url/server-authentication

MIT licensed.
