# callspine

The reliability layer that sits under a hosted voice-agent platform.

Vapi and Retell both give you a voice agent in an afternoon. Neither gives you an
answer when a booking silently fails to reach the calendar, when the dashboard says a
call is live and your database says it ended, or when a customer is billed twice
because a webhook arrived twice.

This is one backend serving **the same agent on both platforms**, written so those
conditions are detected rather than discovered later by a customer. It exists to be
read, not to be a product.

```
Twilio number
      │
      ├── Vapi ────┐
      │            ├──▶  callspine  ──▶  normalized events ──▶ state machine ──▶ store
      └── Retell ──┘         │                                       │
                             ├── signature verification              ├── anomalies
                             ├── idempotency (DB-enforced)           └── latency spans
                             └── tool endpoint (mid-call)
```

## What running it against both platforms actually taught me

These are findings from `faultkit`, the fault-injection harness in this repo, not from
reading documentation.

| | Vapi | Retell |
|---|---|---|
| **Auth scheme** | Your choice: shared secret, or HMAC where *you* pick the algorithm, headers and payload format | Fixed: HMAC-SHA256 keyed with your API key |
| **Signature header** | Configurable (`x-vapi-signature` by default) | `x-retell-signature`, shaped `v={ts},d={digest}` |
| **What gets signed** | `{timestamp}.{body}` or `{body}`, depending on how you set the credential up | Raw body concatenated with the timestamp |
| **Replay protection** | Only if you chose a timestamped payload format | Timestamp is bound into the signature, but nothing forces you to check it |
| **Per-event id** | None | None usable — see below |
| **Biggest trap** | There is no single correct verifier for "a Vapi webhook". The right code depends on the credential you created. | The signature timestamp looks like an idempotency key and is not one. |

### The Retell timestamp trap

Retell's signature carries an authenticated millisecond timestamp. It is tempting to
key deduplication on `(call_id, event, timestamp)`, and I did.

`faultkit --fault duplicate` caught it in the first run. **A redelivery is re-signed at
the moment it is retried**, so the same logical event arrives twice bearing two
different timestamps, and a timestamp-keyed dedupe treats both as new. On a booking
tool that is a double booking.

The fix is to key on a hash of the raw body, which is what Vapi forces you into anyway.
The known cost is that two genuinely distinct events with byte-identical payloads
collapse into one. For a repeated identical transcript line that is cheap. For a
duplicated booking it is not, so the trade goes this way round.

Both adapters now dedupe identically, and the constraint is enforced by a `UNIQUE`
index rather than an application-level "have I seen this?" check, because check-then-
insert races against a concurrent redelivery and a unique index cannot.

### Re-serialising the body breaks verification

`json.dumps(json.loads(body))` is not `body`. Key order, unicode escaping and separator
whitespace all shift. Every signature in this repo is computed over the exact bytes
received.

This passes in any test suite that only uses ASCII names and fails on the first real
caller named Zoë. There is a test pinning it: `test_reserialised_json_breaks_the_signature`.

### Returning 500 to a provider is self-inflicted load

Both platforms retry non-2xx responses. An authenticated payload that will never parse
must not return 5xx, or one bad event becomes an infinite retry storm. Here it returns
200 with an anomaly row, which is visible without being load-bearing. Authentication
failures do return 401, because those should be loud and must not be retried.

## Quick start

```bash
uv venv && uv pip install -e ".[dev]"
make test          # 32 tests, no network, no credentials
make dev           # server on :8000
```

Then, in another terminal, break it on purpose:

```bash
python faultkit/replay.py --provider retell --fault duplicate
python faultkit/replay.py --provider vapi   --fault all --calls 5
curl localhost:8000/api/anomalies | jq
```

Sample output from `--fault all`:

```
delivered=20  2xx=18  401=2  other=0

anomalies recorded:
   4  span_unclosed_at_hangup
   4  duplicate_delivery
   2  signature_rejected
   2  illegal_transition
```

## Layout

| Path | What lives there |
|---|---|
| `src/callspine/domain.py` | Provider-neutral call model and the state machine that refuses illegal transitions |
| `src/callspine/providers/` | Vapi and Retell adapters. Pure functions over bytes and headers, no I/O |
| `src/callspine/ingest.py` | Verify, dedupe, advance state, record spans and anomalies |
| `src/callspine/store.py` | SQLite. Deduplication enforced by a `UNIQUE` index, not by application logic |
| `src/callspine/app.py` | Webhook endpoints, the mid-call tool endpoint, and a read API |
| `faultkit/replay.py` | Duplicate, reorder, delay and tamper injection against a live server |

## Wiring it to real phone numbers

The repo runs and tests end to end with no accounts. To put it on a real number:

```bash
export RETELL_API_KEY=...        # the key carrying the webhook badge
export VAPI_SECRET=...
export VAPI_PAYLOAD_FORMAT='{timestamp}.{body}'   # must match your Vapi credential
```

Point both platforms' webhook URLs at `/webhooks/retell` and `/webhooks/vapi`, and the
agent's tool at `/tools/check_availability`.

The Vapi variables are not optional detail. Because Vapi's HMAC format is yours to
define, `VAPI_PAYLOAD_FORMAT` has to match the credential you created or every request
fails closed. `VapiConfig` refuses to construct an incoherent combination rather than
failing mysteriously at request time.

## What this is not

Not a product, not a Vapi competitor, and not a recommendation of one platform over the
other. It is the answer to a question clients ask and most voice-AI freelancers cannot
answer: *what happens to my calls when the network misbehaves, and how would you know?*

Licence: MIT.
