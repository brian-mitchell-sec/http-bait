# AGENTS.md

Machine-readable notes for coding agents working on this repository. Humans want
[README.md](README.md).

## What this is

An internet-facing HTTP honeypot. It serves fake leaked credentials and fake vulnerable
software banners to mass scanners and logs what they do. Everything it returns is bait.
Nothing it returns is real.

## Setup

- Python 3.12 (matches `Dockerfile`'s `python:3.12-slim`).
- `pip install -r app/requirements.txt`
- Tests additionally need `pytest`.
- Docker and Docker Compose for a full-stack run.

## Commands

```bash
# run the app alone
cd app && HB_LOG_DIR=./logs uvicorn main:app --host 0.0.0.0 --port 8100

# run the full stack (caddy + app)
docker compose up -d --build

# tests (both files; run them in separate processes, see Testing below)
cd app && HB_LOG_DIR=/tmp/l1 python -m pytest test_main.py -q
cd app && HB_LOG_DIR=/tmp/l2 python -m pytest test_regressions.py -q

# analyze a log
python analyze.py data/logs/http_events.jsonl [--baseline OLD.jsonl] [--rdns] [--enrich]

# deploy / fetch telemetry
./deploy.sh <host_ip> <hostname>
./pull-telemetry.sh <host_ip>
```

## Layout

```
app/main.py             routes, telemetry middleware, honeytoken minting, CVE signatures
app/formatters.py       per-kind fake-secret generators (pure functions of a token id)
app/test_main.py        behaviour tests
app/test_regressions.py regression tests for detectors that were once silently broken
analyze.py              offline JSONL analyzer, stdlib only
Caddyfile               TLS termination + JA4/JA4H fingerprint headers
docker-compose.yml      caddy + app, with healthcheck and log caps
data/logs/              runtime output; gitignored, never committed
```

Environment variables are documented in README.md's configuration table. Every one is read
in `app/main.py`; if you add one, add it to that table in the same change.

## Hard constraints — do not violate

- **Nothing executes.** No route may run a command, query a database, fetch a URL, or make
  any outbound request on a caller's behalf. Routes that *look* like they do (`/api/run-job`,
  `/graphql`, the debug endpoints) must log and return a synthetic result. This is the
  single most important invariant in the repository; breaking it turns a research tool
  into an SSRF/RCE proxy pointed at the internet.
- **The one permitted outbound call** is minting a canary token from canarytokens.org, and
  only when `HB_CANARYTOKENS_LIVE=1`. It is part of constructing the bait, not an action
  taken for a caller — the caller never influences what is requested. Do not add a second
  outbound call, and do not gate any outbound call on attacker-supplied input.
- **Do not weaken the canarytokens caps.** `HB_CANARYTOKENS_MAX_SERVINGS` bounds how many
  visitors could be responsible for a single real-world trigger, which is what makes an
  alert attributable. `HB_CANARYTOKENS_RETRY_COOLDOWN_SECS` bounds request volume against
  a third party's free service. Neither is a performance knob.
- **Never retain visitor credentials.** `mark_credential_submission` records presence and
  length only. Values sprayed at login lures are frequently real credentials stolen from
  third parties. Do not "improve" this by capturing them, and do not print the legacy raw
  values that old log records may still contain.
- **Keep `SENSITIVE_HEADERS` redaction.** Authorization and Cookie headers are replaced
  with a scheme-and-length placeholder before logging.
- **Honeytoken reuse detection must stay O(request), not O(issued × request).** Both sides
  are attacker-controlled: minting is free and the token set is capped at 50,000. Scanning
  every issued token against every request is a remotely triggerable CPU exhaustion on a
  single-worker event loop. Extract candidates from the request, then look them up.
- **Match both token forms.** Some formatters serve a 12-character prefix of the token id
  (`db_password`, and the password inside `db_connection_string`) rather than all 16. A
  detector that only matches 16 characters is silently blind to those kinds. See
  `TOKEN_PREFIX_LEN` and `_issued_token_prefixes` in `app/main.py`.
- **Telemetry must not fail silently.** `JsonlWriter.write` deliberately swallows write
  errors so a full disk cannot take the service down, which means `/healthz` is the only
  thing standing between "collecting" and "up but recording nothing." Keep the writer's
  error counters wired to `/healthz`, and keep the rotation pruning — without it the disk
  fills and collection stops with no outward symptom.
- **Do not log the internal healthcheck.** The container polls `/healthz` from loopback
  every 60s; logging it would swamp a dataset that sees a few hundred real requests a day.
  The middleware skips `/healthz` requests that arrive without `X-Forwarded-For`; requests
  through Caddy still get logged.
- **`/healthz` must not leak operator detail** — disk figures, failure counts, versions.
  Its body is `{"ok": bool}` and nothing else. It is reachable from the internet.
- **Keep CVE signature scopes honest.** `check_attack_patterns` matches each signature
  against a named haystack (`path`, `body`, `content-type`, `headers`, `any`). Header
  matching uses *all* header occurrences, not first-wins — scanners repeat headers to
  hide payloads. Attribution (`rec["ip"]`, `rec["headers"]`) stays first-wins.
- **Add a regression test for any detector you fix.** Two signatures in this repository
  were dead on arrival and nothing caught it, because a regex that never matches looks
  exactly like an attack that never happened. `app/test_regressions.py` exists for this.

## Testing

Run `test_main.py` and `test_regressions.py` in **separate processes**. Both drive the app
through `TestClient` from the same client address, and the per-IP rate limiter is real
module state — a combined run exhausts it and produces cascading 429 failures that look
like unrelated bugs. `test_regressions.py` has an autouse fixture that clears rate-limit
and token state between its own tests.

## Analysis privacy

`analyze.py --rdns` resolves every observed IP through your resolver chain, and `--enrich`
POSTs the full observed-IP set to ip-api.com. Both are off by default and both disclose
the honeypot's visitor list to a third party. Do not enable either in automated runs.
