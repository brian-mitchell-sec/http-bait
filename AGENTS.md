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
python3 analyze.py data/logs/http_events.jsonl [--baseline OLD.jsonl] [--rdns] [--enrich]

# deploy / fetch telemetry
./deploy.sh <host_ip> <hostname>
./pull-telemetry.sh <host_ip>
```

## Layout

```
app/main.py             routes, telemetry middleware, honeytoken minting
app/formatters.py       per-kind fake-secret generators (pure functions of a token id)
app/signatures.py       detection tables, imported by BOTH main.py and analyze.py
app/test_main.py        behaviour tests
app/test_regressions.py regression tests for detectors that were once silently broken
analyze.py              offline JSONL analyzer, stdlib only
gen_detectors.py        regenerates DETECTORS.md; CI diffs it
fixtures/               synthetic log + the exact expected analyzer report; CI diffs it
Caddyfile               TLS termination + JA4/JA4H fingerprint headers
docker-compose.yml      caddy + app, with healthcheck and log caps
data/logs/              runtime output; gitignored, never committed
```

Environment variables are documented in README.md's configuration table. Every one is read
in `app/main.py`; if you add one, add it to that table in the same change.

## Hard constraints, do not violate

- **Nothing executes.** No route may run a command, query a database, fetch a URL, or make
  any outbound request on a caller's behalf. Routes that *look* like they do (`/api/run-job`,
  `/graphql`, the debug endpoints) must log and return a synthetic result. This is the
  single most important invariant in the repository; breaking it turns a research tool
  into an SSRF/RCE proxy pointed at the internet.
- **The one permitted outbound call** is minting a canary token from canarytokens.org, and
  only when `HB_CANARYTOKENS_LIVE=1`. It is part of constructing the bait, not an action
  taken for a caller, the caller never influences what is requested. Do not add a second
  outbound call, and do not gate any outbound call on attacker-supplied input.
- **Do not weaken the canarytokens caps.** `HB_CANARYTOKENS_MAX_SERVINGS` bounds how many
  visitors could be responsible for a single real-world trigger, which is what makes an
  alert attributable. `HB_CANARYTOKENS_RETRY_COOLDOWN_SECS` bounds request volume against
  a third party's free service. Neither is a performance knob.
- **Never retain visitor credentials.** Values sprayed at login lures are frequently real
  credentials stolen from third parties. Redaction is enforced in the MIDDLEWARE, for
  every request, via `infer_credential_submission`, not per handler. It used to be per
  handler, only four handlers called it, and every credential POSTed anywhere else was
  written to the log verbatim. Do not move this back into the route layer, do not
  "improve" it by capturing values, and do not print the legacy raw values that old log
  records may still contain.
- **Keep `SENSITIVE_HEADERS` redaction, and keep the salt ephemeral.** Values become a
  label, a length, and an HMAC under a per-process random key that is never persisted.
  A bare hash is not acceptable: Basic auth and low-entropy API keys are dictionary
  -recoverable from the log format alone. Adding a stored key would turn every historical
  log into an offline-crackable corpus.
- **Bound every attacker-controlled field.** UA, path, query, XFF, fingerprints and
  header_order all have caps, and `JsonlWriter.write` caps the assembled record. An
  unbounded field is a way to fill the disk, and a full disk stops collection while the
  service still answers 200s.
- **Honeytoken reuse detection must stay O(request), not O(issued × request).** Both sides
  are attacker-controlled: minting is free and the token set is capped at 50,000. Scanning
  every issued token against every request is a remotely triggerable CPU exhaustion on a
  single-worker event loop. Extract candidates from the request, then look them up.
- **Do not hardcode the token scan width.** Some formatters serve a 12-character prefix
  of the token id rather than all 16, and a detector matching only 16 is silently blind
  to them. This used to be a prose warning and a constant; it is now derived from
  `formatters.SERVED_TOKEN_LEN`, which every kind must declare and which
  `test_served_token_len_declarations_are_accurate` checks against real output. Add a
  formatter, add its declaration; the scan width follows.
- **Reuse detection must run even when a request is rate limited.** It used to sit below
  the limiter's early return, so replays were invisible for the whole duration of a
  burst, which is the exact shape a credential-spray has. Path, query and headers are
  scanned; the body is not available, and the resulting record says so
  (`body_available: false`).
- **The issued-token index must survive a restart.** It is rebuilt at startup from
  `honeytoken_issued` events in the retained log. Without that, every deploy silently
  emptied it and every earlier token became unmatchable. Evictions are logged, because a
  null result is only meaningful if you know the detector could have fired.
- **An unissued `/x/` hit is not a confirmed trigger.** `/x/` is a walkable public path.
  Genuine callbacks log `honeytoken_triggered`; everything else logs
  `catcher_probe_unissued`. Do not merge them.
- **Signature tables live in `app/signatures.py` and nowhere else.** `main.py` and
  `analyze.py` both import them. They were previously duplicated, drifted, and the copy
  that produced the published numbers was the stale one.
- **Telemetry must not fail silently.** `JsonlWriter.write` deliberately swallows write
  errors so a full disk cannot take the service down, which means `/healthz` is the only
  thing standing between "collecting" and "up but recording nothing." Keep the writer's
  error counters wired to `/healthz`, and keep the rotation pruning, without it the disk
  fills and collection stops with no outward symptom.
- **Do not log the internal healthcheck.** The container polls `/healthz` from loopback
  every 60s; logging it would swamp a dataset that sees a few hundred real requests a day.
  The middleware skips `/healthz` requests that arrive without `X-Forwarded-For`; requests
  through Caddy still get logged.
- **`/healthz` must not leak operator detail**, disk figures, failure counts, versions.
  Its body is `{"ok": bool}` and nothing else. It is reachable from the internet.
- **Keep CVE signature scopes honest.** `check_attack_patterns` matches each signature
  against a named haystack (`path`, `body`, `content-type`, `headers`, `any`). Header
  matching uses *all* header occurrences, not first-wins, scanners repeat headers to
  hide payloads. Attribution (`rec["ip"]`, `rec["headers"]`) stays first-wins.
- **Add a regression test for any detector you fix.** Two signatures in this repository
  were dead on arrival and nothing caught it, because a regex that never matches looks
  exactly like an attack that never happened. `app/test_regressions.py` exists for this.

## Testing

```bash
cd app && HB_LOG_DIR=/tmp/l python -m pytest -q
```

A combined run is fine. `test_regressions.py` has an autouse fixture that clears
rate-limit and token state between tests, which is what makes it safe; an earlier
version of this file called separate processes a hard constraint, and that has not been
true for some time. If you add a test that drives the app through `TestClient` without
that fixture, the per-IP rate limiter is real module state and you will get cascading
429s that look like unrelated bugs.

CI runs the suite on 3.12 (what the Dockerfile pins) and 3.14, plus three checks that
exist to keep documentation honest: the analyzer's output against
`fixtures/expected_analysis.txt`, `DETECTORS.md` against `gen_detectors.py`, and
`analyze.py` under a bare interpreter with no dependencies installed.

## Producing a findings report

`FINDINGS.md` is a template. **Write to `FINDINGS.local.md`, never to `FINDINGS.md`.**
`*.local.md` is gitignored; the template is tracked, so editing it in place puts a
deployment's data one `git add -A` away from being published. The same suffix applies to
any other operator-specific document you produce.

Never populate a findings report from `fixtures/`, that data is synthetic and exists to
test the analyzer. Never carry another deployment's numbers into a fork.

1. Confirm the collection window is closed. `HB_WINDOW_LABEL` must not have been
   changed mid-window, and must be bumped before anything about this deployment is
   published, because readers arriving from a writeup are not organic scanner traffic.
2. Record `git rev-parse HEAD`. Detector behaviour changes between commits, so a count
   without a commit cannot be compared to anything.
3. Generate the report:

   ```bash
   python3 analyze.py 'data/logs/http_events*.jsonl' --rescan --window <label> --exclude-ip <self-test ip>
   ```

4. Paste that output into `FINDINGS.local.md`'s Summary block verbatim. Do not hand-edit numbers into
   prose without leaving the block they came from.
5. Work through every caveat in the template before writing a single conclusion.

**Rules for what may be claimed:**

- **Never report a null without establishing the detector could have fired.** Check the
  signature's `since` against the window, check for `issued_token_index_evicted`, and
  check whether the traffic that would have carried it was rate limited. This
  repository has already published one null that was a blind spot rather than a
  finding. That is the failure mode to hunt for, not to rediscover.
- **Separate exploitation from fingerprinting.** A path probe against a version you
  advertise is reconnaissance. A payload that would execute against a real stack is an
  attempt. An aggregate that mixes them is the first number a skeptical reader attacks.
- **A honeytoken replay shows an automated loop closed**, not that a human decided to
  use a credential. Scrape-to-reuse latency is the defensible claim.
- **`catcher_probe_unissued` is not a confirmed trigger.**
- **The live AWS canary is attributable to a bounded set, never to an individual.**
- **Do not publish raw logs**, and do not pass `--full-ips` in anything published.

## Analysis privacy

`analyze.py --rdns` resolves every observed IP through your resolver chain, and `--enrich`
POSTs the full observed-IP set to ip-api.com. Both are off by default and both disclose
the honeypot's visitor list to a third party. Do not enable either in automated runs.
