# http-bait

An HTTP honeypot that measures **exploitation**, not discovery.

Most honeypot writeups tell you who connected. This one is built to tell you who *used*
what they found. It serves plausible leaked secrets (`.env`, `.git/config`,
`.aws/credentials`, …), admin login panels, and fake vulnerable-version banners to the
mass scanners that reach any new public IP within hours — and every "secret" it serves is
a unique, attributable honeytoken. When one of those values comes back in a later request,
that is proof a specific scrape led to a specific reuse, not an inference from timing.

## What it found

Numbers below cover a 12.66-day window (2026-07-10 to 2026-07-22): 3,820 requests from
159 distinct IPs, 810 honeytokens issued.

- **Real exploitation, fast.** Genuine exploit attempts for Log4Shell (CVE-2021-44228,
  a JNDI callback sprayed into headers), Spring4Shell (CVE-2022-22965, a POST trying to
  plant a JSP webshell via `Runtime.exec()`), React2Shell (CVE-2025-55182), PHPUnit
  (CVE-2017-9841), and WP-Automatic SQLi (CVE-2024-27956) — 41 hits across 5 CVEs by
  retroactive scan, from 24 IPs.
- **One confirmed honeytoken replay.** An IP scraped a fake GitHub PAT from
  `/.git/config` and replayed it as a live `Authorization: Bearer` header against a batch
  of API-secret probe paths roughly two minutes later.
- **Nothing touched the credential-stuffing bait.** No `/admin/login` password spraying
  in the whole window, despite the panel being served and indexed.

Detail, caveats, and the numbers you should *not* quote without reading the caveats are in
[FINDINGS.md](FINDINGS.md). Two matter most: the live and retroactive CVE counts differ
(17 vs 41) because two detector signatures shipped *after* the traffic they match arrived,
and both are lower bounds because request bodies are capped.

## Run it

```bash
docker compose up -d --build
curl -s http://localhost:8100/.env          # a lure, via the app directly
python analyze.py data/logs/http_events.jsonl
```

Tests:

```bash
docker run --rm -v "$PWD:/src" -w /src python:3.12-slim sh -c "pip install -q -r app/requirements.txt pytest && cd app && HB_LOG_DIR=/tmp/l python -m pytest -q"
```

To put it on the internet — which is the only way it collects anything interesting — see
[DEPLOY.md](DEPLOY.md). You need a host with Docker, a DNS name pointing at it, and ports
80/443 free. A $4–6/month VPS is enough; the service is idle-cheap and there are no API
costs unless you opt into live canary tokens (below).

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `HB_LOG_DIR` | `/data/logs` | Where `http_events.jsonl` is written. |
| `HB_CANARY_BASE` | `https://http-bait.example` | Public base URL embedded in canary URLs. Must be the hostname you actually serve, or callbacks won't reach you. |
| `HB_LOG_MAX_BYTES` | `209715200` (200MB) | Rotate the live log at this size. |
| `HB_LOG_KEEP_ROTATED` | `10` | Rotated files to keep. `0` keeps everything — only safe if something else prunes, or the disk will fill and collection will stop. |
| `HB_HEALTH_MIN_FREE_BYTES` | `536870912` (512MB) | Below this free space, `/healthz` reports unhealthy. |
| `HB_CANARYTOKENS_LIVE` | unset (off) | Opt in to minting **real** AWS canary keys via canarytokens.org. See below. |
| `HB_CANARYTOKENS_REFRESH_SECS` | `86400` | Max age of a minted live key before re-minting. |
| `HB_CANARYTOKENS_MAX_SERVINGS` | `30` | Max times one live key is served before re-minting. |
| `HB_CANARYTOKENS_RETRY_COOLDOWN_SECS` | `300` | Floor between mint attempts against canarytokens.org. |

## The one thing that isn't fake

Everything served is synthetic by default. With `HB_CANARYTOKENS_LIVE=1`, the AWS
credential lure is backed by a **real, functioning** AWS canary key minted through
canarytokens.org's public API, so a genuine third-party use fires their alerting as well
as ours. The key grants no permissions — canarytokens.org's AWS canaries exist to trigger
detection, not access.

If you enable it, leave the three caps alone. `MAX_SERVINGS` is not a tuning knob: it
bounds how many visitors could have been responsible for any single real-world trigger,
which is what makes an alert attributable at all. `RETRY_COOLDOWN_SECS` bounds the request
volume this can generate against canarytokens.org, a free service run by someone else.

## Ethics and scope

Read [SPEC.md §2](SPEC.md) before deploying. The short version, all of it load-bearing:

- **Nothing executes.** No route runs a command, queries a database, or makes an outbound
  request on a caller's behalf. No SSRF amplification, ever.
- **Not a DoS amplifier.** Per-IP rate limiting, hard body caps, no reflection.
- **Don't entrap.** It offers plausible exposed files and observes. It never solicits
  illegal action or walks a visitor toward one.
- **Visitor credentials are never retained.** Anything submitted to a login lure is
  recorded as presence and shape only — credentials sprayed at honeypots are frequently
  real credentials stolen from someone else.
- **Coordinate disclosure.** If you catch a *named* vendor or tool doing something
  disclosure-worthy, tell them before you publish specifics.

Running this points a deliberately attackable surface at the internet under your name.
Give it its own host and a hostname with no association to anything else you run.

## Layout

```
app/main.py            FastAPI honeypot: routes, telemetry middleware, honeytoken minting
app/formatters.py      Per-kind fake-secret generators
app/test_main.py       Behaviour tests (redaction, caps, non-retention)
app/test_regressions.py Regression tests for previously-broken detectors
analyze.py             Offline JSONL analyzer (stdlib only)
Caddyfile              TLS reverse proxy with JA4/JA4H fingerprinting
docker-compose.yml     caddy + app
deploy.sh              Push to a host and bring the stack up
pull-telemetry.sh      Fetch logs back for offline analysis
SPEC.md                Design spec: what each piece is for, which constraints are load-bearing
AGENTS.md              Machine-readable setup, commands, and hard constraints
```

## License

MIT. See [LICENSE](LICENSE).
