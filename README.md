# http-bait

An HTTP honeypot built to measure **exploitation** rather than discovery.

> **Research prototype.** This is an instrument for collecting and reasoning about
> scanner behaviour, and it is not a production security control. It has run on one
> host, for one window, under one operator. Read
> [DATA-HANDLING.md](DATA-HANDLING.md) and [SPEC.md](SPEC.md) §2 before deploying it,
> because running it makes you the custodian of a file of third-party network activity.

Most honeypot writeups tell you who connected. This one is built to tell you who *used*
what they found. It serves plausible leaked secrets (`.env`, `.git/config`,
`.aws/credentials`, …), admin login panels, and fake vulnerable-version banners to the
mass scanners that reach any new public IP within hours. Each synthetic secret carries a
unique id, so when one comes back in a later request, a specific scrape is tied to a
specific reuse by the value itself rather than by timing.

The exception is the live AWS canary path, where one real key is shared across up to
`HB_CANARYTOKENS_MAX_SERVINGS` visitors and is therefore attributable to a bounded set
rather than to an individual. See [the canary section](#the-one-thing-that-isnt-fake).

## What it measures

Findings belong to a deployment, not to this repository, so none ship here.
[FINDINGS.md](FINDINGS.md) is a template carrying the caveats you are expected to work
through before quoting any number you produce. Copy it to `FINDINGS.local.md`, which is
gitignored, and fill that in from your own logs.

The reason those caveats are the longest section of the template is that the hardest
problem with an instrument like this is not collecting data, it is knowing whether a
quiet result means nothing happened or means the detector could never have fired. This
codebase has produced both. A signature that shipped after the traffic it matches, and a
reuse detector blind to ~14% of the bait it was watching, both looked exactly like
absence of attack.

You can watch that failure mode happen on synthetic data that ships with the repo:

```bash
python analyze.py fixtures/sample_events.jsonl --rescan
```

The live pass finds one CVE. Re-applying the current signature set to the same retained
records finds five, including one whose signature postdates the traffic it matches by
five days. Nothing about the traffic changed; only the detector did.

[DETECTORS.md](DETECTORS.md) lists every signature and when it shipped, so you can tell
which of your own counts could only have come from a rescan.

## Run it

Locally, app only, bound to loopback:

```bash
docker compose -f docker-compose.local.yml up -d --build
curl -s http://localhost:8100/.env
python analyze.py data/logs/http_events.jsonl
```

The main `docker-compose.yml` runs Caddy on 80/443 and requests a certificate for the
hostname in `Caddyfile`, so it is for a real deployment rather than a laptop. It also
does not publish the app's port, which is why the local file above exists.

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
| `HB_CANARYTOKENS_MAX_SERVINGS` | `30` | Max visitors served one live key before re-minting, and therefore the size of the set a real-world trigger narrows to. Clamped to 100. It interacts with the cooldown: `MAX_SERVINGS × 86400 / RETRY_COOLDOWN_SECS` is the ceiling on live servings per day (8,640 at the defaults), so a busier host needs headroom or visitors silently get synthetic keys. The effective values are logged at startup as `canary_config`. |
| `HB_CANARYTOKENS_RETRY_COOLDOWN_SECS` | `300` | Floor between mint attempts against canarytokens.org. |
| `HB_OPERATOR_CONTACT` | unset | Address published in `/.well-known/security.txt` and the plugin manifest. Unset means the file says so explicitly rather than naming a placeholder nobody reads. |
| `HB_WINDOW_LABEL` | `unlabelled` | Tags every record with a collection window. Change it whenever the population changes, and **before publishing anything about a deployment**: readers arriving from a writeup are not organic scanner traffic, and mixing them invalidates every rate. `analyze.py --window <label>` then separates them. |

## The one thing that isn't fake

Everything served is synthetic by default. With `HB_CANARYTOKENS_LIVE=1`, the AWS
credential lure is backed by a **real, functioning** AWS canary key minted through
canarytokens.org's public API, so a genuine third-party use fires their alerting as well
as ours. The key grants no permissions; canarytokens.org's AWS canaries exist to trigger
detection rather than access.

**This is the one lure that is not uniquely attributable**, and it is the exception to
the uniqueness property described at the top of this file. One minted key is served to
up to `HB_CANARYTOKENS_MAX_SERVINGS` visitors, so a later real-world trigger narrows to
that set rather than to one visitor. Each serving is logged with a `serving_index` and a
`mint_generation` so the set can be reconstructed exactly. Do not describe a live-canary
trigger as proof that a particular visitor used the key.

If you enable it, leave the three caps alone. `MAX_SERVINGS` is not a tuning knob: it
bounds how many visitors could have been responsible for any single real-world trigger,
which is what makes an alert attributable at all. `RETRY_COOLDOWN_SECS` bounds the request
volume this can generate against canarytokens.org, a free service run by someone else.

## The agent-bait surface

Alongside the scanner lures, the service advertises a small machine-readable API and two
operations, so a client that reads a schema and then calls what it advertises leaves
much stronger evidence of automated tool use than a User-Agent or a request cadence
would.

| path | what it is |
|---|---|
| `/.well-known/ai-plugin.json` | Plugin manifest pointing at the OpenAPI document |
| `/openapi.json`, `/swagger.json` | A deliberately synthetic schema, never FastAPI's real one |
| `/api/v1/system/status` | `getSystemStatus`, logs `api_tool_call_attempt`, returns fake status |
| `/api/v1/jobs/run` | `runMaintenanceJob`, logs the job name and argument keys, runs nothing and returns 503 |

`analyze.py` reports discovery requests, operation calls, and the chains where the same
client did both.

This surface drew no traffic at all in the published window. That is a baseline rather
than a result: it was undocumented until now, and one quiet window on one hostname is
not evidence that agents do not do this.

FastAPI's own generated schema is never exposed (`openapi_url=None`), because it would
reveal the real route table and the trigger catcher.

## Ethics and scope

Read [SPEC.md §2](SPEC.md) before deploying. The short version, all of it load-bearing:

- **Nothing executes.** No route runs a command, queries a database, or makes an outbound
  request on a caller's behalf. No SSRF amplification, ever.
- **Not a DoS amplifier.** Per-IP rate limiting, hard body caps, no reflection.
- **Don't entrap.** It offers plausible exposed files and observes. It never solicits
  illegal action or walks a visitor toward one.
- **Visitor credentials are not retained.** Anything submitted to any route is recorded
  as presence and shape only, because credentials sprayed at honeypots are frequently
  real credentials stolen from someone else. Enforced in the middleware for every
  request rather than per handler, across form-encoded, JSON at any depth, multipart,
  query strings, and a pattern fallback for anything else. Values of credential-bearing
  headers are likewise reduced to a length and an ephemeral HMAC. See
  [DATA-HANDLING.md](DATA-HANDLING.md).
- **Coordinate disclosure.** If you catch a *named* vendor or tool doing something
  disclosure-worthy, tell them before you publish specifics.

Running this points a deliberately attackable surface at the internet under your name.
Give it its own host and a hostname with no association to anything else you run.

## Layout

```
app/main.py             FastAPI honeypot: routes, telemetry middleware, honeytoken minting
app/formatters.py       Per-kind fake-secret generators, and what length each one serves
app/signatures.py       Detection tables, shared with analyze.py so the two cannot drift
app/test_main.py        Behaviour tests (redaction, caps, non-retention)
app/test_regressions.py Regression tests for previously-broken detectors
analyze.py              Offline JSONL analyzer (stdlib only)
NOTICE                  Third-party terms, including the JA4+ commercial-use restriction
gen_detectors.py        Regenerates DETECTORS.md from the signature tables
fixtures/               Synthetic log plus the exact report the analyzer prints for it
Caddyfile               TLS reverse proxy with JA4/JA4H fingerprinting
docker-compose.yml      caddy + app, for a real deployment
docker-compose.local.yml App only, loopback, no TLS — for running it on your machine
deploy.sh               Push to a host and bring the stack up
pull-telemetry.sh       Fetch logs back for offline analysis
SPEC.md                 Design spec: what each piece is for, which constraints are load-bearing
FINDINGS.md             Template; copy to FINDINGS.local.md (gitignored) and fill that
DETECTORS.md            Generated signature timeline: what could have fired, and since when
DATA-HANDLING.md        What is recorded, what is discarded, what you inherit as operator
SECURITY.md             Reporting and data-removal contact
AGENTS.md               Machine-readable setup, commands, and hard constraints
```

## License

MIT for the code in this repository, see [LICENSE](LICENSE).

The Caddy image built by `caddy/Dockerfile` links JA4+ fingerprinting, which is
distributed under the **FoxIO License 1.1** and restricts commercial use. That
term reaches you as a downstream recipient and is not relicensed by the MIT
grant above. See [NOTICE](NOTICE), which also explains how to drop the
dependency if the restriction is a problem for you.
