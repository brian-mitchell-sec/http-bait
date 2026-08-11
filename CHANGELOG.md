# Changelog

## v0.1.3, 2026-08-11

Fixes from an external adversarial review of the repository itself. Each is in
a failure class this project claims to hunt, which is exactly why they matter.

- **Oversized User-Agents no longer destroy issuance records.**
  `honeytoken_issued` logged `session` (ip|ua) uncapped; a >128KB UA pushed the
  record over `RECORD_MAX_BYTES`, the backstop's keep-list dropped
  token/kind/route, and the issuance — the record that makes later reuse
  attributable — was silently deleted with no eviction event to bound the null.
  `session` is now capped (`SESSION_CAP`) and the oversize keep-list retains
  token/kind/route. Regression test: a 1MB UA must not lose an issuance, and
  the index must rebuild from the surviving records.
- **The offline reuse scan now sees what the live one sees.** The runtime
  detector scans path, query, body and headers; `analyze.py` omitted path, so
  a token replayed only in the request path fired live and was invisible in
  the report findings come from. The fixture itself contained such a replay
  (slack_webhook issued at `/config.json`, replayed to `/x/...` by a different
  address): the frozen report now counts it, going from 2 circumstantial hits
  to 3. The remaining live/offline asymmetry (offline same-route/time
  exclusions) is documented at the scan site.
- **The "single squashed commit" provenance claim removed.** `signatures.py`
  and the generated `DETECTORS.md` justified two `since: "unknown"` entries by
  claiming the repository was one squashed commit. It was not; `git log -S`
  dates both signatures' current forms to 2026-08-04. A provenance artifact
  whose premise fails one command is worse than no date at all.
- **The live-canary state machine has tests.** `get_live_aws_pair()` — the
  code whose failure harms canarytokens.org, not us — had zero coverage. Now:
  the servings cap is a hard bound (exhausted cache returns None, never
  over-serves), the retry floor bounds outbound mint attempts to one per
  window under an outage, an exhausted cache is not served after a failed
  remint, a merely time-stale cache keeps serving, and a mint exception
  degrades to the synthetic formatter instead of a 500. Writing those tests
  surfaced a real defect, caught by CI rather than locally:
  `_live_aws_last_attempt_at` initialized to `0.0` measured against
  `time.monotonic()`, so on a host with uptime under the retry floor the very
  first mint attempt was judged "inside the cooldown window" and no live pair
  was ever minted — the service looked healthy and silently served only
  synthetic keys. It now initializes to `-CANARYTOKENS_RETRY_COOLDOWN_SECS`,
  and a test pins the fresh-boot behaviour.
- `analyze.py`'s `TOKEN_PREFIX_LEN` fallback narrowed to `ImportError` and made
  loud; a broad `except` silently reverted the scan width on any breakage in
  `formatters.py`, the constant-goes-stale bug the import exists to prevent.
- `pull-telemetry.sh` honors `SSH_USER` like `deploy.sh` does; the CI badge
  URL had a literal newline in it and rendered as broken text; the README now
  shows the live-vs-rescan fixture output instead of only describing it, and
  links the sister MCP project.
- **One placeholder, everywhere.** The `HB_CANARY_BASE` code default was
  `https://http-bait.example` while the compose files, the Caddyfile and
  deploy.sh's rewrite pattern all used `https://http-bait.example.com`, and the
  README's configuration table documented the code value. The code default and
  the README now use the deploy placeholder, so there is exactly one string for
  deploy.sh to rewrite and one for an operator to recognize. A CI step greps
  all four locations against it, because doc-drift detection is already this
  workflow's job.

Tests 55 to 64.

## v0.1.2, 2026-08-04

Fork-and-run fixes. No behaviour change to the service; this release is about
whether a stranger can stand it up without asking anyone.

- **The JA4 escape hatch works now.** `NOTICE` told operators who cannot accept
  the FoxIO License 1.1 commercial-use restriction to remove two `--with` lines
  from `caddy/Dockerfile`. That was not sufficient: the Caddyfile also uses the
  `ja4` listener wrapper and two directives, and stock Caddy refuses to parse
  them, exits, and serves nothing. Ships `Caddyfile.nofingerprint`, validated
  against `caddy:2.8-alpine`, and `docker-compose.nofingerprint.yml`. Anyone who
  followed the documented licensing route on v0.1.1 got a service that would not
  start.
- **`deploy.sh` fails honestly.** Its readiness loop swallowed stderr, so an auth
  failure, a wrong address and a host that was down all printed "still
  provisioning" forever. It now probes once, fails in ten seconds with the real
  error, and suggests `SSH_USER` for the common case of root login being
  disabled. `READY_TIMEOUT` bounds the wait.
- **Documented analyzer commands use the log glob.** The singular filename reads
  one segment after rotation and prints a smaller number with no sign anything
  is missing. The analyzer now also warns when it finds rotated siblings it was
  not given.
- **`DEPLOY.md` gained "After the first deploy"**, covering the gap between the
  stack reporting healthy and the data being trustworthy: reachability from a
  third machine, whether TLS actually provisioned, excluding your own address,
  where `/healthz` failure detail goes, the rotation glob, and build sizing.
- `HB_OPERATOR_CONTACT` surfaced on the deploy path. `gen_detectors.py` writes
  `DETECTORS.md` instead of printing it, which is what the docs always claimed.
  `.dockerignore`, since the build context included collected telemetry. `ruff`
  config and a CI lint step.

## v0.1.1, 2026-08-04

Fixes for defects found in review after v0.1.0 was tagged. **v0.1.0 ships a
credential-retention defect and should not be deployed or cited.**

- **Credential redaction covers every request shape.** v0.1.0 handled flat
  form-encoded bodies and flat top-level JSON only; nested JSON, JSON arrays,
  XML, multipart and query strings were written to the log verbatim while the
  documentation claimed otherwise. Query strings leaked in the `query` field as
  well as the body.
- **Exploit attempts and vulnerability probes are counted separately.** A
  path-only signature cannot observe a payload, so reaching
  `/vendor/phpunit/.../eval-stdin.php` is reconnaissance rather than an exploit
  attempt. Any figure of the form "N exploit attempts across M CVEs" produced
  before this needs regenerating; the denominator changes.
- **Every record carries its collection window**, and issuances carry `ip`, so
  `--window` and `--exclude-ip` reach derived events. Previously a report scoped
  to one window silently kept issuances, triggers and reuse hits from outside it.
- **The live canary registers its catcher token after minting**, so the
  creation-time webhook canarytokens.org sends to validate the URL is no longer
  recorded as a confirmed trigger.
- **Analyzer output is sanitized by default.** User-Agents, probed paths,
  GraphQL text and parsed commands are attacker-controlled; `--show-payloads`
  opts back in for private analysis. IPv6 anonymization uses
  `ipaddress.ip_network` and no longer emits invalid networks.
- `HB_OPERATOR_CONTACT` replaces the placeholder address in `security.txt`.
- `NOTICE` records the FoxIO License 1.1 restriction on the JA4+ fingerprinting
  built into the Caddy image, which the MIT grant does not relicense.

Tests 33 to 55.

## v0.1.0, 2026-08-03

First tagged release. Everything below landed in one pass after a review of the initial
public drop. Several items change what the tooling reports, so any figure produced by an
earlier version has to be regenerated before it is cited.

**`FINDINGS.md` is a template now.** Results belong to a deployment while the code
travels to whoever forks it, so the repository ships the part that generalizes: the list
of caveats to work through before quoting any number. Fill in a copy at
`FINDINGS.local.md`, which is gitignored. `AGENTS.md` gained a "Producing a findings
report" section with the commands and the rules about what may be claimed.

### Privacy and data handling

- **Credential redaction moved from the route layer to the middleware.** It applied only
  to the four registered panel handlers, so a credential POSTed to any other path fell
  through to the catch-all and was written to `body_excerpt` verbatim. `/admin` is
  advertised in `robots.txt` and `sitemap.xml` but only registered `GET`, so a stuffing
  tool POSTing to the advertised URL had its credentials stored in full. These are
  frequently credentials stolen from an uninvolved third party, which made this the one
  defect here with someone else's harm attached.
- **`SENSITIVE_HEADERS` extended** to `x-api-key`, `api-key`, `apikey`, `x-auth-token`,
  `auth-token`, `x-access-token`, `access-token`, `x-session-token`,
  `x-amz-security-token`, `x-goog-api-key`, `x-functions-key`. For a project whose thesis
  is credential replay in headers, these were the wrong ones to be keeping in the clear.
- **Redacted values now carry an HMAC** under a per-process random key that is never
  persisted, so repeat values stay correlatable within a run without the values
  surviving it, and without the digests being attackable offline.
- **GraphQL no longer retains raw bodies.** Credential-shaped literals are stripped, and
  a body that does not parse as JSON is recorded as a shape rather than as text.
- **Every attacker-controlled log field is bounded**, plus a 128KB cap on the assembled
  record. UA, path, query, XFF, fingerprints and `header_order` were unbounded.
- **[DATA-HANDLING.md](DATA-HANDLING.md)** added.

### Detection correctness

- **Reuse detection now runs on rate-limited requests.** It sat below the limiter's early
  return, so replays were invisible for the whole duration of a burst. A credential replay
  characteristically arrives as a rapid `Authorization` spray across many probe paths,
  which is exactly the shape that trips the limiter, so the detector was blind to the
  traffic it exists to catch. Any earlier "no replay" result is bounded by this.
- **The issued-token index is rebuilt at startup** from `honeytoken_issued` events.
  Previously in-memory only, so every restart silently emptied it. Evictions are now
  logged rather than silent.
- **Unissued `/x/` probes are a separate event** (`catcher_probe_unissued`) from genuine
  callbacks. `/x/` is a walkable public path; counting probes as confirmed triggers
  inflated the one metric meant to be unambiguous.
- **The live canary catcher token is registered** like any other issuance, so a hit on
  its own webhook URL is attributable instead of looking like a stranger's probe.
- **Token scan width is derived, not hardcoded.** `formatters.SERVED_TOKEN_LEN` declares
  what each kind serves; the detector scans at the minimum, and a test checks every
  declaration against real output. The original bug, matching only the full 16-character
  id while two kinds serve 12, blinding the detector to ~14% of issuances, was possible
  because nothing enforced the assumption.
- **An oversized body retains its leading 64KB** instead of discarding everything. A
  single 64,001-byte chunk previously retained zero bytes, and Caddy proxies with
  `flush_interval -1`, so large bodies arrive in few large chunks.
- **`body_len` on a truncated request is now `body_len_at_least`.** It previously
  recorded `BODY_CAP + 1`, a specific length that was never measured.

### Reproducibility

- **`analyze.py` computes the route and status distributions.** It reported neither
  before, so a findings document citing them could not point at the tool that produced
  them.
- **`--rescan` implements the retroactive CVE scan.** `analyze.py` previously tallied
  only the `cve_pattern_match` events the service had already written, so it could not
  surface traffic that predated a signature. Re-applying the current signature set to
  retained records is now a flag on the published tool rather than an offline step, and
  per-CVE distinct-IP counts and first-seen dates come with it.
- **The offline reuse scan matches 12-character prefixes.** `main.py` handled this
  before the initial release; `analyze.py` did not, and the offline path is the one a
  findings report is generated from.
- **`--exclude-ip` / `--exclude-ua`** make self-test exclusion a recorded flag rather
  than an offline step, and the report prints how many records each dropped.
- **Third-party addresses print as /24 by default** (`--full-ips` opts out), so
  truncation is a property of the tool rather than of editorial practice.
- **Signature tables moved to `app/signatures.py`**, imported by both the service and the
  analyzer. They were duplicated and had already drifted: `analyze.py` was missing
  `java:ProcessBuilder` and three route variants including the three pinned parallel
  variants the comparison experiment depends on.
- **Torn final lines are skipped and counted.** `pull-telemetry.sh` rsyncs a file being
  appended to, so an unterminated last record is normal; an unguarded `json.loads`
  aborted the whole report.
- **Multiple files and globs** are accepted, so rotated logs are reachable.
- **`fixtures/`** ships a synthetic log and the exact report the analyzer prints for it.
  CI diffs them. The fixture contains traffic predating one of its own signatures, so the
  live-versus-rescan gap is reproducible without the raw data.
- **`HB_WINDOW_LABEL`** tags records with a collection window, so post-publication
  traffic can be separated from the organic scanner population rather than silently
  contaminating it.

### Signatures

- **CVE-2024-27956 (WP-Automatic SQLi) added.** It appeared in the original findings
  table with no signature anywhere in the code.
- **CVE-2020-25213 corrected.** The id was attached to a pattern matching xmlrpc
  pingback/multicall abuse, which is a different thing entirely. That pattern now reports
  as `WP-XMLRPC-PINGBACK` (unchanged, so historical counts carry over) and a real
  wp-file-manager signature was added under the correct id.
- **CVE-2016-1000027's description corrected.** It described the actuator write-env
  chain; the pattern was always HttpInvoker deserialization, so only the comment was
  wrong.
- **Signatures carry a `since` date**, surfaced in logs, in `--rescan` output, and in the
  generated [DETECTORS.md](DETECTORS.md). Dates that are not recoverable from this
  repository's history are marked `unknown` rather than guessed.

### Packaging and docs

- CI on 3.12 and 3.14, plus a container build-and-healthcheck job.
- [SECURITY.md](SECURITY.md), [DATA-HANDLING.md](DATA-HANDLING.md),
  [DETECTORS.md](DETECTORS.md), this file.
- `docker-compose.local.yml`, because the README quickstart could not work: the main
  stack uses `expose` rather than `ports`, so `curl localhost:8100` failed, and bringing
  up Caddy on a laptop starts an ACME attempt for a placeholder hostname.
- README labels the project a research prototype rather than a production control,
  describes what the instrument measures rather than what one deployment saw, and
  documents the agent-bait surface (`/.well-known/ai-plugin.json`, `/openapi.json`,
  `/api/v1/*`), which existed only in code.
- Removed extraction artifacts referencing a private monorepo (`../Caddyfile`,
  `../deploy/`, `CONTENT_IDEAS.md`, `(internal reference removed)`, a `static/` directory
  that does not exist).
- Removed dead code: the unused `log()` wrapper, the unused `aws` formatter, the unused
  `python-multipart` dependency, and four function-local `parse_qs` imports.
- `docker-compose.yml` referenced `BODY_HARD_LIMIT`, which does not exist.
- Test suite runs in one process on 3.12 and 3.14; `asyncio.get_event_loop()` raised on
  3.14.
