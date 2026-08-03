# http-bait — design spec

This is the design document the service was built from, lightly edited for public
release. It records what each piece is for and which constraints are load-bearing, so a
change doesn't quietly break a guarantee. For what it is and how to run it, see
README.md.

## 1. Why this exists

Most honeypot writeups measure *discovery* — who connected. This one is built to measure
**exploitation**: who actually uses what they find. It targets the largest population on
the internet that will do so unprompted, **mass scanners** hunting leaked secrets, known
CVEs, and exposed admin surfaces. They reach any new public IP within hours.

Every "secret" it serves is a unique, attributable honeytoken, so a later request carrying
one is proof that a specific scrape led to a specific reuse — not an inference from
correlated timing.

## 2. Non-goals / ethics guardrails (read first, hard constraints)

- **Nothing here is real, with ONE deliberate, bounded exception.** No real secrets, no
  real credentials, no real admin panel. Every "leaked" value is a honeytoken:
  tracking-only, attributable, harmless if used. **Exception (added 2026-07, opt-in,
  `HB_CANARYTOKENS_LIVE=1`, off by default):** the `aws_pair` kind can be backed by a
  REAL, functioning AWS key pair minted live via canarytokens.org's public API, so a
  genuine third-party use is independently detectable through their own alerting — this
  is the one honeytoken kind that is not synthetic when the flag is set. It carries no
  attached IAM permissions (canarytokens.org's own AWS canary keys exist solely to
  trigger detection, not to grant access) and its exposure is explicitly bounded: capped
  by both elapsed time (`HB_CANARYTOKENS_REFRESH_SECS`) and serving count
  (`HB_CANARYTOKENS_MAX_SERVINGS`), with a floor on real mint-attempt frequency
  (`HB_CANARYTOKENS_RETRY_COOLDOWN_SECS`) so it can never be forced into a sustained
  real-call-volume vector against canarytokens.org itself. See `app/main.py`'s "Live
  canarytokens.org integration" section for the full design and reasoning.
- **Nothing executes.** Any route that looks like it runs a command, query, or fetch
  (if added later) must log-only and return a synthetic result — never actually execute,
  query, or make an outbound request on the caller's behalf (no SSRF amplification).
  The one exception above (live AWS key minting) is a request the honeypot itself makes
  to a third party as part of the bait's OWN construction, not a route acting as a proxy
  or amplifier on a caller's behalf — the caller never controls what gets requested.
- **Not a DoS amplifier.** Rate-limit per IP, cap request/response body size (64KB), no reflection/amplification behavior. The live-AWS-key
  exception above required its own explicit rate floor to keep holding this guarantee —
  see that section.
- **Don't entrap.** The service offers plausible-looking exposed files/endpoints and
  observes; it never solicits illegal action or walks a visitor toward one.
- **Responsible disclosure.** If a *named* scanner/tool/vendor is caught doing something
  disclosure-worthy (e.g. actively exploiting a served "credential"), coordinate
  disclosure before publishing specifics.
- **Isolation.** Runs in its own container, own restricted filesystem, own subdomain.
  Must not share a network namespace, volume, or secret with any real asset.

## 3. Architecture

Standalone, so it can be deployed independently (own droplet, or a new isolated compose
service on a host you already run — deployer's call).

```
                 internet
                    │ HTTP/HTTPS (mass scanners)
        ┌───────────▼─────────────┐
        │ Caddy (real TLS)        │  a boring, unremarkable hostname — see below
        │   └─ http-bait app      │
        │      (FastAPI/Starlette)│
        └─────────────────────────┘
                    │
              http_events.jsonl  (pulled and analyzed offline)
```

- Python + FastAPI/Starlette. `app/main.py` holds the JsonlWriter and the telemetry
  middleware; every route is logged by the middleware, not by the handlers.
- Caddy (`caddy/Dockerfile`) builds with the JA4/JA4H fingerprinting module, so each
  visitor gets a TLS-stack fingerprint alongside the request record.
- **Give it a hostname with no history and no association with anything else you run.**
  A name that resolves to your other work mixes populations and makes the traffic
  uninterpretable — and tells anyone who looks who is running the honeypot.
- Own Docker container: read-only rootfs, `tmpfs: ["/tmp"]`, `cap_drop: ["ALL"]`,
  `security_opt: ["no-new-privileges:true"]`.

## 4. Route table — HTTP-layer bait

All routes: log full request (method, path, query, headers in received order, body up
to cap, source IP/XFF, JA4/JA4H via Caddy headers, TLS SNI/version/cipher, timestamp),
then return a plausible synthetic body. Every "secret" value is unique per (route,
visitor-session) and is a honeytoken — see §5.

### 4.1 Secret-file lures
| Path | Content-Type | Body |
|---|---|---|
| `/.env` | text/plain | `DB_PASSWORD=`, `AWS_ACCESS_KEY_ID=`, `STRIPE_SECRET_KEY=`, `JWT_SECRET=` — each a distinct honeytoken type (see §5) |
| `/.git/config` | text/plain | synthetic git config with a `url =` embedding a credentialed-looking clone URL (canary) |
| `/.git/HEAD` | text/plain | `ref: refs/heads/main` (paired with `/.git/config` — scanners that check `.git/HEAD` before `.git/config` are doing structured `.git` dumping; log the pair) |
| `/config.json` | application/json | `{"db": {...}, "api_keys": {...}}` with honeytokens |
| `/backup.sql` | application/sql | a few synthetic `INSERT INTO users/customers` lines, one row with a honeytoken-shaped API key column |
| `/.aws/credentials` | text/plain | INI-style `[default]` block, canary AWS key pair |
| `/wp-config.php` | text/plain (served as if static) | PHP source text with `DB_PASSWORD` honeytoken (WordPress-specific scanners are extremely common) |
| `/docker-compose.yml` | text/plain | synthetic compose file, one service env var is a honeytoken |
| `/id_rsa`, `/.ssh/id_rsa` | text/plain | a syntactically valid but non-functional PEM-shaped private-key-looking blob (clearly non-cryptographic filler — never a real key format that could be mistaken for reusable, but visually matches what scanners grep for) |

### 4.2 Admin / auth lures
| Path | Behavior |
|---|---|
| `/admin`, `/admin/login` | Serves a generic login form. Submitted credential **presence and lengths** are logged, but unknown values are discarded; it always returns "invalid credentials." This preserves stuffing-attempt signal without retaining potentially stolen credentials. |
| `/api/keys` | Requires no auth (misconfiguration lure); returns a JSON list of honeytoken API keys with plausible names (`prod-payments`, `internal-ci`, `partner-readonly`) |
| `/debug`, `/debug/vars`, `/actuator/env`, `/actuator/health` | Returns a Spring-Boot-Actuator-shaped or Go-`expvar`-shaped JSON blob with honeytoken env vars — these paths are hit constantly by generic CVE scanners regardless of actual stack |
| `/.well-known/security.txt` | Real-looking security contact (a canary email/alias — log any mail received) |
| `/graphql` (POST) | Accepts any GraphQL query, returns a generic introspection-disabled error, but logs the full query — many scanners probe for open GraphQL introspection |

### 4.3 CVE / version signaling
- Set `Server:` and/or a framework-identifying header (e.g. `X-Powered-By`) to a string
  matching a **known-vulnerable version** of something (rotate periodically across
  variants: an old WordPress, an old Struts, an old Spring Boot, an old Confluence — pick
  2–3 to run in parallel on different paths/subdomains so you can compare which draws
  the most CVE-specific follow-up).
- Log any request that matches a known CVE exploit pattern for the *advertised* version
  (path/param signatures are public; a short static list is enough — don't need a full
  CVE database) as `event: cve_pattern_match` with the matched CVE id.
- Advertise via a plausible root page too — a generic "control panel" login screen whose
  HTML/meta reveals the same fake version banner, since some scanners fingerprint via
  page content rather than headers.

### 4.4 Leaked-key-in-page
- Landing page (`/`) HTML/inline JS embeds one honeytoken (e.g. a fake analytics or
  maps API key as a JS variable) in a plausible location. Anything that later **uses**
  that key (hits the real vendor's API, or a canary endpoint standing in for one) proves
  an actor scraped the page content and acted on it — a different capture than a scanner
  hitting `/.env` directly.

### 4.5 Everything else
- `robots.txt` and `sitemap.xml` **list** the bait paths (don't hide them — the goal is
  scanners and crawlers finding them, unlike a real robots.txt which would disallow).
- Catch-all 404 handler still logs the full request (path scanning without a hit is
  itself signal — which paths are probed that aren't in the bait list tells you what
  scanners expect to find).

## 5. Honeytoken scheme

Mint a unique, attributable fake secret per (route, session) — same tracking-only
principle throughout:

```python
def honeytoken(kind: str, session: str) -> str:
    """Mint a tracking-only fake secret of the given kind; log issuance for attribution."""
    tok = uuid.uuid4().hex[:16]
    log({"event": "honeytoken_issued", "kind": kind, "token": tok, "session": session})
    return FORMATTERS[kind](tok)  # e.g. AKIA-shaped, sk_live-shaped, ghp_-shaped, etc.
```

Token **kinds** to implement (format each so it superficially passes a scanner's regex
for that service, per public honeytoken conventions — canarytokens.org's formats are a
good reference):
- AWS access key (`AKIA...` + secret)
- GCP service-account-shaped JSON key
- GitHub PAT (`ghp_...`)
- Slack webhook / bot token (`xox[bp]-...`)
- Stripe secret key (`sk_live_...`)
- Generic DB connection string (`postgres://user:pass@host/db`)
- Generic JWT (`eyJ...` — decodes to plausible-but-fake claims)
- OpenAI-shaped API key (`sk-...`)

**Trigger catcher:** for token kinds where "use" is externally observable (a URL a
scanner might visit, e.g. embed a canary URL alongside/instead of a raw key where
plausible — use the `/x/{token}` catcher., or stand up an
equivalent `/x/{token}` on this service), log `event: honeytoken_triggered`. For key
formats that can't carry a callback (a bare AWS key string), the "trigger" signal has to
come from a partner data source (e.g. AWS's own leaked-key detection contacting the
account — out of scope to build, note as a known limitation) or from watching whether
the *same* key reappears in a later request (e.g. an `Authorization` header on some
other route) as circumstantial reuse evidence.

## 6. Logging schema (`http_events.jsonl`)

One JSON object per request, newline-delimited, same fsync-on-write discipline as
the writer in `app/main.py`:

```jsonc
{
  "ts": "2026-07-10T12:00:00.000000+00:00",
  "event": "request",              // or honeytoken_issued / honeytoken_triggered / cve_pattern_match
  "ip": "1.2.3.4",
  "xff": "...",
  "ua": "...",
  "ja4": "...", "ja4h": "...",
  "tls": {"version": "...", "cipher": "...", "sni": "...", "alpn": "..."},
  "method": "GET", "path": "/.env", "query": "",
  "header_order": ["host", "user-agent", "..."],
  "headers": {"...": "..."},        // full received headers, sanitized per existing precedent
  "body_len": 0, "body_excerpt": "",  // capped, e.g. 4KB
  "status_served": 200,
  "route_kind": "secret-file|admin|debug|graphql|cve-signal|catch-all",
  "creds_submitted": {             // fingerprinted panel POSTs only
    "user_present": true, "user_len": 5,
    "pass_present": true, "pass_len": 8,
    "source": "body"
  }
}
```

Plus derived events: `honeytoken_issued {kind, token, route, session}`,
`honeytoken_triggered {token, kind, ip, ts}`, `honeytoken_reuse_observed`,
`cve_pattern_match {cve_id, path}`, `rsc_action_probe`,
`tool_invocation_attempt`, and `api_tool_call_attempt`. Every request-scoped
event carries the same `request_id` for exact joins under concurrency.

## 7. Deployment

New standalone directory (this one), independently deployable:
```
http-bait/
  app/
    main.py            # FastAPI app: routes above, JsonlWriter, honeytoken minting
    formatters.py       # per-kind fake-secret formatters + served-length declarations
    signatures.py       # detection tables, shared with analyze.py
  Dockerfile
  Caddyfile             # standalone site block for the new subdomain
  docker-compose.yml    # caddy + app
  data/logs/            # http_events.jsonl lands here; pull via scp like mcp_data/
```
- Keep the hardening flags (`read_only`, `tmpfs: ["/tmp"]`,
  `cap_drop: ["ALL"]`, `no-new-privileges`).
- A hostname with no history. Do not reuse a domain that resolves to, or has
  ever resolved to, anything else you operate.
- Can run on the existing droplet as an additional isolated container/site-block, or on
  a fresh droplet — deployer's choice; nothing here assumes either.
- `pull-telemetry.sh <host_ip>` copies `data/logs/` back for offline analysis.

## 8. Analysis

`analyze.py` reports:
- Per-IP/session request sequence, path list, cadence (scanner-burst vs. slow).
- Which secret-file paths get hit, in what order (does the scanner check `.git/HEAD`
  before `.git/config`? `.env` before `wp-config.php`? — sequence reveals scanner
  toolkit/template).
- `cve_pattern_match` counts by advertised-version variant (which fake version drew the
  most targeted follow-up).
- `honeytoken_triggered` counts by kind (which secret type gets used/tested — the
  clearest "what do attackers actually want" signal).
- Credential-stuffing attempts on `/admin/login` (volume + credential patterns).
- IP/ASN classification (`--rdns` and `--enrich`, both opt-in; see README.md).

## 9. Success metrics (what "working" looks like)

- **Time-to-first-hit** on each bait path (expect hours, not weeks — this is the point).
- **Exploit-attempt rate**: hits on secret-file/admin/debug paths per day.
- **`honeytoken_triggered` > 0** within the first collection window (would be the
  service's first real "proof of use" event).
- **CVE-pattern-match rate by advertised version** — which fake vulnerability draws the
  most targeted (non-generic) follow-up.
