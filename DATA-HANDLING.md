# Data handling

What this service records about the people and machines that reach it, what it
deliberately does not record, and what you inherit as an operator if you run it.

This document exists because the previous version of that promise lived in one
sentence in the README and was not true. "Visitor credentials are never
retained" described four route handlers rather than the service: any credential
POSTed to a path without its own handler fell through to the catch-all and was
written to the log verbatim. That is fixed (see **Credentials** below), and the
promise is now written down where its limits can be checked.

## What is recorded for every request

Per request, in `http_events.jsonl`:

| Field | Notes |
|---|---|
| `ts`, `window` | UTC timestamp and collection-window label |
| `ip`, `xff` | Client address as seen by the proxy, capped at 1,000 chars |
| `ua` | User-Agent, capped at 1,000 chars |
| `ja4`, `ja4h`, `tls.*` | Fingerprints from Caddy, capped at 256 chars each |
| `method`, `path`, `query` | Capped at 16 / 2,000 / 4,000 chars |
| `header_order`, `header_count` | First 100 header names, plus the true count |
| `headers` | Values capped at 4,000 chars each, 32,000 total; sensitive ones redacted |
| `status_served`, `route_kind` | What was served and which lure served it |
| `body_len`, `body_excerpt` | First 4KB of the body, redacted if credential-shaped |

The assembled record is capped at 128KB. Anything larger is replaced by an
identifying subset plus `oversize_record: true`, so the event is never silently
dropped and never unbounded.

## What is deliberately not retained

**Credentials submitted to any lure.** Login panels exist here to measure
credential stuffing, and credentials sprayed at a honeypot are routinely real
credentials stolen from a third party who has no connection to any of this.
Recording them would make this service a second breach of the same people.

Both the registered panel handlers and a generic check in the middleware reduce
a credential submission to its shape:

```json
"creds_submitted": {"user_present": true, "user_len": 17, "pass_present": true,
                    "pass_len": 12, "source": "body-inferred"}
"body_excerpt": "<redacted:credential-submission:len=52>"
```

The generic check runs for every request no handler already marked, so a new
lure cannot reintroduce the gap by forgetting to opt in. Covered by
`test_catch_all_post_credentials_are_redacted`.

**Values of credential-bearing headers.** `authorization`, `cookie`,
`x-api-key`, `x-amz-security-token` and the rest of `SENSITIVE_HEADERS` are
stored as a scheme label, a length, and an HMAC:

```
"x-api-key": "<redacted:key:len=21:hmac=9f2c1d0a4b83>"
```

The HMAC key is 32 random bytes generated at process start and never written
anywhere. Repeat values stay correlatable within a run; the values themselves
do not survive it, and the digests are not attackable offline. A bare SHA-256
would not be good enough: half of what arrives in these headers is Basic auth
and low-entropy API keys, which a dictionary attack recovers from the published
log format alone. The cost of the ephemeral key is that correlation does not
survive a restart, which is the right trade against a stored key turning every
historical log into a crackable corpus if it ever leaks.

**GraphQL argument values.** Credential-shaped literals in a query are replaced
before logging, and a body that does not parse as JSON is recorded as a shape
rather than as text.

**Anything past the caps.** Request bodies stop being read at 64KB. Only the
first 4KB is retained. A signature match on bytes past the cap is impossible,
which is one reason every detection count here is a lower bound.

## What the analyzer discloses

`analyze.py` prints third-party addresses truncated to /24 (IPv6 to /48) by
default. `--full-ips` opts out. Two flags disclose your visitor list to a third
party and are off by default:

- `--enrich` sends observed addresses to ip-api.com.
- `--rdns` resolves each address through whatever resolver chain you are behind.

Raw logs are not published in this repository and should not be. They contain
third-party addresses, and an address attributed to an exploit attempt today may
belong to an unrelated party next month.

## What you inherit as an operator

Running this points a deliberately attackable surface at the internet under your
name, and creates a file of third-party network activity on your disk.

- **You become the custodian of that file.** Decide a retention period before you
  deploy, not after something interesting shows up in it.
- **Log rotation is not deletion.** `HB_LOG_KEEP_ROTATED` bounds how many rotated
  files are kept. Setting it to `0` keeps everything, which fills the disk and
  stops collection.
- **The catcher can receive third-party data.** `/x/{token}` accepts GET and POST.
  A POST body to it is not currently parsed or stored beyond the standard
  request record, but it is a path by which someone else's data can arrive.
- **If you enable live canary tokens**, canarytokens.org receives a mint request
  from you and holds the resulting alert data. That is a third party in your
  data path; read their terms before turning it on.
- **Disclosure.** If you identify a named vendor or product doing something
  disclosure-worthy, tell them before you publish specifics.

## Reporting

If you believe this service retained something about you that it should not
have, or you want data associated with an address removed, see
[SECURITY.md](SECURITY.md).
