# Findings

Window: **2026-07-10T04:27Z → 2026-07-22T20:14Z** (12.66 days), single host, one public
hostname with no prior history. Self-test traffic excluded from every figure below.

| | |
|---|---|
| Requests | 3,820 |
| Distinct IPs | 159 |
| Honeytokens issued | 810 |
| CVE exploit attempts (retroactive scan) | 41 hits / 5 CVEs / 24 IPs |
| CVE exploit attempts (live detector) | 17 hits / 3 CVEs |
| Confirmed honeytoken replays | 1 |
| Credential-stuffing attempts on `/admin/login` | 0 |

## Read these caveats before quoting any number

**The two CVE counts differ because the detectors changed under the data.** The live count
(17) is what the deployed signature set flagged in real time. The retroactive count (41)
is a re-scan of retained request data with the *current* signature set. Two signatures
shipped after traffic they match had already arrived — React2Shell on 2026-07-19 and the
header-haystack fix for Log4Shell on 2026-07-11. **The retroactive figure is the better
ground truth.** Both are lower bounds: request bodies are capped at 64KB and only a 4KB
excerpt is retained, so a payload past the cap is invisible to both.

**"First seen" is when the traffic arrived, not when detection started.** React2Shell
traffic first appears 2026-07-10; its detector shipped nine days later. Do not read the
detector date as the arrival date.

**One honeypot, one hostname, thirteen days.** Everything here is a single observation of
a single bait surface. Scanner populations vary by hosting provider, IP reputation,
hostname age, and what the root page advertises. Treat these as existence proofs of
behaviour, not as base rates.

**Third-party IPs are truncated to /24 throughout.** Addresses get reassigned, and an
address attributed to an exploit attempt today may belong to an unrelated party next
month.

## What arrived

Traffic began almost immediately. The first outside request landed within seconds of the
hostname's TLS certificate being issued — almost certainly certificate-transparency-log
scrapers rather than genuine discovery, so treat sub-minute "time to first hit" as an
artifact of how the host was stood up, not a finding.

**Route distribution** (3,820 requests): catch-all 2,719 · rate-limited 566 ·
CVE-signal 230 · secret-file 184 · admin 49 · debug 47 · GraphQL 25.

**Status codes**: 404 × 2,668 · 200 × 527 · 429 × 566 · 413 × 34 · 400 × 25.

## Confirmed exploitation attempts

Retroactive scan, by CVE, with distinct source IPs:

| CVE | Hits | IPs | First seen |
|---|---|---|---|
| CVE-2025-55182 (React2Shell) | 35 | 18 | 2026-07-10 |
| CVE-2017-9841 (PHPUnit `eval-stdin.php`) | 3 | 3 | 2026-07-13 |
| CVE-2022-22965 (Spring4Shell) | 1 | 1 | 2026-07-11 |
| CVE-2021-44228 (Log4Shell) | 1 | 1 | 2026-07-11 |
| CVE-2024-27956 (WP-Automatic SQLi) | 1 | 1 | 2026-07-11 |

Two were unambiguous exploitation rather than fingerprinting:

- **Log4Shell**: an obfuscated JNDI/LDAP callback string sprayed across arbitrary request
  headers. It was logged but initially *not* flagged, because the signature matcher only
  searched path, query, and body — scanners put JNDI payloads in any header they can
  reach. Fixed 2026-07-11 by adding headers to the haystack.
- **Spring4Shell**: a POST attempting to write a JSP webshell with a `Runtime.exec()`
  payload.

Also observed: path traversal, LFI, SQLi, and Elementor RCE probes.

## The honeytoken replay

One confirmed reuse in the window. An IP requested `/.git/config`, received a synthetic
GitHub personal access token, and roughly two minutes later replayed that exact token as
an `Authorization: Bearer` header against a batch of API-secret probe paths. The scrape
and the reuse are tied together by the token's uniqueness, not by timing.

No second replay has been observed.

**A limitation that bears directly on that null,** found in review and fixed 2026-07-23:
the reuse detector matched only the full 16-character token id, but two honeytoken kinds
(`db_password` and the password inside `db_connection_string`) serve a 12-character prefix
instead. A replayed database password could therefore never have fired the detector. That
covers 110 of 810 issuances (~14%) across four routes. The "no second replay" result above
was measured with a detector blind to that share of its own bait, so read it as *no
replay of a detectable kind*. The current code matches both forms.

## Still zero

- **No credential stuffing.** `/admin/login`, `/wp-login.php`, phpMyAdmin, and Adminer
  lures were served and never subjected to password spraying.
- **No canary-URL fetches.** Canary URLs embedded in served secrets were never requested.

The absence of credential stuffing is the more interesting of the two: the panels were
reachable and the scanners clearly parsed the pages around them.

## Reproducing

`analyze.py` produces the per-route, per-status, per-IP, and CVE breakdowns above from a
raw `http_events.jsonl`:

```bash
python analyze.py data/logs/http_events.jsonl
```

Raw logs are not published — they contain third-party IP addresses. The counts here are
what the analyzer prints.
