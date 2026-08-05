# Detectors

Generated from `app/signatures.py` by `gen_detectors.py`. Do not edit by hand.

A detection count means nothing without knowing when the detector existed. Two
signatures in this table shipped *after* traffic they match had already
arrived, so their live counts and their rescan counts differ by construction.
`analyze.py --rescan` re-applies the current set to retained records and prints
both, with the `since` value beside each row.

`since` values:

- a date: the day that signature's **current form** shipped
- `initial`: present when collection began
- `unknown`: the signature is known to have changed and no date is recoverable
  from the repository's own history (`git log -S <id> -- app/`). If this ever
  occurs, say concretely why. Do not guess one.

## CVE and exploit signatures

`kind` separates payload-bearing attempts from path probes. Reaching
/vendor/phpunit/.../eval-stdin.php with no body is a scanner checking
whether PHPUnit is installed; the exploit needs PHP in the request body.
Report the two counts separately.

| id | kind | scope | since |
|---|---|---|---|
| `CVE-2025-55182` | **exploit** | raw body and its percent-decoded form | 2026-07-19 |
| `CVE-2022-22965` | **exploit** | path, query, body and Content-Type | initial |
| `CVE-2017-5638` | **exploit** | Content-Type header | initial |
| `CVE-2018-11776` | **exploit** | path + query | 2026-08-04 |
| `CVE-2016-1000027` | **exploit** | path, query, body and Content-Type | initial |
| `WP-XMLRPC-PINGBACK` | **probe** | path, query, body and Content-Type | initial |
| `CVE-2020-25213` | **probe** | path, query, body and Content-Type | 2026-08-03 |
| `CVE-2021-44228` | **exploit** | every occurrence of every header | 2026-07-11 |
| `CVE-2017-9841` | **probe** | path + query | 2026-08-04 |
| `CVE-2024-27956` | **probe** | path + query | 2026-08-03 |

## Tool-invocation signatures

These parse an already-bounded request. Nothing is evaluated, imported,
executed, or fetched.

| tool |
|---|
| `node:child_process.execSync` |
| `node:child_process.exec` |
| `java:Runtime.exec` |
| `java:ProcessBuilder` |

## Honeytoken geometry

How many leading characters of the token id each kind serves as one
contiguous run. The reuse detector scans at the minimum, so a kind that
serves a shorter run widens the scan automatically. Current minimum: **12**.

| kind | served run |
|---|---|
| `aws_pair` | 16 |
| `db_connection_string` | 12  <- sets the scan width |
| `db_password` | 12  <- sets the scan width |
| `gcp` | 16 |
| `github_pat` | 16 |
| `google_api_key` | 16 |
| `jwt` | 16 |
| `openai_key` | 16 |
| `slack_bot_token` | 16 |
| `slack_webhook` | 16 |
| `ssh_private_key` | 16 |
| `stripe_secret` | 16 |

### Why this table exists

The reuse detector originally matched only the full 16-character id. Two kinds
serve 12. A replayed database password therefore could not fire the detector at
all, across roughly 14% of everything ever issued, and the resulting "no second
replay" reads as a finding rather than as a blind spot. Nothing in the code
enforced the assumption, so nothing caught it.

`app/test_regressions.py::test_served_token_len_declarations_are_accurate`
now checks every number above against what the formatter actually emits.

