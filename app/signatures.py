"""
Detection tables shared by the live service (app/main.py) and the offline
analyzer (analyze.py).

Why this file exists: these tables used to be duplicated. app/main.py had four
tool-invocation signatures and analyze.py had three; app/main.py's ROUTE_VARIANT
gained /app, /site, /legacy and analyze.py's copy did not. Both copies drifted
silently, and the second copy is the one that produced the published numbers, so
the drift was invisible until someone diffed them by hand. AGENTS.md warns in
prose that a detector which never fires looks exactly like an attack that never
happened; a duplicated table is the same failure with an extra step.

Stdlib only, on purpose. analyze.py must stay runnable against a raw log on a
machine with no FastAPI, no httpx, and no virtualenv.
"""
from __future__ import annotations

import re
from datetime import datetime

# --------------------------------------------------------------------------- #
# Honeytoken id geometry.
#
# honeytoken() mints uuid4().hex[:TOKEN_ID_LEN]. Some formatters serve only a
# PREFIX of that id rather than the whole thing, so a detector matching the full
# id can never fire for those kinds. See formatters.SERVED_TOKEN_LEN, which is
# where each kind declares what it actually serves, and the invariant test in
# app/test_regressions.py that keeps the declaration honest.
# --------------------------------------------------------------------------- #
TOKEN_ID_LEN = 16

# --------------------------------------------------------------------------- #
# CVE version-signaling variants (SPEC §4.3). Assigned by ROUTE, not globally,
# so different bait surfaces advertise different vulnerable stacks and draw
# comparably-classified follow-up.
# --------------------------------------------------------------------------- #
VARIANTS = {
    "wordpress": {"server": "Apache/2.4.29 (Ubuntu)", "x_powered_by": "PHP/7.2.24",
                  "meta": '<meta name="generator" content="WordPress 5.7.2" />'},
    "struts": {"server": "Apache-Coyote/1.1", "x_powered_by": None,
               "meta": '<!-- Apache Struts 2.3.31 -->'},
    "spring": {"server": None, "x_powered_by": None,
               "meta": '<!-- Spring Boot 2.1.6.RELEASE -->'},
}

ROUTE_VARIANT = {
    "/wp-config.php": "wordpress",
    "/wp-login.php": "wordpress",
    # phpMyAdmin is bundled on the same LAMP stack as the WordPress bait, so it
    # shares that variant's Apache/PHP banner rather than getting its own.
    "/phpmyadmin/": "wordpress", "/phpmyadmin/index.php": "wordpress",
    "/admin": "struts", "/admin/login": "struts",
    "/actuator/env": "spring", "/actuator/health": "spring",
    # Permanently-pinned parallel variants (2026-07 addition), see the
    # "Landing page(s)" section of app/main.py for why these run alongside
    # "/"'s existing rotation instead of replacing it.
    "/app": "wordpress", "/site": "struts", "/legacy": "spring",
    # "/" rotates across all three (SPEC §4.3 "rotate periodically"), see
    # root_variant_at() below.
    # "/debug", "/debug/vars" carry NO banner on purpose, their body is
    # Go-expvar-shaped (cmdline/memstats), and real Go net/http servers don't
    # set a Server header by default, so silence here is itself consistent
    # signal rather than a mismatch with a Spring/WordPress/Struts banner.
}
ROOT_VARIANT_CYCLE = ["wordpress", "struts", "spring"]
ROOT_ROTATION_PERIOD_DAYS = 14


def root_variant_at(ts: datetime) -> str:
    """Which variant "/" advertised at a given moment."""
    epoch_days = int(ts.timestamp() // 86400)
    idx = (epoch_days // ROOT_ROTATION_PERIOD_DAYS) % len(ROOT_VARIANT_CYCLE)
    return ROOT_VARIANT_CYCLE[idx]


# --------------------------------------------------------------------------- #
# Short static list of public path/param/header signatures for known exploits
# against the ADVERTISED versions above (SPEC §4.3). Not a full CVE database,
# just enough to flag targeted (non-generic) follow-up.
#
# Every entry carries `since`: the UTC date its CURRENT form shipped, or
# "initial" for signatures present at the first release. This is code
# provenance, not an observation about anyone's traffic.
#
# It matters because a live detector count is only comparable across a window in
# which the signature existed for the whole window. If a signature changed
# during your collection window, your live and rescan counts disagree by
# construction. DETECTORS.md is generated from this field, and
# `analyze.py --rescan` prints it beside every count so a reader can see which
# rows could only have come from a rescan.
#
# Dates come from the repository's own history (`git log -S <cve> -- app/`):
# the signature table shipped 2026-08-03 (687954c) and the kind field that
# completes each entry's current form landed 2026-08-04 (184ef59). An earlier
# revision of this comment claimed the dates were unrecoverable because the
# repository was "a single squashed commit"; that was false — the history was
# never squashed — and a provenance artifact whose premise fails one `git log`
# is worse than no date at all. If a date is ever genuinely unrecoverable, mark
# it "unknown" and say why, concretely. Do not guess.
#
# Scopes: "path" (path + "?" + query), "content-type", "headers" (every
# occurrence of every header), "body" (raw + percent-decoded), "any" (union of
# path, query, body, content-type).
#
# Each entry also declares a KIND:
#
#   "exploit", the pattern matches attacker-supplied payload. A hit is an
#               attempt to exploit, not merely to look.
#   "probe", the pattern matches a path or a generic marker and nothing more.
#               Reaching the endpoint is reconnaissance. CVE-2017-9841 needs PHP
#               in the request body to do anything, and CVE-2024-27956 needs its
#               SQL payload; a bare GET to either path is a scanner checking
#               whether the software is installed.
#
# The distinction exists because collapsing the two inflates the number everyone
# quotes. A report saying "N exploit attempts" where N counts path probes is
# describing scanner inventory as attack. analyze.py tallies them separately and
# records `body_present` on probe hits, so a probe that did arrive with a body
# can be promoted deliberately rather than by accident.
# --------------------------------------------------------------------------- #
CVE_SIGNATURES = [
    # React Server Components unsafe deserialization ("React2Shell"). The
    # payloads arrive as multipart Server Action POSTs carrying a `Next-Action`
    # header and this promise/prototype chain in the body.
    # React tracks the upstream flaw as CVE-2025-55182; affected frameworks
    # such as Next.js received their own downstream advisories.
    ("CVE-2025-55182", re.compile(r"\$1:__proto__:then", re.I), "body", "2026-07-19", "exploit"),
    # Spring4Shell / class-loader manipulation.
    ("CVE-2022-22965", re.compile(r"class\.module\.classLoader", re.I), "any", "initial", "exploit"),
    # Struts2 OGNL RCE via Content-Type (S2-045/S2-046 family).
    ("CVE-2017-5638", re.compile(r"%\{.*(ognl|runtime|processbuilder)", re.I), "content-type", "initial", "exploit"),
    # S2-057 payloads put the action prefix BEFORE the OGNL expression
    # (`redirect:${233*233}`, `redirectAction:${...}`), and the RCE variant
    # spells it `ognl.OgnlContext` with a dot, not `ognl:`. The previous
    # pattern required `${` first and a trailing colon, so it matched none of
    # the shapes actually seen in the wild, a detector that could never fire.
    ("CVE-2018-11776", re.compile(r"(redirect(action)?:|@?ognl[.:])", re.I), "path", "2026-08-04", "exploit"),
    # Spring Framework HttpInvoker deserialization. The advertised Spring Boot
    # banner is what draws these; the probe itself targets the remoting
    # endpoint rather than the actuator write-env chain. (The comment on this
    # entry previously described the actuator write-env chain, which is a
    # different flaw; the pattern was always the HttpInvoker one, so only the
    # description was wrong.)
    ("CVE-2016-1000027", re.compile(r"org\.springframework\.remoting\.httpinvoker", re.I), "any", "initial", "exploit"),
    # WordPress xmlrpc pingback/multicall abuse. NOT a CVE: this is documented
    # protocol behaviour being abused, and it was previously mislabelled
    # CVE-2020-25213 (which is the wp-file-manager RCE, an unrelated flaw with
    # an unrelated payload). The pattern is unchanged, so historical counts
    # carry over; only the id it reports under is corrected.
    ("WP-XMLRPC-PINGBACK", re.compile(r"wp_ajax|multicall|pingback\.ping", re.I), "any", "initial", "probe"),
    # wp-file-manager unauthenticated upload/RCE (connector endpoint probe), # the flaw CVE-2020-25213 actually refers to.
    ("CVE-2020-25213", re.compile(r"wp-file-manager|filemanager/lib/php/connector", re.I), "any", "2026-08-03", "probe"),
    # Log4Shell: sprayed into ANY header (User-Agent, X-Api-Version, Referer, …)
    # by real-world scanners regardless of advertised stack, so it is not gated
    # to a variant banner the way the others are. Originally scoped to
    # path/query/body only, which missed the header-sprayed shape that is how
    # this actually arrives; rescoped to headers 2026-07-11.
    ("CVE-2021-44228", re.compile(r"\$\{jndi:", re.I), "headers", "2026-07-11", "exploit"),
    # PHPUnit eval-stdin.php RCE, the path alone is the exploit. A generic,
    # stack-agnostic probe like Log4Shell, commonly seen riding along in
    # round-robin scan bursts. The signature table entry shipped 2026-08-03 and
    # gained its kind classification 2026-08-04, so its current form dates from
    # the latter.
    ("CVE-2017-9841", re.compile(r"phpunit.*eval-stdin\.php", re.I), "path", "2026-08-04", "probe"),
    # WP-Automatic auth-bypass SQLi. The probe is a request to the plugin's CSV
    # handler; the injected SQL rides in the query string. Path-scoped for the
    # same reason as PHPUnit above: reaching this endpoint at all is the
    # attempt.
    ("CVE-2024-27956", re.compile(r"wp-automatic/inc/csv\.php", re.I), "path", "2026-08-03", "probe"),
]

# Log attempted command/tool invocations as their own derived signal. These
# patterns only PARSE the already-bounded request text; they never evaluate,
# import, shell out, fetch, or otherwise act on attacker input.
TOOL_INVOCATION_SIGNATURES = [
    ("node:child_process.execSync",
     re.compile(r"execSync\(\s*(['\"])(?P<command>.{1,200}?)\1", re.I | re.S)),
    ("node:child_process.exec",
     re.compile(r"(?<!Sync)exec\(\s*(['\"])(?P<command>.{1,200}?)\1", re.I | re.S)),
    ("java:Runtime.exec",
     re.compile(r"Runtime\.getRuntime\(\)\.exec\(\s*(['\"])(?P<command>.{1,200}?)\1", re.I | re.S)),
    ("java:ProcessBuilder",
     re.compile(r"ProcessBuilder\(\s*(['\"])(?P<command>.{1,200}?)\1", re.I | re.S)),
]

# Some observed payloads assign a command to a variable and later call
# `cp.exec(cmd, ...)`; that is still an invocation attempt even when the
# retained excerpt does not include the earlier assignment.
INDIRECT_COMMAND_RE = re.compile(r"\b(?:cp|child_process)\.exec\(\s*cmd\b", re.I)

# React Server Component prototype-chain payload, used both as a CVE signature
# above and as a standalone "was the payload actually retained" check.
RSC_PROTOTYPE_RE = re.compile(r"\$1:__proto__:then", re.I)

# Request headers whose values are treated as third-party secrets: redacted to
# a length and a salted-free digest rather than retained. `authorization` and
# `cookie` were the original set. The rest were added 2026-08-03 after review
# pointed out that this project's entire thesis is credential replay in
# headers, which makes x-api-key and x-amz-security-token exactly the wrong
# ones to keep in the clear.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "auth-token",
    "x-access-token",
    "access-token",
    "x-session-token",
    "x-amz-security-token",
    "x-goog-api-key",
    "x-functions-key",
}

# Body field names that indicate a credential submission. Used to redact
# credential-shaped POST bodies on routes that are NOT one of the registered
# panel handlers, see main.py's infer_credential_submission(). Matched
# case-insensitively against form field names and JSON keys.
CREDENTIAL_FIELD_NAMES = {
    "password", "passwd", "pwd", "pass", "pw",
    "auth[password]", "pma_password", "user_pass",
    "secret", "client_secret", "api_key", "apikey", "api-key",
    "token", "access_token", "refresh_token", "private_key",
}
IDENTITY_FIELD_NAMES = {
    "username", "user", "login", "log", "email", "userid", "user_id",
    "auth[username]", "pma_username", "user_login", "account",
}
