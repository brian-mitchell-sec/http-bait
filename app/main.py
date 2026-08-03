"""
http-bait — a plain-HTTP honeypot targeting mass internet scanners (leaked-secret
hunters, admin-panel brute-forcers, CVE scanners). See SPEC.md for the full
design and README.md for what it is and how to run it.

PASSIVE & SAFE: nothing here executes, queries, or makes an outbound request on
a caller's behalf. Every "secret" is a honeytoken (see formatters.py):
syntactically plausible, unique per issuance, never real, never reusable.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import re
import shutil
import sys
import threading
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse
from starlette.requests import ClientDisconnect

from formatters import FORMATTERS, CATCHER_EMBEDDED, MIN_SERVED_TOKEN_LEN
from signatures import (
    CREDENTIAL_FIELD_NAMES,
    CVE_SIGNATURES,
    IDENTITY_FIELD_NAMES,
    INDIRECT_COMMAND_RE,
    ROOT_ROTATION_PERIOD_DAYS,
    ROOT_VARIANT_CYCLE,
    ROUTE_VARIANT,
    SENSITIVE_HEADERS,
    TOKEN_ID_LEN,
    TOOL_INVOCATION_SIGNATURES,
    VARIANTS,
    root_variant_at,
)

LOG_DIR = Path(os.environ.get("HB_LOG_DIR", "/data/logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
EVENTS = LOG_DIR / "http_events.jsonl"
CANARY_BASE = os.environ.get("HB_CANARY_BASE", "https://http-bait.example")

BODY_CAP = 64_000          # hard cap on stored/read request body bytes (SPEC §2 non-goal: not a DoS amplifier)
BODY_EXCERPT_CAP = 4_000   # logged excerpt cap (SPEC §6)

# Per-field caps on attacker-controlled values that end up in a log record.
# Header VALUES were capped already; these were not, so a request could still
# write an unbounded User-Agent, path, or query into a JSONL line, and
# header_order grew one entry per header sent. RECORD_MAX_BYTES is the backstop
# on the assembled line for anything not individually bounded.
UA_CAP = 1_000
PATH_CAP = 2_000
QUERY_CAP = 4_000
XFF_CAP = 1_000
FINGERPRINT_CAP = 256
HEADER_ORDER_CAP = 100
RECORD_MAX_BYTES = 128 * 1024

# Labels every record with the collection window it belongs to. Publishing a
# writeup changes who is looking: post-publication traffic is readers, security
# tourists, and people testing the thing they just read about, and mixing it
# into the organic scanner population silently contaminates every rate in
# FINDINGS.md. Bump this before publishing so the two populations separate by
# a field rather than by a timestamp guess.
WINDOW_LABEL = os.environ.get("HB_WINDOW_LABEL", "unlabelled")


def _cap(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}<truncated:len={len(value)}>"
# Rotate http_events.jsonl once it crosses this size, keeping the newest
# HB_LOG_KEEP_ROTATED rotated files and deleting older ones. Rotation alone
# caps the LIVE file but not total disk: on a small droplet absorbing scanner
# traffic for weeks, undeleted rotations fill the disk, and a full disk makes
# write() fail silently while the service still answers 200s — i.e. the
# honeypot looks healthy and records nothing. Set HB_LOG_KEEP_ROTATED=0 to
# retain everything (only safe if something else prunes or ships the files).
LOG_MAX_BYTES = int(os.environ.get("HB_LOG_MAX_BYTES", 200 * 1024 * 1024))
LOG_KEEP_ROTATED = int(os.environ.get("HB_LOG_KEEP_ROTATED", 10))

@asynccontextmanager
async def lifespan(_app: FastAPI):
    restored = rebuild_issued_token_index()
    await alog({"event": "issued_token_index_rebuilt", "window": WINDOW_LABEL,
                "records_replayed": restored, "index_size": len(_issued_token_ids),
                "cap": ISSUED_TOKEN_MEMORY_CAP})
    yield


# Never expose FastAPI's generated schema: it reveals the real route table,
# Python-derived operation IDs, and the trigger catcher. A small deliberately
# synthetic OpenAPI lure is served below instead.
app = FastAPI(title="portal", docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=lifespan)


# --------------------------------------------------------------------------- #
# JSONL writer. write() never raises (best-effort telemetry, not the
# product) and rotates the live file at LOG_MAX_BYTES. awrite() is the path
# every async call site should use — it offloads the actual fsync'd write to
# a worker thread via asyncio.to_thread so a slow/full disk never blocks the
# event loop that's also serving every other in-flight request (found in
# review: the sync-only version blocked on fsync directly from async route
# handlers).
# --------------------------------------------------------------------------- #
class JsonlWriter:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        # Health signal. A write failure (most plausibly a full disk) is not
        # fatal to serving, so it must not raise — but it must be visible, or
        # the service goes on answering 200s while recording nothing. /healthz
        # reads these.
        self.last_write_error: str | None = None
        self.last_write_ok_at: float = 0.0
        self.write_failures: int = 0

    def _prune_rotated(self) -> None:
        # Must be called with self._lock held.
        if LOG_KEEP_ROTATED <= 0:
            return
        pattern = f"{self.path.stem}.*{self.path.suffix}"
        rotated = sorted(self.path.parent.glob(pattern))  # timestamped names sort chronologically
        for stale in rotated[:-LOG_KEEP_ROTATED]:
            try:
                stale.unlink()
            except OSError as e:
                print(f"http-bait: could not prune {stale.name}: {e}", file=sys.stderr)

    def _rotate_if_needed(self) -> None:
        # Must be called with self._lock held.
        try:
            if self.path.exists() and self.path.stat().st_size >= LOG_MAX_BYTES:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                self.path.rename(self.path.with_name(f"{self.path.stem}.{stamp}{self.path.suffix}"))
                self._prune_rotated()
        except OSError as e:
            print(f"http-bait: log rotation failed: {e}", file=sys.stderr)  # keeps growing; not fatal

    def write(self, record: dict) -> None:
        try:
            record.setdefault("ts", datetime.now(timezone.utc).isoformat())
            line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
            if len(line) > RECORD_MAX_BYTES:
                # Backstop for anything the per-field caps miss (a novel field,
                # a pathological header set that fits every individual limit).
                # Keep the fields an analyst needs to know the record existed
                # and drop the rest, rather than writing an unbounded line or
                # dropping the event entirely.
                keep = {k: record.get(k) for k in
                        ("ts", "event", "window", "ip", "method", "path",
                         "status_served", "route_kind", "request_id")
                        if record.get(k) is not None}
                keep["oversize_record"] = True
                keep["original_len"] = len(line)
                line = json.dumps(keep, separators=(",", ":"), ensure_ascii=False)
            with self._lock:
                self._rotate_if_needed()
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                self.last_write_ok_at = time.time()
                self.last_write_error = None
        except Exception as e:
            with self._lock:
                self.write_failures += 1
                self.last_write_error = f"{type(e).__name__}: {e}"[:200]
            print(f"http-bait: log write failed: {e}", file=sys.stderr)

    async def awrite(self, record: dict) -> None:
        record.setdefault("ts", datetime.now(timezone.utc).isoformat())
        try:
            await asyncio.to_thread(self.write, record)
        except Exception as e:
            try:
                await asyncio.to_thread(self.write, {"event": "log_error", "err": str(e)})
            except Exception:
                pass


writer = JsonlWriter(EVENTS)
_request_id_ctx: ContextVar[str] = ContextVar("http_bait_request_id", default="")


async def alog(rec: dict) -> None:
    request_id = _request_id_ctx.get()
    if request_id:
        rec.setdefault("request_id", request_id)
    await writer.awrite(rec)


# --------------------------------------------------------------------------- #
# Honeytoken minting (SPEC §5). Unique per issuance; issuance itself is logged
# so every value that ever appears "in the wild" is attributable.
# --------------------------------------------------------------------------- #
_issued_token_order: deque[str] = deque()
_issued_token_ids: set[str] = set()
_issued_token_prefixes: dict[str, str] = {}   # tok[:TOKEN_PREFIX_LEN] -> full id
ISSUED_TOKEN_MEMORY_CAP = 50_000


_issued_token_evictions = 0


def _remember_issued_token(tok: str) -> str | None:
    """Add a token to the reuse index. Returns the evicted id, if any."""
    global _issued_token_evictions
    evicted = None
    if len(_issued_token_order) >= ISSUED_TOKEN_MEMORY_CAP:
        evicted = _issued_token_order.popleft()
        _issued_token_ids.discard(evicted)
        _issued_token_prefixes.pop(evicted[:TOKEN_PREFIX_LEN], None)
        _issued_token_evictions += 1
    _issued_token_order.append(tok)
    _issued_token_prefixes[tok[:TOKEN_PREFIX_LEN]] = tok
    _issued_token_ids.add(tok)
    return evicted


def rebuild_issued_token_index() -> int:
    """Repopulate the reuse index from the event log at startup.

    The index was in-memory only, so every restart silently emptied it and
    every token issued before the restart became unmatchable. A replay after a
    deploy looked exactly like no replay, which is the same failure mode as the
    prefix bug: a detector that cannot fire, reported as an attack that did not
    happen.

    Rebuilding from honeytoken_issued events costs one pass over the retained
    log at boot and needs no new on-disk format. Rotated files are replayed
    oldest-first so the newest ISSUED_TOKEN_MEMORY_CAP ids win.
    """
    rotated = sorted(LOG_DIR.glob(f"{EVENTS.stem}.*{EVENTS.suffix}"))
    restored = 0
    for path in [*rotated, EVENTS]:
        if not path.exists():
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if '"honeytoken_issued"' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue  # a torn final line is normal on a live file
                    tok = rec.get("token")
                    if isinstance(tok, str) and tok:
                        _remember_issued_token(tok)
                        restored += 1
        except OSError as e:
            print(f"http-bait: could not replay {path.name}: {e}", file=sys.stderr)
    return restored


async def honeytoken(kind: str, session: str, route: str) -> str | dict:
    tok = uuid.uuid4().hex[:TOKEN_ID_LEN]
    evicted = _remember_issued_token(tok)
    if evicted is not None:
        # An eviction means a previously-issued token can no longer be matched,
        # so any later "no reuse observed" is bounded by this. Recording it
        # keeps that bound in the data instead of in someone's memory: an
        # attacker who scrapes, floods the index, then replays would otherwise
        # produce a clean null.
        await alog({"event": "issued_token_index_evicted", "token": evicted,
                    "total_evictions": _issued_token_evictions,
                    "cap": ISSUED_TOKEN_MEMORY_CAP})
    catcher_url = f"{CANARY_BASE}/x/{tok}" if kind in CATCHER_EMBEDDED else None
    await alog({"event": "honeytoken_issued", "kind": kind, "token": tok, "route": route, "session": session})
    return FORMATTERS[kind](tok, catcher_url)


# --------------------------------------------------------------------------- #
# Live canarytokens.org integration (opt-in). SPEC §5's known limitation for a
# bare (non-catcher-embedded) kind like aws_pair is that "use" is only provable
# via the real provider's own leaked-credential detection, which we can't see —
# our synthetic key can never actually be validated against a real AWS API.
# canarytokens.org mints REAL, functioning AWS access keys against their own
# monitored AWS account; a call made with one anywhere (not just against us)
# fires their alert to a webhook we control. Off by default
# (HB_CANARYTOKENS_LIVE=1 to enable) — this is the one place this service makes
# an outbound call to a third party, so it stays opt-in rather than live-default.
#
# Endpoint confirmed against thinkst/canarytokens' own frontend/app.py
# (POST /generate, token_type="aws_keys"): unauthenticated, no captcha (the
# turnstile check in that handler is gated to token_type=="credit_card_v2"
# only), memo required, webhook_url validated by the service POSTing to it
# once at creation time — which our own /x/{token} catcher already satisfies
# (any request there returns 200), so no new route is needed.
#
# Never blocks a request: minting happens at most once per refresh window, and
# every request path only ever reads an in-memory cache.
# --------------------------------------------------------------------------- #
CANARYTOKENS_LIVE = os.environ.get("HB_CANARYTOKENS_LIVE") == "1"
CANARYTOKENS_REFRESH_SECS = int(os.environ.get("HB_CANARYTOKENS_REFRESH_SECS", 24 * 3600))
CANARYTOKENS_MINT_TIMEOUT_SECS = 8.0
# Floor between mint ATTEMPTS, UNCONDITIONAL — applies whether the last
# attempt failed (outage backoff) OR succeeded (routine servings/refresh
# staleness). Without this, a canarytokens.org outage/slowdown means every
# single request hitting an aws_pair-serving route while the cache is empty
# re-attempts its own real outbound call; separately, an attacker who stays
# within this service's own per-IP rate limit but repeatedly exhausts the
# GLOBAL servings cap could otherwise force a real mint call roughly once
# per mint round-trip, sustained — a genuine (if non-amplifying) DoS vector
# against canarytokens.org itself, found in ethics/safety review, that SPEC
# §2's "not a DoS amplifier" guardrail didn't previously bound. Default
# bounds worst-case real mint volume to ~12/hour regardless of attack
# traffic, which is far above what serving ordinary scanner traffic needs, so
# normal operation never notices the floor. Safe to gate
# ROUTINE (non-failure) remints on this too, unlike an earlier version of
# this check: once _live_aws_servings_exhausted(), the accessor below now
# returns None (falls back to synthetic) rather than over-serving the real
# key while waiting the floor out, so the anonymity-set bound this pairs
# with (CANARYTOKENS_MAX_SERVINGS) still holds even while this floor blocks
# a routine re-mint.
CANARYTOKENS_RETRY_COOLDOWN_SECS = float(os.environ.get("HB_CANARYTOKENS_RETRY_COOLDOWN_SECS", 300))
# Cap the number of distinct servings of ONE live key, alongside the time cap
# (whichever is hit first forces a re-mint). Found in adversarial review: a
# flat 24h time cap alone means a real-world trigger could implicate ANY of
# the potentially dozens of visitors served that same pair during the day —
# capping by serving count too bounds that anonymity set directly, which is
# the variable that actually determines how many suspects there are, rather
# than relying solely on elapsed time.
CANARYTOKENS_MAX_SERVINGS = int(os.environ.get("HB_CANARYTOKENS_MAX_SERVINGS", 30))

_live_aws_lock = asyncio.Lock()
_live_aws_cache: dict | None = None
_live_aws_minted_at: float = 0.0                    # time.monotonic() — internal freshness math only
_live_aws_minted_generation: str | None = None       # wall-clock ISO ts — the one that goes in logs
_live_aws_last_attempt_at: float = 0.0
_live_aws_servings: int = 0


def _live_aws_fresh(now: float) -> bool:
    return (_live_aws_cache is not None
            and now - _live_aws_minted_at < CANARYTOKENS_REFRESH_SECS
            and _live_aws_servings < CANARYTOKENS_MAX_SERVINGS)


async def _mint_live_aws_pair() -> dict | None:
    """One-shot mint call. Returns None on ANY failure (network, non-2xx,
    unexpected response shape) — this is best-effort, and must never raise
    into a request handler or block one waiting on a third party."""
    tok = uuid.uuid4().hex[:TOKEN_ID_LEN]
    # Register the catcher token like any other issuance. Without this, a hit on
    # this key's own webhook URL landed in /x/{token} as an id the service had
    # never heard of, indistinguishable from a stranger probing catcher paths.
    _remember_issued_token(tok)
    payload = {
        "token_type": "aws_keys",
        "memo": f"http-bait honeypot live AWS canary, issued {datetime.now(timezone.utc).isoformat()}",
        "webhook_url": f"{CANARY_BASE}/x/{tok}",
    }
    try:
        async with httpx.AsyncClient(timeout=CANARYTOKENS_MINT_TIMEOUT_SECS) as client:
            resp = await client.post("https://canarytokens.org/generate", json=payload)
        resp.raise_for_status()
        data = resp.json()
        pair = {"aws_access_key_id": data["aws_access_key_id"],
                "aws_secret_access_key": data["aws_secret_access_key"]}
    except Exception as e:
        await alog({"event": "canarytokens_mint_failed", "err": str(e)[:300]})
        return None
    await alog({"event": "canarytokens_mint_ok", "catcher_token": tok,
                "canarytoken": data.get("token", ""), "canarytoken_url": data.get("token_url", "")})
    return pair


def _live_aws_servings_exhausted() -> bool:
    return _live_aws_cache is not None and _live_aws_servings >= CANARYTOKENS_MAX_SERVINGS


async def get_live_aws_pair() -> dict | None:
    """Cached accessor: mints at most once per CANARYTOKENS_REFRESH_SECS OR
    after CANARYTOKENS_MAX_SERVINGS distinct calls, whichever comes first —
    serves a stale-but-still-real cached pair otherwise. Minting a fresh live
    AWS key on every single honeypot hit would be both wasteful and needlessly
    noisy against a third-party service for no additional signal; the servings
    cap exists to bound the OTHER cost of sharing one key — and unlike the
    time cap, it's a bound on how many visitors could plausibly be
    responsible for a later real-world trigger, which is NOT allowed to
    degrade gracefully under a remint failure the way freshness can (see the
    exhausted-vs-merely-stale distinction below)."""
    global _live_aws_cache, _live_aws_minted_at, _live_aws_minted_generation
    global _live_aws_last_attempt_at, _live_aws_servings
    if not CANARYTOKENS_LIVE:
        return None
    now = time.monotonic()
    if _live_aws_fresh(now):
        _live_aws_servings += 1
        return _live_aws_cache
    async with _live_aws_lock:
        # Re-check after acquiring the lock: a concurrent request may have
        # already refreshed the cache while this one was waiting on it.
        now = time.monotonic()
        if _live_aws_fresh(now):
            _live_aws_servings += 1
            return _live_aws_cache
        # Unconditional floor between ATTEMPTS — see CANARYTOKENS_RETRY_COOLDOWN_SECS's
        # comment for why this now applies to routine (non-failure) remints too.
        if now - _live_aws_last_attempt_at < CANARYTOKENS_RETRY_COOLDOWN_SECS:
            # A servings-EXHAUSTED cache must not keep being served just
            # because a remint isn't allowed yet — that would let the
            # anonymity set the cap exists to bound grow unboundedly for the
            # full duration of the floor, repeatedly (found in adversarial
            # review: the fallback-serve path below had no ceiling check of
            # its own). Merely TIME-stale (still under the servings budget)
            # is fine to keep serving — that's a freshness concern, not a
            # per-key exposure bound, and degrading it to "serve nothing"
            # while merely waiting out the floor would be worse.
            if _live_aws_servings_exhausted():
                return None
            if _live_aws_cache is not None:
                _live_aws_servings += 1
            return _live_aws_cache
        _live_aws_last_attempt_at = now
        # _mint_live_aws_pair() already catches everything internally and
        # returns None rather than raising — but this accessor must never
        # depend on that as its ONLY line of defense (a future refactor of
        # that function, or of whatever it delegates to, could reintroduce
        # a raise). A live-canary mint failure must never turn into a 500
        # for a real visitor hitting an ordinary bait route.
        try:
            pair = await _mint_live_aws_pair()
        except Exception as e:
            await alog({"event": "canarytokens_mint_failed", "err": f"unexpected raise: {e}"[:300]})
            pair = None
        if pair is not None:
            _live_aws_cache = pair
            _live_aws_minted_at = now
            _live_aws_minted_generation = datetime.now(timezone.utc).isoformat()
            _live_aws_servings = 1  # this call is itself the first serving of the new pair
        elif _live_aws_servings_exhausted():
            # Same hard-bound rule as the cooldown branch above: an exhausted
            # cache does not get served just because THIS remint attempt
            # (not merely a cooldown-skipped one) also failed.
            return None
        elif _live_aws_cache is not None:
            # Mint failed, but the cache is only time-stale, not
            # servings-exhausted — still serving it as a last resort.
            _live_aws_servings += 1
        return _live_aws_cache  # fresh mint, last-good stale (not exhausted) cache, or None


async def aws_pair_honeytoken(session: str, route: str) -> dict:
    """Drop-in async counterpart to honeytoken("aws_pair", ...): serves a REAL
    canarytokens.org-minted pair when available, else falls back to the
    existing synthetic formatter completely unchanged."""
    live = await get_live_aws_pair()
    if live is not None:
        # serving_index/mint_generation close an attribution gap flagged in
        # review: without them, narrowing a later real-world trigger down to
        # a specific visitor among the (up to CANARYTOKENS_MAX_SERVINGS) who
        # saw this same key requires fragile timestamp-bucketing against
        # canarytokens_mint_ok events. Logging exactly which serving this
        # was, and which mint generation it belongs to, makes that
        # reconstruction direct instead of inferred. mint_generation is wall
        # -clock (found in review: an earlier version logged
        # _live_aws_minted_at directly, which is time.monotonic()-based —
        # process-relative and NOT joinable against canarytokens_mint_ok's
        # or this event's own wall-clock ts, defeating the whole point).
        await alog({"event": "honeytoken_issued", "kind": "aws_pair_live", "route": route, "session": session,
                    "serving_index": _live_aws_servings, "mint_generation": _live_aws_minted_generation})
        return live
    return await honeytoken("aws_pair", session, route)


# --------------------------------------------------------------------------- #
# Per-IP rate limiting (SPEC §2 non-goal: not a DoS amplifier). Sliding-window
# token bucket in memory — this is a single-worker, single-process service
# (see Dockerfile), so no cross-process coordination is needed.
# --------------------------------------------------------------------------- #
RATE_WINDOW_S = 10.0
RATE_MAX_REQ = 40  # generous headroom above any real scanner's per-target rate
EVICT_MIN_INTERVAL_S = 30.0  # throttle the O(n) eviction scan itself (see below)

_rate_lock = threading.Lock()
_rate_buckets: dict[str, deque] = {}
_last_evict = 0.0


def _rate_limited(ip: str) -> bool:
    global _last_evict
    now = time.monotonic()
    with _rate_lock:
        bucket = _rate_buckets.setdefault(ip, deque())
        while bucket and now - bucket[0] > RATE_WINDOW_S:
            bucket.popleft()
        if len(bucket) >= RATE_MAX_REQ:
            return True
        bucket.append(now)
        # Bound memory: an unbounded number of distinct scanner IPs would
        # otherwise grow this dict forever over a multi-week run. Evict IPs
        # whose whole window has gone stale (their last hit was over
        # RATE_WINDOW_S ago) rather than clearing everything at once, so a
        # mass-scan spike doesn't reset every currently-limited IP's window
        # simultaneously. The scan itself is O(n) over every tracked IP, so
        # under SUSTAINED high-cardinality scanning (the traffic this service
        # exists to attract) re-running it on every single request would
        # serialize the whole event loop behind it; only attempt it at most
        # once per EVICT_MIN_INTERVAL_S regardless of how over-budget we are.
        if len(_rate_buckets) > 50_000 and now - _last_evict > EVICT_MIN_INTERVAL_S:
            _last_evict = now
            stale = [k for k, b in _rate_buckets.items() if b and now - b[-1] > RATE_WINDOW_S]
            for k in stale:
                del _rate_buckets[k]
            if len(_rate_buckets) > 50_000:  # still over budget — drop oldest-inserted as a fallback
                for k in list(_rate_buckets.keys())[:10_000]:
                    del _rate_buckets[k]
        return False


# --------------------------------------------------------------------------- #
# CVE version-signaling variants (SPEC §4.3). Assigned by ROUTE, not globally,
# so different bait surfaces advertise different vulnerable stacks and draw
# comparably-classified follow-up.
# --------------------------------------------------------------------------- #
# VARIANTS / ROUTE_VARIANT / ROOT_VARIANT_CYCLE / ROOT_ROTATION_PERIOD_DAYS all
# live in signatures.py now, so analyze.py classifies traffic with the same
# table the service served it under. They used to be copied into analyze.py by
# hand, and the copy had already drifted.


def _root_variant() -> str:
    return root_variant_at(datetime.now(timezone.utc))


def current_variant_name(path: str) -> str | None:
    if path == "/":
        return _root_variant()
    return ROUTE_VARIANT.get(path)


def apply_variant_headers(resp: Response, path: str) -> None:
    name = current_variant_name(path)
    if not name:
        return
    v = VARIANTS[name]
    if v["server"]:
        resp.headers["Server"] = v["server"]
    if v["x_powered_by"]:
        resp.headers["X-Powered-By"] = v["x_powered_by"]


# CVE_SIGNATURES and TOOL_INVOCATION_SIGNATURES now live in signatures.py,
# shared with analyze.py. Each CVE entry is (id, pattern, scope, since).


def _safe_command_summary(command: str) -> dict:
    normalized = " ".join(command.split())[:200]
    redacted = re.sub(r"https?://\S+", "<url>", normalized, flags=re.I)
    redacted = re.sub(
        r"(?i)\b(password|passwd|token|api[_-]?key|secret)=\S+",
        r"\1=<redacted>",
        redacted,
    )
    return {
        "command": redacted,
        "command_len": len(normalized),
        "command_sha256": hashlib.sha256(normalized.encode()).hexdigest()[:16],
    }


async def check_attack_patterns(path: str, query: str, body_text: str, headers: dict,
                                body_available: bool = True,
                                headers_raw: list | None = None) -> None:
    decoded_body = unquote_plus(body_text)
    content_type = headers.get("content-type", "")
    ip = headers.get("x-forwarded-for", "").split(",")[0].strip()
    ua = headers.get("user-agent", "")
    header_text = (_headers_haystack(headers_raw) if headers_raw is not None
                   else " ".join(headers.values()))
    haystacks = {
        "path": path + "?" + query,
        "content-type": content_type,
        "headers": header_text,
        "body": body_text + "\n" + decoded_body,
        "any": " ".join([path, query, body_text, decoded_body, content_type]),
    }
    for cve_id, pattern, where, since in CVE_SIGNATURES:
        # .get() rather than [] so a signature added with a typo'd scope is a
        # dead signature, not a KeyError on every single request.
        if pattern.search(haystacks.get(where, "")):
            # signature_since goes in the record so a later reader can tell,
            # from the log alone, whether a row could have been produced live
            # or only by a rescan with a newer signature set.
            await alog({"event": "cve_pattern_match", "cve_id": cve_id,
                        "path": path, "matched_in": where, "ip": ip, "ua": ua,
                        "signature_since": since})

    # A Next/React Server Action header on multipart input is useful even when
    # the rate limiter or body cap prevents us from retaining the payload. It
    # is not itself proof of exploitation, so keep it separate from the CVE
    # match above and record whether a body was available for stronger review.
    rsc_header = headers.get("next-action") or headers.get("x-nextjs-server-actions")
    if rsc_header:
        await alog({"event": "rsc_action_probe", "path": path, "ip": ip, "ua": ua,
                    "action_header": rsc_header[:120],
                    "multipart": "multipart/form-data" in content_type.lower(),
                    "body_available": body_available})

    tool_haystack = "\n".join([path, query, body_text, decoded_body, haystacks["headers"]])
    for tool, pattern in TOOL_INVOCATION_SIGNATURES:
        match = pattern.search(tool_haystack)
        if match:
            summary = _safe_command_summary(match.group("command"))
            await alog({"event": "tool_invocation_attempt", "tool": tool,
                        **summary, "path": path, "ip": ip, "ua": ua})
    if INDIRECT_COMMAND_RE.search(tool_haystack):
        await alog({"event": "tool_invocation_attempt",
                    "tool": "node:child_process.exec",
                    "command": "<indirect cmd variable>", "command_len": 0,
                    "command_sha256": "", "path": path, "ip": ip, "ua": ua})


def _headers_first_wins(request: Request) -> tuple[dict, list]:
    # Starlette's Headers.get() (used for ip extraction) returns the FIRST
    # occurrence of a repeated header; a naive dict(raw) keeps the LAST. Build
    # the logged dict the same first-wins way so rec["headers"]/rec["xff"]
    # never silently disagree with rec["ip"] on a request with duplicate
    # X-Forwarded-For (or any other repeated header).
    hdrs_raw = [[k.decode("latin1"), v.decode("latin1")] for k, v in request.headers.raw]
    hdrs: dict = {}
    for k, v in hdrs_raw:
        hdrs.setdefault(k, v)
    return hdrs, hdrs_raw


def _headers_haystack(hdrs_raw: list) -> str:
    """Every header occurrence, for signature matching.

    First-wins is right for attribution (rec["ip"] and rec["headers"] must
    agree), but wrong for detection: a scanner that sends `Referer: ok`
    followed by `Referer: ${jndi:ldap://…}` would have the payload dropped
    before any signature saw it. Match against all occurrences.
    """
    return "\n".join(v for _, v in hdrs_raw)


# Bodies are capped (BODY_CAP/BODY_EXCERPT_CAP) but header values were not, so a
# single request carrying a ~1MB header value (within Go/Caddy's default
# MaxHeaderBytes) wrote ~1MB into one JSONL line. At the per-IP rate limit that
# is a few MB/s of disk from one source — a cheap way to fill the disk and
# silence collection. Truncate for storage; the length is retained.
HEADER_VALUE_CAP = 4_000
HEADERS_TOTAL_CAP = 32_000

# Ephemeral, per-process, never written anywhere. Redacted secrets are recorded
# as HMAC(_REDACTION_SALT, value) so "the same unknown credential appeared on
# two requests" stays answerable while the value itself does not survive.
#
# A bare sha256 would not be good enough here. Half of what lands in these
# headers is Basic auth (base64 of user:pass) and low-entropy API keys, and an
# unsalted digest of those is recoverable by dictionary attack from the
# published log format alone. Regenerating the salt each start deliberately
# costs cross-restart correlation: the alternative is a stored key that turns
# every historical log into an offline-crackable corpus the moment it leaks.
_REDACTION_SALT = os.urandom(32)


def _redaction_digest(value: str) -> str:
    return hmac.new(_REDACTION_SALT, value.encode("utf-8", "replace"),
                    hashlib.sha256).hexdigest()[:12]


def _sensitive_label(name: str, value: str) -> str:
    if name.endswith("authorization"):
        # "Bearer", "Basic", … — the scheme is signal, the credential is not.
        return value.split(" ", 1)[0][:32] or "unknown"
    if "cookie" in name:
        return "cookie"
    return "key"


def _headers_for_log(headers: dict) -> dict:
    out = dict(headers)
    for name in SENSITIVE_HEADERS:
        value = out.get(name)
        if value is not None:
            label = _sensitive_label(name, value)
            out[name] = (f"<redacted:{label}:len={len(value)}"
                         f":hmac={_redaction_digest(value)}>")
    budget = HEADERS_TOTAL_CAP
    capped = {}
    for name, value in out.items():
        if budget <= 0:
            capped["<truncated>"] = f"{len(out) - len(capped)} more header(s) dropped"
            break
        if len(value) > HEADER_VALUE_CAP:
            value = f"{value[:HEADER_VALUE_CAP]}<truncated:len={len(value)}>"
        budget -= len(value)
        capped[name] = value
    return capped


# Some formatters serve only a PREFIX of the id rather than the whole thing —
# formatters.db_password is tok[:12], and db_connection_string embeds the same
# 12-char slice. Matching on the full 16 could therefore never fire for those
# kinds (~14% of everything issued), so a replayed database password looked
# identical to no replay at all. Scan for the shortest served form and check
# the longer one where the run allows it.
#
# The width is derived from formatters.SERVED_TOKEN_LEN rather than hardcoded,
# so a new kind that serves a shorter run widens the scan automatically instead
# of silently falling outside it. That is the bug class this whole comment
# exists because of; a constant here would just wait to go stale again.
TOKEN_PREFIX_LEN = MIN_SERVED_TOKEN_LEN
_HEX_RUN_RE = re.compile(r"[0-9a-f]{%d,}" % TOKEN_PREFIX_LEN)
MAX_TOKEN_CANDIDATES = 4_000            # backstop on pathological hex-dense input


async def _check_honeytoken_reuse(path: str, query: str, body: bytes,
                                  headers: dict,
                                  body_available: bool = True) -> None:
    # Inspect before general-log redaction, retain only the already-random
    # honeytoken id and source location, and discard unknown visitor secrets.
    #
    # Direction matters. Scanning every issued token against the request is
    # O(issued x request) with both sides attacker-controlled: minting is free
    # (one GET /.env mints 4), so a single rate-limit-compliant IP fills the
    # 50k cap in under an hour and every later request then costs GBs of
    # substring search on the one worker's event loop, wedging the service
    # while it still returns 200s. Instead, pull token-shaped candidates out of
    # the request and look each up in the set: O(request), independent of how
    # many tokens have been issued.
    locations = {
        "path": path,
        "query": query,
        "body": body.decode("utf-8", "replace"),
        "headers": "\n".join(headers.values()),
    }
    seen: dict[str, tuple[str, str]] = {}   # token -> (location, matched form)
    budget = MAX_TOKEN_CANDIDATES
    for where, value in locations.items():
        for run in _HEX_RUN_RE.finditer(value.lower()):
            text = run.group(0)
            # A served value may repeat the token to reach a required width
            # (formatters._hex_pad), so the id can start at any offset in a run.
            for i in range(len(text) - TOKEN_PREFIX_LEN + 1):
                if budget <= 0:
                    break
                budget -= 1
                full = text[i:i + TOKEN_ID_LEN]
                if len(full) == TOKEN_ID_LEN and full in _issued_token_ids:
                    seen.setdefault(full, (where, "full"))
                    continue
                prefix = text[i:i + TOKEN_PREFIX_LEN]
                tok = _issued_token_prefixes.get(prefix)
                if tok is not None:
                    seen.setdefault(tok, (where, "prefix"))
    for tok, (where, form) in seen.items():
        await alog({"event": "honeytoken_reuse_observed", "token": tok,
                    "path": path, "seen_in": where, "matched": form,
                    "body_available": body_available,
                    "ip": headers.get("x-forwarded-for", "").split(",")[0].strip()})


async def _read_capped_body(request: Request) -> tuple[bytes, bool]:
    """Stream the body, never buffering more than BODY_CAP bytes total —
    applied as a hard read-abort (not just a post-hoc log truncation) so a
    lying or absent Content-Length, or a chunked upload, cannot buffer more
    than that regardless. Returns (bytes_read, exceeded)."""
    chunks = []
    total = 0
    try:
        async for chunk in request.stream():
            total += len(chunk)
            if total > BODY_CAP:
                # Keep the leading BODY_CAP bytes rather than discarding the
                # whole offending chunk. Caddy proxies with `flush_interval -1`,
                # so bodies arrive in few large chunks: dropping the chunk that
                # crossed the line meant a single 64,001-byte write retained
                # nothing at all, and a payload "past the cap" was in practice a
                # payload that erased everything before it too. Signatures now
                # get the first 64KB in every case.
                chunks.append(chunk)
                return b"".join(chunks)[:BODY_CAP], True
            chunks.append(chunk)
    except ClientDisconnect:
        # A client that promises a Content-Length and then goes away mid-body is
        # ordinary scanner behaviour (timeouts, resets, fire-and-forget POSTs).
        # Letting this propagate meant the request was never logged at all — the
        # exception fires before the middleware writes its record — so the most
        # abrupt scanners were the ones systematically missing from the data.
        # Keep what arrived and let the caller log it.
        pass
    return b"".join(chunks), False


# --------------------------------------------------------------------------- #
# Request telemetry middleware. Logs every request per SPEC §6 — including
# rate-limited and oversized ones, so a burst/flood still leaves a trace —
# then lets the route handler run. Body is read once here (capped) and
# stashed on request.state so downstream handlers reuse it without
# re-reading the stream.
# --------------------------------------------------------------------------- #
@app.middleware("http")
async def telemetry_mw(request: Request, call_next):
    _request_id_ctx.set(uuid.uuid4().hex)
    hdrs, hdrs_raw = _headers_first_wins(request)
    ip = hdrs.get("x-forwarded-for", "").split(",")[0].strip() or (
        request.client.host if request.client else "")

    # The container healthcheck polls /healthz from loopback every 60s — ~1,440
    # hits/day against a real-traffic baseline of a few hundred, which would
    # swamp the dataset it exists to protect. Anything arriving through Caddy
    # carries X-Forwarded-For, so an OUTSIDE probe of /healthz still gets
    # logged; only the internal poll is dropped.
    if request.url.path == "/healthz" and not hdrs.get("x-forwarded-for"):
        return await call_next(request)

    def base_rec(status: int, route_kind: str) -> dict:
        # Every field below is attacker-controlled. Each one is bounded here,
        # and JsonlWriter bounds the assembled record again: an unbounded
        # field is a way to fill the disk, and a full disk stops collection
        # while the service goes on answering 200s.
        return {
            "event": "request", "window": WINDOW_LABEL, "ip": ip,
            "xff": _cap(hdrs.get("x-forwarded-for", ""), XFF_CAP),
            "ua": _cap(hdrs.get("user-agent", ""), UA_CAP),
            "ja4": _cap(hdrs.get("x-ja4", ""), FINGERPRINT_CAP),
            "ja4h": _cap(hdrs.get("ja4h", ""), FINGERPRINT_CAP),
            "tls": {"version": _cap(hdrs.get("x-tls-version", ""), FINGERPRINT_CAP),
                    "cipher": _cap(hdrs.get("x-tls-cipher", ""), FINGERPRINT_CAP),
                    "sni": _cap(hdrs.get("x-tls-sni", ""), FINGERPRINT_CAP),
                    "alpn": _cap(hdrs.get("x-tls-alpn", ""), FINGERPRINT_CAP)},
            "method": request.method[:16],
            "path": _cap(request.url.path, PATH_CAP),
            "query": _cap(str(request.url.query), QUERY_CAP),
            "header_order": [h[0][:64] for h in hdrs_raw[:HEADER_ORDER_CAP]],
            "header_count": len(hdrs_raw),
            "headers": _headers_for_log(hdrs),
            "status_served": status, "route_kind": route_kind,
        }

    if _rate_limited(ip):
        # Skip the (relatively costly) body read on a flood, but still log
        # the hit — a silent gap here would be exactly the burst traffic
        # SPEC §8's cadence analysis most needs to see.
        rec = base_rec(429, "rate-limited")
        rec["body_len"] = 0
        rec["body_excerpt"] = ""
        await alog(rec)
        # Reuse detection used to sit below this early return, so a replayed
        # honeytoken was invisible for the entire duration of a burst. That is
        # backwards: a credential replay characteristically arrives as a
        # rapid spray of Authorization headers across many probe paths, which
        # is precisely the shape that trips the limiter, so the detector was
        # blind to exactly the traffic it exists to catch. Scanning path, query
        # and headers costs nothing extra because they are already parsed;
        # only the body is unavailable, and that gap is now recorded rather
        # than assumed.
        await _check_honeytoken_reuse(request.url.path, str(request.url.query),
                                      b"", hdrs, body_available=False)
        await check_attack_patterns(request.url.path, str(request.url.query), "",
                                    hdrs, body_available=False, headers_raw=hdrs_raw)
        return PlainTextResponse("rate limited", status_code=429)

    raw, exceeded = await _read_capped_body(request)
    await _check_honeytoken_reuse(request.url.path, str(request.url.query), raw, hdrs)
    if exceeded:
        rec = base_rec(413, "catch-all")
        # The true size is unknown past the abort point. Recording BODY_CAP + 1
        # as `body_len` stated a specific length that was never measured; name
        # the field for what it actually is instead.
        rec["body_len_at_least"] = len(raw)
        rec["body_truncated"] = True
        rec["body_excerpt"] = ""
        await alog(rec)
        await check_attack_patterns(request.url.path, str(request.url.query),
                                    raw.decode("utf-8", "replace"), hdrs,
                                    body_available=False, headers_raw=hdrs_raw)
        # We stopped reading mid-body without draining the rest — force the
        # connection closed rather than let it be reused, so leftover bytes
        # can't be misparsed as the start of the next request on this socket.
        return PlainTextResponse("payload too large", status_code=413,
                                 headers={"Connection": "close"})

    body = raw[:BODY_CAP]
    request.state.body = body

    resp = await call_next(request)

    # Any route that did not mark a credential submission itself gets the
    # generic shape check, so redaction no longer depends on each handler
    # remembering to opt in. This is what closes the catch-all POST hole.
    infer_credential_submission(request, body)

    body_excerpt = body[:BODY_EXCERPT_CAP].decode("utf-8", "replace")
    if getattr(request.state, "sensitive_body", False):
        body_excerpt = f"<redacted:credential-submission:len={len(body)}>"
    rec = base_rec(resp.status_code, getattr(request.state, "route_kind", "catch-all"))
    rec["body_len"] = len(raw)
    rec["body_excerpt"] = body_excerpt
    creds = getattr(request.state, "creds_submitted", None)
    if creds is not None:
        rec["creds_submitted"] = creds
    await alog(rec)

    # Detection scans the complete bounded body (<=64KB), while the general
    # request record retains only its 4KB excerpt. This closes the easy evasion
    # where an exploit signature is padded just beyond the logging excerpt.
    body_text = body.decode("utf-8", "replace")
    await check_attack_patterns(request.url.path, str(request.url.query), body_text, hdrs,
                                headers_raw=hdrs_raw)
    return resp


def sess_of(request: Request) -> str:
    # No cookie-based session tracking: scanners essentially never retain
    # cookies, and a fresh honeytoken per hit is *more* attributable, not
    # less (SPEC §5's "unique per route/session" is satisfied trivially when
    # every hit is its own session). Use ip+ua as the grouping key for the
    # log/analysis layer instead of minting server-side session state.
    return f"{request.headers.get('x-forwarded-for','').split(',')[0].strip()}|{request.headers.get('user-agent','')}"


def mark(request: Request, kind: str) -> None:
    request.state.route_kind = kind


def mark_credential_submission(request: Request, user: str, password: str,
                               source: str = "body") -> None:
    # Unknown visitor credentials may be stolen/reused material. Preserve the
    # stuffing signal without retaining the values themselves. Any body-derived
    # source redacts the excerpt; "basic-auth" does not, because the credential
    # was in a header that _headers_for_log already redacts.
    request.state.sensitive_body = source.startswith("body")
    request.state.creds_submitted = {
        "user_present": bool(user),
        "user_len": len(user),
        "pass_present": bool(password),
        "pass_len": len(password),
        "source": source,
    }


_CREDENTIAL_LITERAL_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(n) for n in sorted(CREDENTIAL_FIELD_NAMES)) + r")"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)")


def _redact_credential_literals(text: str) -> str:
    """Strip credential values from free-form text that is logged verbatim.

    Used for GraphQL query bodies, where a login mutation carries the password
    inline as an argument rather than as a form field.
    """
    return _CREDENTIAL_LITERAL_RE.sub(r"\1\2<redacted>", text)


def _decode_credential_fields(body: bytes, content_type: str) -> tuple[str, str] | None:
    """Pull (identity, secret) out of a form-encoded or JSON body, or None.

    Field names come from signatures.CREDENTIAL_FIELD_NAMES /
    IDENTITY_FIELD_NAMES so the panel handlers and this generic path agree on
    what counts as a credential.
    """
    if not body:
        return None
    text = body[:BODY_CAP].decode("utf-8", "replace")
    fields: dict[str, str] = {}
    if "application/json" in content_type:
        try:
            data = json.loads(text or "{}")
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        fields = {str(k).lower(): str(v) for k, v in data.items()
                  if isinstance(v, (str, int, float))}
    else:
        # parse_qs on a body that is not actually form-encoded yields either
        # nothing or one junk key, so this is safe to attempt unconditionally.
        try:
            fields = {k.lower(): (v[0] if v else "")
                      for k, v in parse_qs(text, keep_blank_values=True).items()}
        except Exception:
            return None
    secret = next((fields[k] for k in fields if k in CREDENTIAL_FIELD_NAMES), None)
    if secret is None:
        return None
    identity = next((fields[k] for k in fields if k in IDENTITY_FIELD_NAMES), "")
    return identity, secret


def infer_credential_submission(request: Request, body: bytes) -> None:
    """Redact credential-shaped bodies on routes with no dedicated handler.

    Redaction used to depend entirely on a handler calling
    mark_credential_submission(), and only four POST handlers did. Everything
    else fell through to catch_all and the raw body was written to
    body_excerpt verbatim. /admin is advertised in robots.txt and sitemap.xml
    but only registers GET, so a stuffing tool that POSTed to the advertised
    URL rather than the form's action had its credentials stored in full —
    which is exactly the material the non-retention rule exists to not keep,
    since credentials sprayed at a honeypot are usually stolen from a third
    party who has nothing to do with any of this.

    Called from the middleware for every request no handler already marked, so
    a new lure cannot reintroduce the gap by forgetting to opt in.
    """
    if getattr(request.state, "creds_submitted", None) is not None:
        return
    found = _decode_credential_fields(body, request.headers.get("content-type", ""))
    if found is None:
        return
    identity, secret = found
    mark_credential_submission(request, identity, secret, source="body-inferred")


HEALTH_MIN_FREE_BYTES = int(os.environ.get("HB_HEALTH_MIN_FREE_BYTES", 512 * 1024 * 1024))


@app.get("/healthz")
async def healthz():
    """Liveness AND recording health.

    Answering requests is not the same as recording them: a full disk makes
    JsonlWriter.write() fail without raising, so the old unconditional
    {"ok": true} reported a healthy service that was collecting nothing. Gate
    on the writer's own error counter and on free space.

    The response body stays exactly {"ok": bool} — this route is reachable from
    the internet, and disk figures or failure counts would both leak operator
    detail and read as an unusual thing for the app this pretends to be. Detail
    goes to stderr and the container log instead.
    """
    ok = True
    detail = []
    if writer.last_write_error is not None:
        ok = False
        detail.append(f"write_failures={writer.write_failures} last={writer.last_write_error}")
    try:
        free = shutil.disk_usage(LOG_DIR).free
        if free < HEALTH_MIN_FREE_BYTES:
            ok = False
            detail.append(f"low_disk free={free}")
    except OSError as e:
        ok = False
        detail.append(f"disk_usage_failed={e}")
    if not ok:
        print(f"http-bait: UNHEALTHY: {'; '.join(detail)}", file=sys.stderr)
        return JSONResponse({"ok": False}, status_code=503)
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Sanitized machine-readable API discovery lure. This replaces FastAPI's real
# generated schema and advertises only two synthetic, log-only operations.
# A client that fetches the schema and then calls one of these routes produces
# much stronger agent/tool-use evidence than a User-Agent or cadence guess.
# --------------------------------------------------------------------------- #
BAIT_OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "Portal Operations API", "version": "1.4.2"},
    "servers": [{"url": CANARY_BASE}],
    "paths": {
        "/api/v1/system/status": {
            "get": {
                "operationId": "getSystemStatus",
                "summary": "Get production system status",
                "responses": {"200": {"description": "Current status"}},
            },
        },
        "/api/v1/jobs/run": {
            "post": {
                "operationId": "runMaintenanceJob",
                "summary": "Run a named maintenance job",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["job"],
                                "properties": {
                                    "job": {"type": "string",
                                            "enum": ["refresh-cache", "rotate-logs", "sync-config"]},
                                    "dry_run": {"type": "boolean", "default": True},
                                },
                            },
                        },
                    },
                },
                "responses": {"202": {"description": "Job accepted"}},
            },
        },
    },
}


@app.get("/openapi.json")
@app.get("/swagger.json")
async def openapi_lure(request: Request):
    mark(request, "api-discovery")
    return JSONResponse(BAIT_OPENAPI)


@app.get("/.well-known/ai-plugin.json")
async def ai_plugin_lure(request: Request):
    mark(request, "api-discovery")
    return JSONResponse({
        "schema_version": "v1",
        "name_for_human": "Portal Operations",
        "name_for_model": "portal_operations",
        "description_for_human": "Production portal health and maintenance operations.",
        "description_for_model": "Inspect portal health and run approved maintenance jobs.",
        "auth": {"type": "none"},
        "api": {"type": "openapi", "url": f"{CANARY_BASE}/openapi.json"},
        "logo_url": f"{CANARY_BASE}/favicon.ico",
        "contact_email": "ops@http-bait.example",
        "legal_info_url": f"{CANARY_BASE}/terms",
    })


@app.get("/api/v1/system/status")
async def api_system_status(request: Request):
    mark(request, "tool-call")
    await alog({"event": "api_tool_call_attempt", "tool": "getSystemStatus",
                "ip": request.headers.get("x-forwarded-for", "").split(",")[0].strip(),
                "args": {}})
    return JSONResponse({"status": "degraded", "region": "us-west",
                         "maintenance_mode": False})


@app.post("/api/v1/jobs/run")
async def api_run_job(request: Request):
    mark(request, "tool-call")
    body = request.state.body
    try:
        args = json.loads(body or b"{}")
        if not isinstance(args, dict):
            args = {"value": str(args)[:500]}
    except Exception:
        args = {"raw": body[:500].decode("utf-8", "replace")}
    safe_args = {
        "job": str(args.get("job", ""))[:200],
        "dry_run": args.get("dry_run"),
        "keys": sorted(str(k)[:100] for k in args)[:30],
    }
    await alog({"event": "api_tool_call_attempt", "tool": "runMaintenanceJob",
                "ip": request.headers.get("x-forwarded-for", "").split(",")[0].strip(),
                "args": safe_args})
    # Log-only: no job is run, queued, fetched, or otherwise acted on.
    return JSONResponse({"status": "rejected", "message": "runner unavailable"},
                        status_code=503)


# --------------------------------------------------------------------------- #
# 4.1 Secret-file lures
# --------------------------------------------------------------------------- #
@app.get("/.env")
async def env_file(request: Request):
    mark(request, "secret-file")
    s = sess_of(request)
    aws_pair = await aws_pair_honeytoken(s, "/.env")
    body = "\n".join([
        f"DB_PASSWORD={await honeytoken('db_password', s, '/.env')}",
        f"AWS_ACCESS_KEY_ID={aws_pair['aws_access_key_id']}",
        f"STRIPE_SECRET_KEY={await honeytoken('stripe_secret', s, '/.env')}",
        f"JWT_SECRET={await honeytoken('jwt', s, '/.env')}",
    ]) + "\n"
    return PlainTextResponse(body)


@app.get("/.git/HEAD")
async def git_head(request: Request):
    mark(request, "secret-file")
    return PlainTextResponse("ref: refs/heads/main\n")


@app.get("/.git/index")
async def git_index(request: Request):
    # A valid empty Git index header is enough for dumpers to recognize the
    # file and continue to /.git/config/HEAD without exposing real repository
    # content or building an attacker-controlled object traversal surface.
    mark(request, "secret-file")
    return Response(b"DIRC\x00\x00\x00\x02\x00\x00\x00\x00",
                    media_type="application/octet-stream")


@app.get("/.git/config")
async def git_config(request: Request):
    mark(request, "secret-file")
    s = sess_of(request)
    tok = await honeytoken("github_pat", s, "/.git/config")
    body = (
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
        "[remote \"origin\"]\n"
        f"\turl = https://x-access-token:{tok}@github.com/internal-org/backend-service.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
    )
    return PlainTextResponse(body)


@app.get("/config.json")
async def config_json(request: Request):
    mark(request, "secret-file")
    s = sess_of(request)
    return JSONResponse({
        "db": {"host": "db.internal-prod.local", "user": "app", "password": await honeytoken("db_password", s, "/config.json")},
        "api_keys": {"stripe": await honeytoken("stripe_secret", s, "/config.json"),
                     "openai": await honeytoken("openai_key", s, "/config.json")},
        "gcp_service_account": await honeytoken("gcp", s, "/config.json"),
        "notifications": {"slack_webhook": await honeytoken("slack_webhook", s, "/config.json")},
    })


@app.get("/backup.sql")
async def backup_sql(request: Request):
    mark(request, "secret-file")
    s = sess_of(request)
    key = await honeytoken("stripe_secret", s, "/backup.sql")
    body = (
        "INSERT INTO users (id, email, password_hash) VALUES\n"
        "  (1, 'admin@internal-prod.local', '$2b$12$abcdefghijklmnopqrstuv'),\n"
        "  (2, 'ops@internal-prod.local', '$2b$12$0123456789abcdefghijkl');\n"
        "INSERT INTO customers (id, name, api_key) VALUES\n"
        f"  (1, 'Acme Corp', '{key}');\n"
    )
    return Response(body, media_type="application/sql")


@app.get("/.aws/credentials")
async def aws_credentials(request: Request):
    mark(request, "secret-file")
    pair = await aws_pair_honeytoken(sess_of(request), "/.aws/credentials")
    body = f"[default]\naws_access_key_id = {pair['aws_access_key_id']}\naws_secret_access_key = {pair['aws_secret_access_key']}\nregion = us-east-1\n"
    return PlainTextResponse(body)


@app.get("/wp-config.php")
async def wp_config(request: Request):
    mark(request, "secret-file")
    s = sess_of(request)
    pw = await honeytoken("db_password", s, "/wp-config.php")
    body = (
        "<?php\n"
        "define('DB_NAME', 'wordpress');\n"
        "define('DB_USER', 'wp_user');\n"
        f"define('DB_PASSWORD', '{pw}');\n"
        "define('DB_HOST', 'localhost');\n"
        "define('AUTH_KEY', 'put your unique phrase here');\n"
    )
    resp = PlainTextResponse(body)
    apply_variant_headers(resp, "/wp-config.php")
    return resp


@app.get("/docker-compose.yml")
async def docker_compose_yml(request: Request):
    mark(request, "secret-file")
    s = sess_of(request)
    key = await honeytoken("db_connection_string", s, "/docker-compose.yml")
    body = (
        "services:\n  app:\n    image: internal/backend:latest\n    environment:\n"
        f"      - DATABASE_URL={key}\n      - NODE_ENV=production\n    ports:\n        - \"3000:3000\"\n"
    )
    return PlainTextResponse(body)


@app.get("/.vscode/sftp.json")
async def vscode_sftp(request: Request):
    mark(request, "secret-file")
    s = sess_of(request)
    return JSONResponse({
        "name": "production",
        "host": "deploy.internal-prod.local",
        "protocol": "sftp",
        "port": 22,
        "username": "deploy",
        "password": await honeytoken("db_password", s, "/.vscode/sftp.json"),
        "remotePath": "/srv/www",
        "uploadOnSave": True,
    })


@app.get("/id_rsa")
@app.get("/.ssh/id_rsa")
async def id_rsa(request: Request):
    mark(request, "secret-file")
    s = sess_of(request)
    body = await honeytoken("ssh_private_key", s, request.url.path)
    return PlainTextResponse(body)


# --------------------------------------------------------------------------- #
# 4.2 Admin / auth lures
# --------------------------------------------------------------------------- #
_LOGIN_FORM = """<!doctype html><html><head><title>Admin Login</title>{meta}</head>
<body><h2>Administrator Login</h2>
<form method="post" action="/admin/login">
<input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Log in</button></form></body></html>"""


@app.get("/admin")
@app.get("/admin/login")
async def admin_login_form(request: Request):
    mark(request, "admin")
    resp = HTMLResponse(_LOGIN_FORM.format(meta=VARIANTS["struts"]["meta"]))
    apply_variant_headers(resp, "/admin")
    return resp


@app.post("/admin/login")
async def admin_login_submit(request: Request):
    mark(request, "admin")
    body = request.state.body
    ct = request.headers.get("content-type", "")
    user = pw = ""
    try:
        if "application/json" in ct:
            data = json.loads(body or b"{}")
            user, pw = str(data.get("username", data.get("user", ""))), str(data.get("password", data.get("pass", "")))
        else:
            data = parse_qs(body.decode("utf-8", "replace"))
            user = (data.get("username") or data.get("user") or [""])[0]
            pw = (data.get("password") or data.get("pass") or [""])[0]
    except Exception:
        pass
    mark_credential_submission(request, user, pw)
    resp = HTMLResponse(_LOGIN_FORM.format(meta="<!-- invalid credentials -->"), status_code=401)
    apply_variant_headers(resp, "/admin")
    return resp


# Fingerprinted panel lures (2026-07 addition): the generic /admin form above
# gets found but never gets POSTed to — real credential-stuffing toolkits key
# on KNOWN product signatures, not a bare <form>. These three match what
# actual stuffing tooling fingerprints before it bothers submitting.

_WP_LOGIN_FORM = """<!doctype html>
<html lang="en-US">
<head><title>Log In &lsaquo; portal &#8212; WordPress</title>{meta}</head>
<body class="login no-js">
<div id="login">
<h1><a href="https://wordpress.org/">Portal</a></h1>
{error}<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20"></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input" size="20"></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"></p>
<input type="hidden" name="redirect_to" value="/wp-admin/">
<input type="hidden" id="testcookie" name="testcookie" value="1">
</form>
</div>
</body></html>"""


@app.get("/wp-login.php")
async def wp_login_form(request: Request):
    mark(request, "admin")
    resp = HTMLResponse(_WP_LOGIN_FORM.format(meta=VARIANTS["wordpress"]["meta"], error=""))
    apply_variant_headers(resp, "/wp-login.php")
    return resp


@app.post("/wp-login.php")
async def wp_login_submit(request: Request):
    mark(request, "admin")
    body = request.state.body
    try:
        data = parse_qs(body.decode("utf-8", "replace"))
        user = (data.get("log") or [""])[0]
        pw = (data.get("pwd") or [""])[0]
    except Exception:
        user = pw = ""
    mark_credential_submission(request, user, pw)
    # Real WordPress renders the error INLINE at 200, not a 401/403 — matching
    # that is part of the fingerprint; a stuffing tool checking status code
    # alone would otherwise learn nothing from a non-200 response here.
    error = (f'<div id="login_error">ERROR: The password you entered for the '
             f'submitted username is incorrect. '
             f'<a href="/wp-login.php?action=lostpassword">Lost your password?</a></div>')
    resp = HTMLResponse(_WP_LOGIN_FORM.format(meta=VARIANTS["wordpress"]["meta"], error=error))
    apply_variant_headers(resp, "/wp-login.php")
    return resp


_PHPMYADMIN_FORM = """<!doctype html>
<html lang="en" dir="ltr">
<head><title>phpMyAdmin</title>{meta}</head>
<body>
<div id="page_login">
{error}<form method="post" action="index.php" name="login_form" id="login_form" class="disableAjax login">
<input type="hidden" name="set_session" value="">
<input type="hidden" name="server" value="1">
<fieldset>
<legend>Log in</legend>
<div class="item">
<label for="input_username">Username:</label>
<input type="text" name="pma_username" id="input_username" value="" size="24" autofocus>
</div>
<div class="item">
<label for="input_password">Password:</label>
<input type="password" name="pma_password" id="input_password" value="" size="24">
</div>
<input type="hidden" name="token" value="{token}">
</fieldset>
<fieldset class="tblFooters">
<input type="submit" value="Go">
</fieldset>
</form>
</div>
</body></html>"""


def _pma_token() -> str:
    # phpMyAdmin's real CSRF token is a long hex string tied to the PHP
    # session — this is a fresh, unlinkable random value, never checked or
    # stored, present purely so the field looks structurally correct.
    return uuid.uuid4().hex + uuid.uuid4().hex


@app.get("/phpmyadmin/")
@app.get("/phpmyadmin/index.php")
async def phpmyadmin_form(request: Request):
    mark(request, "admin")
    resp = HTMLResponse(_PHPMYADMIN_FORM.format(
        meta=VARIANTS["wordpress"]["meta"], error="", token=_pma_token()))
    apply_variant_headers(resp, "/phpmyadmin/")
    return resp


@app.post("/phpmyadmin/index.php")
async def phpmyadmin_submit(request: Request):
    mark(request, "admin")
    body = request.state.body
    try:
        data = parse_qs(body.decode("utf-8", "replace"))
        user = (data.get("pma_username") or [""])[0]
        pw = (data.get("pma_password") or [""])[0]
    except Exception:
        user = pw = ""
    mark_credential_submission(request, user, pw)
    error = '<div class="alert alert-danger" role="alert">#1045 Cannot log in to the MySQL server</div>'
    resp = HTMLResponse(_PHPMYADMIN_FORM.format(
        meta=VARIANTS["wordpress"]["meta"], error=error, token=_pma_token()))
    apply_variant_headers(resp, "/phpmyadmin/")
    return resp


_TOMCAT_401_BODY = """<html><head><title>Apache Tomcat/8.5.39 - Error report</title></head>
<body><h1>HTTP Status 401 &ndash; Unauthorized</h1>
<p><b>Type</b> Status Report</p>
<p><b>Message</b> Access to the requested resource has not been granted.</p>
<p><b>Description</b> The client is not authenticated to access the requested resource.</p>
<hr><h3>Apache Tomcat/8.5.39</h3></body></html>"""


@app.get("/manager/html")
@app.get("/manager/status")
async def tomcat_manager(request: Request):
    # Real Tomcat Manager gates on HTTP Basic Auth, not a login form — always
    # 401, whether or not credentials were even offered, matching what a
    # default/never-configured manager install actually does.
    mark(request, "admin")
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "replace")
            user, _, pw = decoded.partition(":")
        except Exception:
            user, pw = "", ""
        mark_credential_submission(request, user, pw, source="basic-auth")
    resp = HTMLResponse(_TOMCAT_401_BODY, status_code=401,
                         headers={"WWW-Authenticate": 'Basic realm="Tomcat Manager Application"'})
    resp.headers["Server"] = "Apache-Tomcat/8.5.39"
    return resp


_ADMINER_FORM = """<!doctype html><html><head><title>Login - Adminer</title>
<meta name="robots" content="noindex"></head><body>
<h1>Login</h1>{error}
<form method="post">
<label>System <select name="auth[driver]"><option value="server">MySQL</option></select></label>
<label>Server <input name="auth[server]" value="localhost"></label>
<label>Username <input name="auth[username]" value=""></label>
<label>Password <input type="password" name="auth[password]"></label>
<label>Database <input name="auth[db]" value=""></label>
<input type="submit" value="Login">
</form><footer>Adminer 4.8.1</footer></body></html>"""


@app.api_route("/adminer.php", methods=["GET", "POST"])
@app.api_route("/adminer/adminer.php", methods=["GET", "POST"])
@app.api_route("/admin/adminer.php", methods=["GET", "POST"])
async def adminer(request: Request):
    mark(request, "admin")
    error = ""
    if request.method == "POST":
        try:
            data = parse_qs(request.state.body.decode("utf-8", "replace"))
            user = (data.get("auth[username]") or data.get("username") or [""])[0]
            pw = (data.get("auth[password]") or data.get("password") or [""])[0]
        except Exception:
            user = pw = ""
        mark_credential_submission(request, user, pw)
        error = '<p class="error">Access denied for user</p>'
    resp = HTMLResponse(_ADMINER_FORM.format(error=error))
    resp.headers["Server"] = "Apache/2.4.29 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.2.24"
    return resp


@app.get("/api/keys")
async def api_keys(request: Request):
    mark(request, "admin")
    s = sess_of(request)
    return JSONResponse({"keys": [
        {"name": "prod-payments", "key": await honeytoken("stripe_secret", s, "/api/keys")},
        {"name": "internal-ci", "key": await honeytoken("github_pat", s, "/api/keys")},
        {"name": "partner-readonly", "key": await honeytoken("openai_key", s, "/api/keys")},
        {"name": "ops-alerts-bot", "key": await honeytoken("slack_bot_token", s, "/api/keys")},
    ]})


@app.get("/debug")
@app.get("/debug/vars")
async def debug_vars(request: Request):
    mark(request, "debug")
    s = sess_of(request)
    resp = JSONResponse({
        "cmdline": ["/app/server", "-env=production"],
        "memstats": {"Alloc": 4831928, "Sys": 71303168},
        "env": {"DATABASE_URL": await honeytoken("db_connection_string", s, "/debug/vars"),
                "JWT_SECRET": await honeytoken("jwt", s, "/debug/vars")},
    })
    apply_variant_headers(resp, "/debug")
    return resp


@app.get("/actuator/env")
async def actuator_env(request: Request):
    mark(request, "debug")
    s = sess_of(request)
    aws_secret = (await aws_pair_honeytoken(s, "/actuator/env"))["aws_secret_access_key"]
    resp = JSONResponse({
        "activeProfiles": ["production"],
        "propertySources": [
            {"name": "applicationConfig", "properties": {
                "spring.datasource.password": {"value": await honeytoken("db_connection_string", s, "/actuator/env")},
                "aws.secretKey": {"value": aws_secret},
            }},
        ],
    })
    apply_variant_headers(resp, "/actuator/env")
    return resp


@app.get("/actuator/health")
async def actuator_health(request: Request):
    mark(request, "debug")
    resp = JSONResponse({"status": "UP", "components": {"db": {"status": "UP"}, "diskSpace": {"status": "UP"}}})
    apply_variant_headers(resp, "/actuator/health")
    return resp


@app.get("/phpinfo.php")
@app.get("/info.php")
@app.get("/_profiler/phpinfo")
@app.get("/app_dev.php/_profiler/phpinfo")
async def phpinfo(request: Request):
    mark(request, "debug")
    s = sess_of(request)
    db_url = await honeytoken("db_connection_string", s, request.url.path)
    body = f"""<!doctype html><html><head><title>phpinfo()</title></head>
<body><h1>PHP Version 7.2.24</h1>
<table>
<tr><td>System</td><td>Linux portal 5.15.0 x86_64</td></tr>
<tr><td>Server API</td><td>FPM/FastCGI</td></tr>
<tr><td>DOCUMENT_ROOT</td><td>/var/www/html/public</td></tr>
<tr><td>APP_ENV</td><td>production</td></tr>
<tr><td>DATABASE_URL</td><td>{html.escape(db_url)}</td></tr>
</table></body></html>"""
    resp = HTMLResponse(body)
    resp.headers["Server"] = "Apache/2.4.29 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.2.24"
    return resp


@app.get("/.well-known/security.txt")
async def security_txt(request: Request):
    # Known limitation (SPEC §5): "log any mail received" needs an actual mail
    # server, which is out of scope for this service. The fetch itself is
    # still logged as a normal `request` event (route_kind=admin); a unique
    # per-visit alias would add no signal without mail infra behind it to
    # receive and correlate against.
    mark(request, "admin")
    body = (
        "Contact: mailto:security@http-bait.example\n"
        "Expires: 2027-01-01T00:00:00.000Z\n"
        "Preferred-Languages: en\n"
    )
    return PlainTextResponse(body, media_type="text/plain")


@app.post("/graphql")
@app.post("/api/graphql")
@app.post("/graphql/api")
@app.post("/api/gql")
async def graphql(request: Request):
    mark(request, "graphql")
    body = request.state.body
    parsed = True
    try:
        query = json.loads(body or b"{}").get("query", "")
        if not isinstance(query, str):
            query = ""
    except Exception:
        # A body that isn't JSON was previously logged raw, which made this the
        # one route that retained arbitrary POST content verbatim regardless of
        # what was in it. Record its shape and let the middleware's own excerpt
        # (already credential-redacted) be the only copy.
        query = ""
        parsed = False
    await alog({"event": "graphql_query", "query": _redact_credential_literals(query)[:4000],
                "parsed": parsed, "body_len": len(body),
                "ip": request.headers.get("x-forwarded-for", "").split(",")[0].strip()})
    return JSONResponse({"errors": [{"message": "introspection is disabled in this environment"}]}, status_code=400)


# --------------------------------------------------------------------------- #
# 4.4 Landing page(s) — leaked-key-in-page lure + fake-version banner.
#
# "/" rotates through all three variants over time (SPEC §4.3's original
# design) — useful for a long-running single-page comparison, but it means
# at any given moment only ONE variant is actually live, confounding "which
# fake version draws more follow-up" with "what else was happening on the
# internet that week". /app, /site, and /legacy (2026-07 addition) each pin
# ONE variant permanently, so all three run simultaneously and are directly
# comparable in the same window; "/" is left rotating, unchanged, so its
# existing multi-week timeline isn't disrupted.
# --------------------------------------------------------------------------- #
def _render_landing_html(variant: str, api_key: str) -> str:
    return f"""<!doctype html><html><head><title>Portal</title>
{VARIANTS[variant]['meta']}
</head><body>
<h1>Welcome</h1>
<p>Sign in to access your dashboard.</p>
<script>
  window.__CONFIG__ = {{ mapsApiKey: "{api_key}", env: "production" }};
</script>
</body></html>"""


async def _landing_page(request: Request, path: str) -> HTMLResponse:
    # cve-signal, not catch-all: this page's job is the fake-version banner
    # (SPEC §4.3) as much as the leaked-key lure below.
    mark(request, "cve-signal")
    s = sess_of(request)
    # Known limitation (SPEC §5): a Maps key's "use" is a call to Google's own
    # API, which we cannot intercept — same bare-key limitation as the AWS/
    # GitHub/Stripe/OpenAI kinds. Reuse detection for this one relies solely
    # on the value reappearing elsewhere (analyze.py's circumstantial-reuse
    # scan), same as any other non-catcher-embedded kind.
    api_key = await honeytoken("google_api_key", s, path)
    variant = current_variant_name(path)
    resp = HTMLResponse(_render_landing_html(variant, api_key))
    apply_variant_headers(resp, path)
    return resp


@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    return await _landing_page(request, "/")


@app.get("/app", response_class=HTMLResponse)
async def landing_app(request: Request):
    return await _landing_page(request, "/app")


@app.get("/site", response_class=HTMLResponse)
async def landing_site(request: Request):
    return await _landing_page(request, "/site")


@app.get("/legacy", response_class=HTMLResponse)
async def landing_legacy(request: Request):
    return await _landing_page(request, "/legacy")


# --------------------------------------------------------------------------- #
# 4.5 robots.txt / sitemap.xml — LIST the bait paths (inverse of a real robots.txt)
# --------------------------------------------------------------------------- #
BAIT_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.git/index", "/config.json", "/backup.sql",
    "/.aws/credentials", "/wp-config.php", "/docker-compose.yml", "/id_rsa", "/.ssh/id_rsa",
    "/.vscode/sftp.json",
    "/admin", "/admin/login", "/api/keys", "/debug", "/debug/vars",
    "/actuator/env", "/actuator/health", "/.well-known/security.txt", "/graphql",
    "/api/graphql", "/graphql/api", "/api/gql",
    "/wp-login.php", "/phpmyadmin/", "/manager/html", "/adminer.php", "/phpinfo.php",
    "/openapi.json", "/.well-known/ai-plugin.json",
    "/app", "/site", "/legacy",
]


@app.get("/robots.txt")
async def robots_txt(request: Request):
    mark(request, "catch-all")
    lines = ["User-agent: *"] + [f"Allow: {p}" for p in BAIT_PATHS] + ["Sitemap: /sitemap.xml"]
    return PlainTextResponse("\n".join(lines) + "\n")


@app.get("/sitemap.xml")
async def sitemap_xml(request: Request):
    mark(request, "catch-all")
    urls = "".join(f"<url><loc>{CANARY_BASE}{p}</loc></url>" for p in BAIT_PATHS)
    body = f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>'
    return Response(body, media_type="application/xml")


# --------------------------------------------------------------------------- #
# Honeytoken trigger catcher (SPEC §5) — a hit here proves "use", not just issuance.
# --------------------------------------------------------------------------- #
@app.api_route("/x/{token}", methods=["GET", "POST"])
async def trigger_catcher(request: Request, token: str):
    """A hit here proves "use" only if the token was one we issued.

    /x/ is a public path like any other, so scanners walk it with ids that were
    never minted. Those used to be logged as honeytoken_triggered exactly like
    a genuine callback, which inflates the one metric that is supposed to be
    unambiguous. Confirmed triggers and unissued probes are now separate
    events; analyze.py counts only the former as use.
    """
    mark(request, "catch-all")
    ident = token.lower()
    issued = (ident in _issued_token_ids
              or _issued_token_prefixes.get(ident[:TOKEN_PREFIX_LEN]) is not None)
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
        request.client.host if request.client else "")
    await alog({
        "event": "honeytoken_triggered" if issued else "catcher_probe_unissued",
        "token": token[:64],
        "index_size": len(_issued_token_ids),
        "index_evictions": _issued_token_evictions,
        "ip": ip,
        "ua": _cap(request.headers.get("user-agent", ""), UA_CAP),
    })
    return PlainTextResponse("ok")


# --------------------------------------------------------------------------- #
# Catch-all 404 — path scanning without a hit is itself signal (SPEC §4.5).
# Registered last so every route above takes precedence.
# --------------------------------------------------------------------------- #
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def catch_all(request: Request, full_path: str):
    mark(request, "catch-all")
    return PlainTextResponse("Not Found", status_code=404)
