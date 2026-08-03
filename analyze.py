"""
Summarize http-bait honeypot activity from one or more raw JSONL logs.

Everything a findings report should cite is printed by this script. That was not
previously true: the route and status distributions were never computed here at
all, and the "retroactive scan" behind the headline CVE count of the first
writeup had no implementation, so a reader who ran the tool got a different
report from the one the document described. Fill in FINDINGS.md from a labelled
section below rather than from anything hand-counted.

Usage:
  python analyze.py data/logs/http_events.jsonl
  python analyze.py 'data/logs/http_events*.jsonl' --rescan
  python analyze.py data/logs/http_events.jsonl --baseline .../http_events.prev.jsonl
  python analyze.py data/logs/http_events.jsonl --exclude-ip 203.0.113.7

--rescan re-applies the CURRENT signature set to retained request records,
which is the only way to compare traffic that arrived before a signature
existed against traffic that arrived after. Counts differ from the live ones by
design; both are printed, and each signature's ship date is printed beside it.

--enrich and --rdns disclose the visitor list to a third party and are off by
default. Third-party IPs print truncated to /24 unless --full-ips is passed.

Stdlib only. Detection tables come from app/signatures.py, shared with the
running service so the analyzer cannot drift away from what actually served the
traffic.
"""
import argparse
import hashlib
import json
import os
import re
import socket
import sys
from collections import Counter, defaultdict
from datetime import datetime
from glob import glob
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "app"))
from signatures import (  # noqa: E402
    CVE_SIGNATURES,
    INDIRECT_COMMAND_RE,
    ROOT_ROTATION_PERIOD_DAYS,
    ROOT_VARIANT_CYCLE,
    ROUTE_VARIANT,
    RSC_PROTOTYPE_RE,
    TOKEN_ID_LEN,
    TOOL_INVOCATION_SIGNATURES,
    root_variant_at,
)

socket.setdefaulttimeout(2.0)

CLOUD = {
    "amazonaws": "AWS", "google": "GCP", "googleusercontent": "GCP", "azure": "Azure",
    "microsoft": "Azure", "digitalocean": "DigitalOcean", "hetzner": "Hetzner",
    "ovh": "OVH", "linode": "Linode", "akamai": "Akamai/Linode", "scaleway": "Scaleway",
    "vultr": "Vultr", "oracle": "Oracle", "cloudflare": "Cloudflare", "fastly": "Fastly",
}

# Matches app/formatters.SERVED_TOKEN_LEN's minimum. Imported rather than
# redeclared where possible; kept here as a fallback so the analyzer still runs
# against a log copied somewhere without the app/ directory beside it.
try:
    from formatters import MIN_SERVED_TOKEN_LEN as TOKEN_PREFIX_LEN  # noqa: E402
except Exception:  # pragma: no cover - only when app/ is absent
    TOKEN_PREFIX_LEN = 12


def build_parser():
    p = argparse.ArgumentParser(description="Summarize HTTP honeypot activity.")
    p.add_argument("paths", nargs="*", default=["data/logs/http_events.jsonl"],
                   help="One or more JSONL files or globs. Rotated logs sort "
                        "chronologically, so 'http_events*.jsonl' works.")
    p.add_argument("--baseline", help="Older JSONL snapshot; report only appended/new events")
    p.add_argument("--rescan", action="store_true",
                   help="Re-apply the CURRENT signature set to retained request "
                        "records, in addition to counting what fired live")
    p.add_argument("--window", help="Only consider records whose `window` field matches")
    p.add_argument("--exclude-ip", action="append", default=[],
                   help="Drop records from this IP (repeatable). Use for self-test traffic.")
    p.add_argument("--exclude-ua", action="append", default=[],
                   help="Drop records whose User-Agent contains this substring (repeatable)")
    p.add_argument("--full-ips", action="store_true",
                   help="Print full addresses instead of /24-truncated ones")
    p.add_argument("--enrich", action="store_true",
                   help="Send observed IPs to ip-api.com for ASN/geo enrichment "
                        "(third-party disclosure of your visitor list; off by default)")
    p.add_argument("--rdns", action="store_true",
                   help="Reverse-DNS each observed IP (discloses the visitor list to "
                        "your resolver chain; off by default)")
    return p


ARGS = argparse.Namespace(rdns=False, enrich=False, full_ips=False)


def variant_for(path: str, ts_iso: str) -> str:
    if path == "/":
        try:
            return root_variant_at(datetime.fromisoformat(ts_iso))
        except Exception:
            return "unknown"
    return ROUTE_VARIANT.get(path, "unknown")


def truncate_ip(ip: str) -> str:
    """Third-party addresses print as /24 by default.

    An earlier writeup stated this as a property of the published data while
    nothing implemented it, so it was true only because that document happened
    to contain no addresses. It is a property of the tool now.
    """
    ip = (ip or "").split(",")[0].strip()
    if ARGS.full_ips or not ip:
        return ip
    if ip.count(".") == 3:
        return ".".join(ip.split(".")[:3]) + ".0/24"
    if ":" in ip:                       # IPv6 -> /48
        return ":".join(ip.split(":")[:3]) + "::/48"
    return ip


def ip_of(record) -> str:
    """First X-Forwarded-For hop, matching client_ip() in app/main.py."""
    return (record.get("ip") or "").split(",")[0].strip()


def classify_ip(ip):
    # rDNS is a lookup per observed IP, which hands the honeypot's full visitor
    # list to whatever resolver chain is in front of you. Opt-in via --rdns.
    if not ip:
        return "unknown"
    ip = ip.split(",")[0].strip()
    if not ARGS.rdns:
        return "no-rdns"
    try:
        ptr = socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return "no-ptr"
    for sub, name in CLOUD.items():
        if sub in ptr:
            return f"cloud:{name}"
    return f"other:{ptr.split('.')[-2] if '.' in ptr else ptr}"


def enrich(ips):
    import urllib.request
    out = {}
    ips = [i.split(",")[0].strip() for i in ips if i]
    for i in range(0, len(ips), 95):
        batch = [{"query": q, "fields": "query,as,org,country,hosting,proxy,mobile"} for q in ips[i:i + 95]]
        try:
            req = urllib.request.Request("https://ip-api.com/batch",
                                         data=json.dumps(batch).encode(),
                                         headers={"Content-Type": "application/json"})
            for r in json.load(urllib.request.urlopen(req, timeout=10)):
                flags = ",".join(f for f in ("hosting", "proxy", "mobile") if r.get(f))
                out[r.get("query")] = f"{r.get('as','')} | {r.get('country','')}{' | '+flags if flags else ''}"
        except Exception as e:
            print(f"  (enrich failed: {e})", file=sys.stderr)
            break
    return out


def first_index(paths, needle) -> int:
    return next(i for i, p in enumerate(paths) if needle in p)


def cadence(gaps):
    if not gaps:
        return "single-shot"
    g = sorted(gaps)[len(gaps) // 2]
    if g < 0.3:
        return "scanner-burst"
    if g <= 20:
        return "paced-automation"
    return "slow/interactive"


def request_text(request: dict) -> dict:
    """The haystacks a signature scans, rebuilt from a stored request record.

    Mirrors check_attack_patterns() in app/main.py. Header values that were
    redacted at write time stay redacted here; a rescan can only ever see what
    was retained, which is one of the reasons a rescan count is a lower bound.
    """
    path = request.get("path", "")
    query = request.get("query", "")
    body = request.get("body_excerpt", "")
    decoded = unquote_plus(body)
    headers = request.get("headers", {}) or {}
    content_type = headers.get("content-type", "")
    return {
        "path": path + "?" + query,
        "content-type": content_type,
        "headers": "\n".join(str(v) for v in headers.values()),
        "body": body + "\n" + decoded,
        "any": " ".join([path, query, body, decoded, content_type]),
    }


def command_attempts(request):
    haystacks = request_text(request)
    text = "\n".join([haystacks["path"], haystacks["body"], haystacks["headers"]])
    out = []
    for tool, pattern in TOOL_INVOCATION_SIGNATURES:
        match = pattern.search(text)
        if match:
            command = " ".join(match.group("command").split())[:200]
            out.append((tool, command))
    if INDIRECT_COMMAND_RE.search(text):
        out.append(("node:child_process.exec", "<indirect cmd variable>"))
    return out


def rsc_probe(request):
    headers = request.get("headers", {}) or {}
    return bool(headers.get("next-action") or headers.get("x-nextjs-server-actions")
                or RSC_PROTOTYPE_RE.search(unquote_plus(request.get("body_excerpt", ""))))


def load_rows(paths):
    """Read every path, tolerating the torn last line of a live file.

    pull-telemetry.sh rsyncs a file the service is actively appending to, so a
    truncated final record is the normal case. An unguarded json.loads aborted
    the entire report on one.
    """
    rows, malformed, files = [], 0, []
    for pattern in paths:
        matched = sorted(glob(pattern)) or ([pattern] if os.path.exists(pattern) else [])
        if not matched:
            print(f"no such file: {pattern}", file=sys.stderr)
        files.extend(matched)
    for path in files:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    malformed += 1
    return rows, malformed, files


def apply_filters(rows):
    """Drop self-test and out-of-window records, and say how many were dropped.

    "Self-test traffic excluded from every figure" was once claimed with no
    exclusion mechanism behind it, so it was done by hand and could not be
    reproduced by anyone reading the document. Record the flags you used.
    """
    kept, dropped_ip, dropped_ua, dropped_window = [], 0, 0, 0
    for r in rows:
        if ARGS.window and r.get("window") not in (None, ARGS.window):
            dropped_window += 1
            continue
        ip = ip_of(r)
        if ip and ip in set(ARGS.exclude_ip):
            dropped_ip += 1
            continue
        ua = r.get("ua") or ""
        if any(pat in ua for pat in ARGS.exclude_ua):
            dropped_ua += 1
            continue
        kept.append(r)
    return kept, {"ip": dropped_ip, "ua": dropped_ua, "window": dropped_window}


def print_cve_table(title, per_cve, since_by_cve):
    print(f"\n{title}")
    if not per_cve:
        print("   (none)")
        return
    print(f"   {'cve_id':<22} {'hits':>5} {'IPs':>5}  {'first seen':<20} signature since")
    for cve, info in sorted(per_cve.items(), key=lambda kv: -kv[1]["hits"]):
        print(f"   {cve:<22} {info['hits']:>5} {len(info['ips']):>5}  "
              f"{info['first']:<20} {since_by_cve.get(cve, '?')}")


def main():
    global ARGS
    ARGS = build_parser().parse_args()

    rows, malformed, files = load_rows(ARGS.paths)
    if not files:
        return 1
    if ARGS.baseline:
        baseline, _, base_files = load_rows([ARGS.baseline])
        if not base_files:
            return 1
        if rows[:len(baseline)] == baseline:
            rows = rows[len(baseline):]
            print(f"delta mode: {len(rows)} events appended after {ARGS.baseline}")
        else:
            cutoff = max((r.get("ts", "") for r in baseline), default="")
            rows = [r for r in rows if r.get("ts", "") > cutoff]
            print(f"delta mode: snapshots diverged; using timestamp cutoff > {cutoff}")

    rows, dropped = apply_filters(rows)

    reqs = [r for r in rows if r.get("event") == "request"]
    issued = [r for r in rows if r.get("event") == "honeytoken_issued"]
    triggered = [r for r in rows if r.get("event") == "honeytoken_triggered"]
    unissued_probes = [r for r in rows if r.get("event") == "catcher_probe_unissued"]
    reuse_observed = [r for r in rows if r.get("event") == "honeytoken_reuse_observed"]
    evictions = [r for r in rows if r.get("event") == "issued_token_index_evicted"]
    cve_hits = [r for r in rows if r.get("event") == "cve_pattern_match"]
    graphql_qs = [r for r in rows if r.get("event") == "graphql_query"]
    logged_rsc = [r for r in rows if r.get("event") == "rsc_action_probe"]
    logged_tools = [r for r in rows if r.get("event") in
                    ("tool_invocation_attempt", "api_tool_call_attempt")]

    # --- provenance ----------------------------------------------------------
    print("=== http-bait analysis ===")
    print(f"files: {', '.join(os.path.basename(f) for f in files)}")
    ts_all = sorted(r.get("ts", "") for r in rows if r.get("ts"))
    if ts_all:
        print(f"window: {ts_all[0]} -> {ts_all[-1]}")
    labels = Counter(r.get("window", "unlabelled") for r in rows)
    print(f"window labels: {dict(labels)}")
    print(f"requests: {len(reqs)}   total events: {len(rows)}")
    if malformed:
        print(f"malformed lines skipped: {malformed} (normal for a live/rsynced file)")
    if any(dropped.values()):
        print(f"excluded: {dropped['ip']} by --exclude-ip, {dropped['ua']} by "
              f"--exclude-ua, {dropped['window']} by --window")
    else:
        print("excluded: none (pass --exclude-ip/--exclude-ua for self-test traffic)")

    ips = Counter(ip_of(r) for r in reqs)
    ips.pop("", None)
    print(f"distinct IPs: {len(ips)}")

    # --- route and status distributions --------------------------------------
    # A findings report quotes both of these. Neither was computed before.
    print("\nroute_kind distribution:")
    for kind, n in Counter(r.get("route_kind", "?") for r in reqs).most_common():
        print(f"   {n:>6}  {kind}")
    print("\nstatus_served distribution:")
    for status, n in Counter(r.get("status_served", 0) for r in reqs).most_common():
        print(f"   {n:>6}  {status}")
    print("\nmethod distribution:")
    for method, n in Counter(r.get("method", "?") for r in reqs).most_common():
        print(f"   {n:>6}  {method}")

    # --- per-session (ip+ua) sequence & cadence ------------------------------
    sess = defaultdict(list)
    for r in reqs:
        sess[f"{(r.get('ip') or '').split(',')[0].strip()}|{r.get('ua','')}"].append(r)

    sess_rows = []
    for _key, evs in sess.items():
        evs.sort(key=lambda r: r.get("ts", ""))
        ts = []
        for r in evs:
            try:
                ts.append(datetime.fromisoformat(r["ts"]))
            except Exception:
                pass
        gaps = [(ts[i + 1] - ts[i]).total_seconds() for i in range(len(ts) - 1)] if len(ts) > 1 else []
        dur = (ts[-1] - ts[0]).total_seconds() if len(ts) > 1 else 0.0
        sess_rows.append({"ip": evs[0].get("ip", ""), "ua": (evs[0].get("ua") or "")[:32],
                          "n": len(evs), "dur": dur, "cadence": cadence(gaps),
                          "paths": [r.get("path", "") for r in evs]})

    print("\nper-session request sequence (top 30 by request count):")
    print(f"   {'ip':<20} {'ua':<34} {'n':>4} {'dur(s)':>8} {'cadence':<16} first paths")
    for r in sorted(sess_rows, key=lambda r: -r["n"])[:30]:
        print(f"   {truncate_ip(r['ip']):<20} {r['ua']:<34} {r['n']:>4} {r['dur']:>8.1f} "
              f"{r['cadence']:<16} {r['paths'][:8]}")

    print("\ncadence distribution:")
    for c, n in Counter(r["cadence"] for r in sess_rows).most_common():
        print(f"   {n:>6}  {c}")

    # --- secret-file hit ordering --------------------------------------------
    print("\nsecret-file path hit counts (route_kind=secret-file):")
    for p, n in Counter(r.get("path", "") for r in reqs
                        if r.get("route_kind") == "secret-file").most_common():
        print(f"   {n:>6}  {p}")

    for a, b in [(".git/HEAD", ".git/config"), (".env", "wp-config.php")]:
        both = [r for r in sess_rows if any(a in p for p in r["paths"]) and any(b in p for p in r["paths"])]
        a_first = sum(1 for r in both
                      if first_index(r["paths"], a) < first_index(r["paths"], b))
        print(f"   sessions hitting both '{a}' & '{b}': {len(both)} "
              f"({a}-first: {a_first}, {b}-first: {len(both)-a_first})")

    # --- CVE: live counts, then optional rescan ------------------------------
    since_by_cve = {cve: since for cve, _pat, _where, since in CVE_SIGNATURES}

    live = defaultdict(lambda: {"hits": 0, "ips": set(), "first": ""})
    for r in cve_hits:
        cve = r.get("cve_id", "?")
        info = live[cve]
        info["hits"] += 1
        info["ips"].add(ip_of(r))
        ts = r.get("ts", "")
        info["first"] = min(info["first"], ts) if info["first"] else ts
    print_cve_table("CVE hits — LIVE (what the deployed signatures flagged at the time):",
                    live, since_by_cve)

    print("\ncve_pattern_match by advertised-version variant:")
    for v, n in Counter(variant_for(r.get("path", ""), r.get("ts", ""))
                        for r in cve_hits).most_common():
        print(f"   {n:>6}  {v}")

    if ARGS.rescan:
        # The "retroactive scan" a findings report should cite. It had no
        # implementation: the old code only tallied cve_pattern_match events
        # that the service had already written, so it could never surface
        # traffic that predated a signature.
        rescan = defaultdict(lambda: {"hits": 0, "ips": set(), "first": ""})
        for r in reqs:
            haystacks = request_text(r)
            for cve, pattern, where, _since in CVE_SIGNATURES:
                if pattern.search(haystacks.get(where, "")):
                    info = rescan[cve]
                    info["hits"] += 1
                    info["ips"].add(ip_of(r))
                    ts = r.get("ts", "")
                    info["first"] = min(info["first"], ts) if info["first"] else ts
        print_cve_table("CVE hits — RESCAN (current signatures re-applied to retained records):",
                        rescan, since_by_cve)
        print("   NOTE: a rescan sees only what was retained. Request bodies are")
        print("   capped and only a 4KB excerpt is stored, and sensitive headers")
        print("   are redacted at write time, so this is a lower bound.")
    else:
        print("\n(pass --rescan to re-apply current signatures to retained records)")

    # --- honeytoken issuance, triggers, reuse --------------------------------
    print(f"\nhoneytoken_issued: {len(issued)}")
    print(f"confirmed triggers (issued ids only): {len(triggered)}")
    print(f"unissued /x/ probes (NOT proof of use): {len(unissued_probes)}")
    if evictions:
        print(f"   WARNING: {len(evictions)} index eviction(s) recorded — tokens issued")
        print("   before an eviction cannot be matched, so any null below is bounded by it.")

    print("\nissuance by kind:")
    for k, n in Counter(r.get("kind", "?") for r in issued).most_common():
        print(f"   {n:>6}  {k}")

    issued_by_tok = {r.get("token"): r for r in issued if r.get("token")}
    trig_kinds = Counter(issued_by_tok.get(r.get("token"), {}).get("kind", "?") for r in triggered)
    if trig_kinds:
        print("\nconfirmed triggers by kind:")
        for k, n in trig_kinds.most_common():
            print(f"   {n:>6}  {k}")

    # --- circumstantial reuse ------------------------------------------------
    # Bare-key kinds have no callback, so reappearance elsewhere is the only
    # available signal (SPEC §5). Two kinds serve a 12-char prefix rather than
    # the full 16-char id; matching only the full id here meant a replayed
    # database password could never be found, across ~14% of all issuances.
    # Direction matters here for the same reason it does in the service:
    # scanning every issued token against every request is O(issued x requests)
    # with both sides growing, which is minutes-to-hours on a multi-week log.
    # Pull token-shaped candidates out of each request and look them up.
    prefix_index = {}
    for tok in issued_by_tok:
        prefix_index.setdefault(tok[:TOKEN_PREFIX_LEN], tok)

    hex_run_re = re.compile(r"[0-9a-f]{%d,}" % TOKEN_PREFIX_LEN)
    reuse_hits = []
    for r in reqs:
        blob = " ".join([json.dumps(r.get("headers", {})),
                         r.get("body_excerpt", ""), r.get("query", "")]).lower()
        ts, path = r.get("ts", ""), r.get("path", "")
        seen = {}
        for run in hex_run_re.finditer(blob):
            text = run.group(0)
            # A served value may repeat the id to reach a required width
            # (formatters._hex_pad), so it can start at any offset in a run.
            for i in range(len(text) - TOKEN_PREFIX_LEN + 1):
                full = text[i:i + TOKEN_ID_LEN]
                if len(full) == TOKEN_ID_LEN and full in issued_by_tok:
                    seen.setdefault(full, "full")
                    continue
                tok = prefix_index.get(text[i:i + TOKEN_PREFIX_LEN])
                if tok is not None:
                    seen.setdefault(tok, "prefix")
        for tok, form in seen.items():
            issue = issued_by_tok[tok]
            if ts <= issue.get("ts", "") or path == issue.get("route"):
                continue
            reuse_hits.append({"token": tok, "kind": issue.get("kind"),
                               "issued_route": issue.get("route"), "seen_path": path,
                               "seen_ts": ts, "matched": form,
                               "seen_ip": ip_of(r)})

    print(f"\ncircumstantial reuse hits (issued value reappearing later elsewhere): {len(reuse_hits)}")
    by_form = Counter(h["matched"] for h in reuse_hits)
    if by_form:
        print(f"   matched by form: {dict(by_form)}")
    for h in reuse_hits[:10]:
        print(f"   {h['kind']:<22} issued@{h['issued_route']:<20} -> seen@{h['seen_path']} "
              f"({h['seen_ts']}, {h['matched']}, {truncate_ip(h['seen_ip'])})")
    print(f"runtime reuse events recorded by the service: {len(reuse_observed)}")
    blind = [r for r in reuse_observed if r.get("body_available") is False]
    if blind:
        print(f"   of which detected without a body (rate-limited): {len(blind)}")

    # --- credential submissions ----------------------------------------------
    creds = [r for r in reqs if "creds_submitted" in r]
    print(f"\ncredential submissions: {len(creds)}")
    print("   by path:", dict(Counter(r.get("path", "") for r in creds)))
    print("   by source:", dict(Counter(r["creds_submitted"].get("source", "?") for r in creds)))
    # Credentials sprayed at a honeypot login are frequently real credentials
    # stolen from someone else, so this reports only presence and shape. Very
    # old records (before main.py stopped retaining values) may still hold raw
    # pairs on disk; count them but never print them.
    legacy_raw = sum(1 for r in creds
                     if "user" in r["creds_submitted"] or "pass" in r["creds_submitted"])
    if legacy_raw:
        print(f"   {legacy_raw:>6}  legacy records with raw values on disk (not shown)")
    metadata = Counter(
        (r["creds_submitted"].get("source", "body"),
         r["creds_submitted"].get("user_present", False),
         r["creds_submitted"].get("pass_present", False))
        for r in creds if "user_present" in r["creds_submitted"])
    for (source, has_user, has_pass), n in metadata.most_common():
        print(f"   {n:>6}  source={source} user_present={has_user} pass_present={has_pass}")

    # --- graphql -------------------------------------------------------------
    print(f"\ngraphql queries logged: {len(graphql_qs)}")
    for r in graphql_qs[:5]:
        print(f"   {r.get('query','')[:120]}")

    # --- tool/agent signals --------------------------------------------------
    raw_rsc = [r for r in reqs if rsc_probe(r)]
    retained_rsc = [r for r in raw_rsc
                    if RSC_PROTOTYPE_RE.search(unquote_plus(r.get("body_excerpt", "")))]
    raw_tools = []
    for r in reqs:
        for tool, command in command_attempts(r):
            raw_tools.append({"ts": r.get("ts", ""), "ip": ip_of(r),
                              "path": r.get("path", ""), "tool": tool, "command": command,
                              "command_hash": hashlib.sha256(command.encode()).hexdigest()[:16]})

    print("\nagent/tool-use signals:")
    print(f"   RSC Server Action probes: {len(raw_rsc)} request(s), "
          f"{len({(r.get('ip') or '') for r in raw_rsc})} IP(s)")
    print(f"   React2Shell prototype-chain payload retained: {len(retained_rsc)}")
    print(f"   derived rsc_action_probe events: {len(logged_rsc)}")
    print(f"   command/tool invocations found in raw requests: {len(raw_tools)}")
    print(f"   derived tool/API call events: {len(logged_tools)}")
    for r in raw_tools[:20]:
        print(f"   {r['ts']} {truncate_ip(r['ip']):<20} {r['tool']:<30} "
              f"{r['command']!r} sha256:{r['command_hash']}")

    # The agent-bait surface: a client that fetched a machine-readable API
    # description and then called an operation it advertised.
    discovery_paths = {"/openapi.json", "/swagger.json", "/.well-known/ai-plugin.json"}
    tool_paths = {"/api/v1/system/status", "/api/v1/jobs/run"}
    discoveries, calls = defaultdict(list), defaultdict(list)
    for r in reqs:
        key = (ip_of(r), r.get("ua", ""))
        if r.get("path") in discovery_paths:
            discoveries[key].append(r)
        if r.get("path") in tool_paths:
            calls[key].append(r)
    print(f"   schema-discovery requests: {sum(len(v) for v in discoveries.values())}")
    print(f"   advertised-operation calls: {sum(len(v) for v in calls.values())}")
    chains = []
    for key in discoveries.keys() & calls.keys():
        for d in discoveries[key]:
            later = next((c for c in calls[key] if c.get("ts", "") >= d.get("ts", "")), None)
            if later:
                chains.append((key, d, later))
                break
    print(f"   schema-discovery -> advertised-operation chains: {len(chains)}")
    for (ip, ua), d, c in chains[:10]:
        print(f"   {truncate_ip(ip):<20} {d.get('path')} -> {c.get('method')} {c.get('path')} "
              f"({ua[:40]})")

    # --- IP classification ---------------------------------------------------
    print("\nIP classification (top 50):")
    geo = enrich(list(ips)) if ARGS.enrich else {}
    for ip, n in ips.most_common(50):
        extra = f"  [{geo[ip]}]" if geo.get(ip) else ""
        print(f"   {n:>6}  {truncate_ip(ip):<22} {classify_ip(ip)}{extra}")

    # --- catch-all -----------------------------------------------------------
    print("\ntop catch-all (404) paths probed but not baited:")
    catch = Counter(r.get("path", "") for r in reqs
                    if r.get("route_kind") == "catch-all" and r.get("status_served") == 404)
    for p, n in catch.most_common(30):
        print(f"   {n:>6}  {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
