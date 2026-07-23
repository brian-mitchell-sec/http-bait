"""
Summarize http-bait honeypot activity: per-IP/session request sequences, secret-file
hit ordering, CVE-pattern-match rates by advertised version, honeytoken triggers,
admin/login credential-stuffing, and IP classification.

Usage:
  python http-bait/analyze.py http-bait/data/logs/http_events.jsonl
  python http-bait/analyze.py http-bait/data/logs/http_events.jsonl --baseline http-bait/data/logs/http_events.prev.jsonl
  python http-bait/analyze.py http-bait/data/logs/http_events.jsonl --enrich

--enrich makes a live call to ip-api.com (sends observed IPs to a 3rd party); off by default.
"""
import argparse, hashlib, json, os, re, socket, sys
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import unquote_plus

socket.setdefaulttimeout(2.0)
PARSER = argparse.ArgumentParser(description="Summarize HTTP honeypot activity.")
PARSER.add_argument("path", nargs="?", default="http-bait/data/logs/http_events.jsonl")
PARSER.add_argument("--baseline", help="Older JSONL snapshot; report only appended/new events")
PARSER.add_argument("--enrich", action="store_true",
                    help="Send observed IPs to ip-api.com for ASN/geo enrichment "
                         "(third-party disclosure of your visitor list; off by default)")
PARSER.add_argument("--rdns", action="store_true",
                    help="Reverse-DNS each observed IP (discloses the visitor list to "
                         "your resolver chain; off by default)")
ARGS = PARSER.parse_args()
PATH = ARGS.path
ENRICH = ARGS.enrich
RDNS = ARGS.rdns

CLOUD = {
    "amazonaws": "AWS", "google": "GCP", "googleusercontent": "GCP", "azure": "Azure",
    "microsoft": "Azure", "digitalocean": "DigitalOcean", "hetzner": "Hetzner",
    "ovh": "OVH", "linode": "Linode", "akamai": "Akamai/Linode", "scaleway": "Scaleway",
    "vultr": "Vultr", "oracle": "Oracle", "cloudflare": "Cloudflare", "fastly": "Fastly",
}

# Route -> CVE-signaling variant (must match ROUTE_VARIANT in app/main.py).
# "/debug"/"/debug/vars" carry no banner by design (see main.py) so they're
# absent here too. "/" rotates over time — see root_variant_at() below.
ROUTE_VARIANT = {
    "/wp-config.php": "wordpress",
    "/admin": "struts", "/admin/login": "struts",
    "/actuator/env": "spring", "/actuator/health": "spring",
}
ROOT_VARIANT_CYCLE = ["wordpress", "struts", "spring"]  # must match main.py
ROOT_ROTATION_PERIOD_DAYS = 14


def root_variant_at(ts_iso: str) -> str:
    try:
        dt = datetime.fromisoformat(ts_iso)
    except Exception:
        return "unknown"
    epoch_days = int(dt.timestamp() // 86400)
    idx = (epoch_days // ROOT_ROTATION_PERIOD_DAYS) % len(ROOT_VARIANT_CYCLE)
    return ROOT_VARIANT_CYCLE[idx]


def variant_for(path: str, ts_iso: str) -> str:
    if path == "/":
        return root_variant_at(ts_iso)
    return ROUTE_VARIANT.get(path, "unknown")


def classify_ip(ip):
    # rDNS is a lookup per observed IP, which hands the honeypot's full visitor
    # list to whatever resolver chain is in front of you. Opt-in via --rdns.
    if not ip:
        return ("", "unknown")
    ip = ip.split(",")[0].strip()
    if not RDNS:
        return (ip, "no-rdns")
    try:
        ptr = socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return (ip, "no-ptr")
    for sub, name in CLOUD.items():
        if sub in ptr:
            return (ip, f"cloud:{name}")
    return (ip, f"other:{ptr.split('.')[-2] if '.' in ptr else ptr}")


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


def cadence(gaps):
    if not gaps:
        return "single-shot"
    g = sorted(gaps)[len(gaps) // 2]
    if g < 0.3:
        return "scanner-burst"
    if g <= 20:
        return "paced-automation"
    return "slow/interactive"


RSC_PROTOTYPE = re.compile(r"\$1:__proto__:then", re.I)
COMMAND_PATTERNS = [
    ("node:child_process.execSync",
     re.compile(r"execSync\(\s*(['\"])(?P<command>.{1,200}?)\1", re.I | re.S)),
    ("node:child_process.exec",
     re.compile(r"(?<!Sync)exec\(\s*(['\"])(?P<command>.{1,200}?)\1", re.I | re.S)),
    ("java:Runtime.exec",
     re.compile(r"Runtime\.getRuntime\(\)\.exec\(\s*(['\"])(?P<command>.{1,200}?)\1", re.I | re.S)),
]


def rsc_probe(request):
    headers = request.get("headers", {})
    return bool(headers.get("next-action") or headers.get("x-nextjs-server-actions")
                or RSC_PROTOTYPE.search(unquote_plus(request.get("body_excerpt", ""))))


def command_attempts(request):
    text = unquote_plus("\n".join([
        request.get("path", ""), request.get("query", ""),
        request.get("body_excerpt", ""),
        " ".join(request.get("headers", {}).values()),
    ]))
    out = []
    for tool, pattern in COMMAND_PATTERNS:
        match = pattern.search(text)
        if match:
            command = " ".join(match.group("command").split())[:200]
            out.append((tool, command))
    # Some observed payloads assign a command to a variable and later call
    # `cp.exec(cmd, ...)`; that is still an invocation attempt even when the
    # 4KB excerpt does not retain the earlier assignment.
    if re.search(r"\b(?:cp|child_process)\.exec\(\s*cmd\b", text, re.I):
        out.append(("node:child_process.exec", "<indirect cmd variable>"))
    return out


def load_rows(path):
    return [json.loads(line) for line in open(path) if line.strip()]


def main():
    if not os.path.exists(PATH):
        print(f"no such file: {PATH}")
        return
    rows = load_rows(PATH)
    if ARGS.baseline:
        if not os.path.exists(ARGS.baseline):
            print(f"no such baseline file: {ARGS.baseline}")
            return
        baseline = load_rows(ARGS.baseline)
        if rows[:len(baseline)] == baseline:
            rows = rows[len(baseline):]
            print(f"delta mode: {len(rows)} events appended after {ARGS.baseline}")
        else:
            cutoff = max((r.get("ts", "") for r in baseline), default="")
            rows = [r for r in rows if r.get("ts", "") > cutoff]
            print(f"delta mode: snapshots diverged; using timestamp cutoff > {cutoff}")
    reqs = [r for r in rows if r.get("event") == "request"]
    issued = [r for r in rows if r.get("event") == "honeytoken_issued"]
    triggered = [r for r in rows if r.get("event") == "honeytoken_triggered"]
    reuse_observed = [r for r in rows if r.get("event") == "honeytoken_reuse_observed"]
    cve_hits = [r for r in rows if r.get("event") == "cve_pattern_match"]
    graphql_qs = [r for r in rows if r.get("event") == "graphql_query"]
    logged_rsc = [r for r in rows if r.get("event") == "rsc_action_probe"]
    logged_tools = [r for r in rows if r.get("event") in
                    ("tool_invocation_attempt", "api_tool_call_attempt")]

    print(f"=== http-bait activity ({len(reqs)} requests, {len(rows)} total events) ===")

    ips = Counter(r.get("ip", "") for r in reqs)
    print(f"distinct IPs: {len(ips)}")

    # --- per-session (ip+ua) sequence & cadence -----------------------------------
    sess = defaultdict(list)
    for r in reqs:
        key = f"{r.get('ip','')}|{r.get('ua','')}"
        sess[key].append(r)

    sess_rows = []
    for key, evs in sess.items():
        evs.sort(key=lambda r: r.get("ts", ""))
        ts = []
        for r in evs:
            try:
                ts.append(datetime.fromisoformat(r["ts"]))
            except Exception:
                pass
        gaps = [(ts[i + 1] - ts[i]).total_seconds() for i in range(len(ts) - 1)] if len(ts) > 1 else []
        dur = (ts[-1] - ts[0]).total_seconds() if len(ts) > 1 else 0.0
        paths = [r.get("path", "") for r in evs]
        sess_rows.append({"ip": evs[0].get("ip", ""), "ua": evs[0].get("ua", "")[:32], "n": len(evs),
                          "dur": dur, "cadence": cadence(gaps), "paths": paths})

    print("\nper-session request sequence (top 30 by request count):")
    print(f"   {'ip':<18} {'ua':<34} {'n':>3} {'dur(s)':>7} {'cadence':<15} first paths")
    for r in sorted(sess_rows, key=lambda r: -r["n"])[:30]:
        print(f"   {r['ip']:<18} {r['ua']:<34} {r['n']:>3} {r['dur']:>7.1f} {r['cadence']:<15} {r['paths'][:8]}")

    # --- secret-file hit ordering ---------------------------------------------
    print("\nsecret-file path hit counts (route_kind=secret-file):")
    sf_counts = Counter(r.get("path", "") for r in reqs if r.get("route_kind") == "secret-file")
    for p, n in sf_counts.most_common():
        print(f"   {n:>4}  {p}")

    # Does a session check /.git/HEAD before /.git/config? .env before wp-config.php?
    pairs = [(".git/HEAD", ".git/config"), (".env", "wp-config.php")]
    for a, b in pairs:
        both = [r for r in sess_rows if any(a in p for p in r["paths"]) and any(b in p for p in r["paths"])]
        a_first = sum(1 for r in both if next(i for i, p in enumerate(r["paths"]) if a in p) <
                                          next(i for i, p in enumerate(r["paths"]) if b in p))
        print(f"   sessions hitting both '{a}' & '{b}': {len(both)} ({a}-first: {a_first}, {b}-first: {len(both)-a_first})")

    # --- CVE pattern matches by advertised version -----------------------------
    print("\ncve_pattern_match counts by advertised-version variant:")
    variant_counts = Counter(variant_for(r.get("path", ""), r.get("ts", "")) for r in cve_hits)
    for v, n in variant_counts.most_common():
        print(f"   {n:>4}  {v}")
    print("   by cve_id:", dict(Counter(r.get("cve_id", "") for r in cve_hits)))

    # --- honeytoken triggers ----------------------------------------------------
    print(f"\nhoneytoken_issued: {len(issued)}  |  honeytoken_triggered: {len(triggered)}")
    trig_kinds = Counter()
    issued_by_tok = {r.get("token"): r for r in issued}
    for r in triggered:
        k = issued_by_tok.get(r.get("token"), {}).get("kind", "?")
        trig_kinds[k] += 1
    for k, n in trig_kinds.most_common():
        print(f"   {n:>4}  {k}")

    # --- circumstantial reuse: does an issued token value show up in a later
    # request's headers/body on a DIFFERENT path? (bare-key kinds have no callback,
    # so this is the fallback detection method noted as a limitation in SPEC §5.)
    all_bodies_headers = []
    for r in reqs:
        blob = " ".join([json.dumps(r.get("headers", {})), r.get("body_excerpt", ""), r.get("query", "")])
        all_bodies_headers.append((r.get("path", ""), r.get("ts", ""), blob))
    reuse_hits = []
    for r in issued:
        tok = r.get("token", "")
        if not tok:
            continue
        for path, ts, blob in all_bodies_headers:
            if tok in blob and path != r.get("route") and ts > r.get("ts", ""):
                reuse_hits.append({"token": tok, "kind": r.get("kind"), "issued_route": r.get("route"),
                                   "seen_path": path, "seen_ts": ts})
    print(f"\ncircumstantial reuse hits (issued token value reappearing later elsewhere): {len(reuse_hits)}")
    for h in reuse_hits[:10]:
        print(f"   {h['kind']:<20} issued@{h['issued_route']:<20} -> seen@{h['seen_path']} ({h['seen_ts']})")
    print(f"privacy-preserving runtime reuse events: {len(reuse_observed)}")

    # --- credential stuffing across every fingerprinted panel -------------------
    creds = [r for r in reqs if "creds_submitted" in r]
    print(f"\ncredential submissions across panel routes: {len(creds)}")
    print("   by path:", dict(Counter(r.get("path", "") for r in creds)))
    # Credentials sprayed at a honeypot login are frequently real credentials
    # stolen from someone else, so this deliberately reports only presence and
    # shape. Very old records (before main.py stopped retaining values) may
    # still hold raw pairs on disk; count them but never print them.
    legacy_raw = sum(1 for r in creds
                     if "user" in r["creds_submitted"] or "pass" in r["creds_submitted"])
    if legacy_raw:
        print(f"   {legacy_raw:>4}  legacy records with raw values on disk (not shown)")
    metadata = Counter(
        (r["creds_submitted"].get("source", "body"),
         r["creds_submitted"].get("user_present", False),
         r["creds_submitted"].get("pass_present", False))
        for r in creds if "user_present" in r["creds_submitted"])
    for (source, has_user, has_pass), n in metadata.most_common():
        print(f"   {n:>4}  source={source} user_present={has_user} pass_present={has_pass}")

    # --- graphql probes -----------------------------------------------------
    print(f"\ngraphql queries logged: {len(graphql_qs)}")
    for r in graphql_qs[:5]:
        print(f"   {r.get('query','')[:120]}")

    # --- tool/agent signals -------------------------------------------------
    # Scan request records too so the report retroactively classifies traffic
    # captured before the derived events were added to the deployed app.
    raw_rsc = [r for r in reqs if rsc_probe(r)]
    retained_rsc = [r for r in raw_rsc if RSC_PROTOTYPE.search(
        unquote_plus(r.get("body_excerpt", "")))]
    raw_tools = []
    for r in reqs:
        for tool, command in command_attempts(r):
            raw_tools.append({"ts": r.get("ts", ""), "ip": r.get("ip", ""),
                              "path": r.get("path", ""), "tool": tool,
                              "command": command,
                              "command_hash": hashlib.sha256(command.encode()).hexdigest()[:16]})

    print("\nagent/tool-use signals:")
    print(f"   RSC Server Action probes: {len(raw_rsc)} request(s), "
          f"{len({r.get('ip','') for r in raw_rsc})} IP(s)")
    print(f"   React2Shell prototype-chain payload retained: {len(retained_rsc)}")
    print(f"   derived rsc_action_probe events: {len(logged_rsc)}")
    print(f"   command/tool invocations found in raw requests: {len(raw_tools)}")
    print(f"   derived tool/API call events: {len(logged_tools)}")
    for r in raw_tools[:20]:
        print(f"   {r['ts']} {r['ip']:<18} {r['tool']:<30} "
              f"{r['command']!r} sha256:{r['command_hash']}")

    # High-confidence agent path: the same IP/UA fetched a machine-readable
    # API description and later called one of the operations it advertised.
    discovery_paths = {"/openapi.json", "/swagger.json", "/.well-known/ai-plugin.json"}
    tool_paths = {"/api/v1/system/status", "/api/v1/jobs/run"}
    discoveries = defaultdict(list)
    calls = defaultdict(list)
    for r in reqs:
        key = (r.get("ip", ""), r.get("ua", ""))
        if r.get("path") in discovery_paths:
            discoveries[key].append(r)
        if r.get("path") in tool_paths:
            calls[key].append(r)
    chains = []
    for key in discoveries.keys() & calls.keys():
        for d in discoveries[key]:
            later = next((c for c in calls[key] if c.get("ts", "") >= d.get("ts", "")), None)
            if later:
                chains.append((key, d, later))
                break
    print(f"   schema-discovery -> advertised-operation chains: {len(chains)}")
    for (ip, ua), d, c in chains[:10]:
        print(f"   {ip:<18} {d.get('path')} -> {c.get('method')} {c.get('path')} "
              f"({ua[:40]})")

    # --- IP classification --------------------------------------------------
    print("\nIP classification:")
    ipinfo = {ip: classify_ip(ip) for ip in ips}
    geo = enrich(list(ips)) if ENRICH else {}
    for ip, n in ips.most_common(50):
        _, cls = ipinfo[ip]
        extra = f"  [{geo[ip.split(',')[0].strip()]}]" if geo.get(ip.split(",")[0].strip()) else ""
        print(f"   {n:>4}  {ip:<20} {cls}{extra}")

    # --- catch-all: paths probed that AREN'T in the bait list -------------------
    print("\ntop catch-all (404) paths probed but not baited:")
    catch = Counter(r.get("path", "") for r in reqs if r.get("route_kind") == "catch-all" and r.get("status_served") == 404)
    for p, n in catch.most_common(30):
        print(f"   {n:>4}  {p}")


if __name__ == "__main__":
    main()
