"""Verification for the pre-release fixes. Run inside the app/ dir."""
import contextlib, json, os, subprocess, sys, time, pathlib
import pytest
from fastapi.testclient import TestClient

LOGDIR = pathlib.Path(os.environ["HB_LOG_DIR"])
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _isolate():
    """Each test starts with an empty rate-limit bucket and token memory.

    Without this the suite tests the rate limiter rather than what it means to,
    and every later assertion sees 429s.
    """
    import main
    main._rate_buckets.clear()
    clear_token_index(main)
    yield
    main._rate_buckets.clear()


def events(kind=None):
    p = LOGDIR / "http_events.jsonl"
    if not p.exists():
        return []
    rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
    return [r for r in rows if kind is None or r.get("event") == kind]


@contextlib.contextmanager
def reuse_events():
    """Collect exactly the honeytoken_reuse_observed events a block produces."""
    before = len(events("honeytoken_reuse_observed"))
    added = []
    yield added
    added.extend(events("honeytoken_reuse_observed")[before:])


def run_analyze(*args, check=True):
    return subprocess.run([sys.executable, str(REPO_ROOT / "analyze.py"), *args],
                          capture_output=True, text=True, check=check)


def clear_token_index(main):
    main._issued_token_ids.clear()
    main._issued_token_order.clear()
    main._issued_token_prefixes.clear()


def test_honeytoken_reuse_still_detected():
    """The scan was inverted for performance; detection must be unchanged."""
    import main
    c = TestClient(main.app)
    c.get("/.env")
    issued = events("honeytoken_issued")
    assert issued, "no honeytokens were minted by GET /.env"
    tok = issued[0]["token"]

    # replay in each of the four inspected locations
    for where, call in [
        ("query", lambda: c.get(f"/anything?k={tok}")),
        ("body", lambda: c.post("/api/run-job", content=f"payload={tok}")),
        ("headers", lambda: c.get("/anything", headers={"x-probe": tok})),
    ]:
        with reuse_events() as after:
            call()
        assert after, f"reuse NOT detected in {where}"
        assert after[-1]["token"] == tok
        print(f"  reuse detected in {where}: seen_in={after[-1]['seen_in']}")


def test_uppercase_and_padded_token_detected():
    """Served values uppercase the id (AKIA...) and repeat it to pad width."""
    import main
    c = TestClient(main.app)
    c.get("/.aws/credentials")
    issued = events("honeytoken_issued")
    tok = issued[-1]["token"]
    with reuse_events() as after:
        c.get("/x", headers={"authorization-probe": "AKIA" + (tok * 2).upper()})
    assert after, "padded/uppercase form not detected"
    print(f"  padded+uppercase detected: {after[-1]['token'] == tok}")


def test_unissued_token_not_flagged():
    import main
    c = TestClient(main.app)
    before = len(events("honeytoken_reuse_observed"))
    c.get("/anything?k=deadbeefdeadbeef")  # 16 hex chars, never issued
    after = len(events("honeytoken_reuse_observed"))
    assert after == before, "false positive on an unissued 16-hex string"
    print("  no false positive on unissued hex")


def test_scan_cost_is_independent_of_issued_count():
    """The whole point of the inversion: 50k issued tokens must not slow the scan.

    Timed against _check_honeytoken_reuse directly rather than through 20 HTTP
    round trips. The claim is about the scan, and routing 60KB through the ASGI
    stack twenty times measures mostly the stack: on a shared CI runner that
    added enough variance to fail a 3x bound on a ratio whose true value is
    ~1.0. Measuring the scan itself allows a much tighter bound, so this is a
    stronger check than the one it replaces, not a relaxed one.

    Best-of-N rather than total, so one descheduled sample cannot set the result.
    """
    import main, asyncio

    body = b"A" * 60_000
    headers = {"user-agent": "scan-cost-probe"}

    def best_scan_seconds(rounds=7):
        best = float("inf")
        for _ in range(rounds):
            t0 = time.perf_counter()
            asyncio.run(main._check_honeytoken_reuse("/probe", "", body, headers))
            best = min(best, time.perf_counter() - t0)
        return best

    clear_token_index(main)
    empty = best_scan_seconds()

    for i in range(50_000):
        main._remember_issued_token(f"{i:016x}")
    assert len(main._issued_token_ids) == 50_000
    full = best_scan_seconds()

    ratio = full / empty if empty else 0
    print(f"  64KB scan: empty-set {empty*1000:.3f}ms, 50k-token set "
          f"{full*1000:.3f}ms (x{ratio:.2f})")
    assert ratio < 1.5, f"scan now scales with issued-token count (x{ratio:.2f})"


def test_requests_still_served_with_a_full_token_index():
    """Integration cover for the above: 50k tokens must not break the request path."""
    import main
    c = TestClient(main.app)
    for i in range(50_000):
        main._remember_issued_token(f"{i:012x}beef")
    r = c.post("/api/run-job", content="A" * 60_000)
    assert r.status_code in (200, 404, 503), r.status_code

    tok = f"{7:012x}beef"
    before = len(events("honeytoken_reuse_observed"))
    c.get(f"/anything?k={tok}")
    new_events = [e for e in events()
                  if e.get("event") == "honeytoken_reuse_observed"][before:]
    assert new_events, "lookup failed against a full index"

    # Membership, not "the only match". The scan slides across every offset in a
    # hex run, because a served value may pad or repeat the id, so densely
    # packed synthetic ids legitimately produce extra prefix candidates. Real
    # uuid4-derived ids do not collide like this; asserting a single match here
    # would be testing the fixture rather than the code.
    by_token = {e["token"]: e for e in new_events}
    assert tok in by_token, f"{tok} not among {sorted(by_token)}"
    assert by_token[tok]["matched"] == "full"
    print(f"  full index serves requests and matches on lookup "
          f"({len(new_events)} candidate(s), exact id among them)")


def test_header_value_is_capped_in_log():
    import main
    c = TestClient(main.app)
    c.get("/anything", headers={"x-big": "z" * 200_000})
    rec = events("request")[-1]
    line = json.dumps(rec)
    assert len(line) < 60_000, f"one request wrote {len(line)} bytes to the log"
    assert "<truncated:len=200000>" in line
    print(f"  200KB header -> {len(line)} byte log line")


def test_healthz_reports_write_failure():
    import main
    c = TestClient(main.app)
    assert c.get("/healthz").status_code == 200
    main.writer.last_write_error = "OSError: [Errno 28] No space left on device"
    main.writer.write_failures = 3
    r = c.get("/healthz")
    assert r.status_code == 503 and r.json() == {"ok": False}
    assert "free" not in r.text and "space" not in r.text, "healthz leaked operator detail"
    main.writer.last_write_error = None
    assert c.get("/healthz").status_code == 200
    print("  healthz 503s on write failure, body stays {'ok': false}")


def test_client_disconnect_still_logs_request():
    """A body read that dies mid-stream must not lose the request record."""
    import main, asyncio
    from starlette.requests import ClientDisconnect

    class FakeReq:
        async def stream(self):
            yield b"partial-payload"
            raise ClientDisconnect()

    body, exceeded = asyncio.run(main._read_capped_body(FakeReq()))
    assert body == b"partial-payload" and exceeded is False
    print("  mid-body disconnect returns partial body instead of raising")


def test_db_password_reuse_now_detected():
    """12-char prefix honeytokens (~14% of issuances) were undetectable."""
    import main
    c = TestClient(main.app)
    c.get("/.env")
    issued = events("honeytoken_issued")
    dbp = [e for e in issued if e.get("kind") == "db_password"]
    assert dbp, f"no db_password issued; kinds seen: {set(e.get('kind') for e in issued)}"
    tok = dbp[-1]["token"]
    served = tok[:12]
    assert len(served) == 12
    with reuse_events() as after:
        c.get(f"/anything?db={served}")
    assert after, "12-char db_password replay STILL not detected"
    assert after[-1]["token"] == tok and after[-1]["matched"] == "prefix"
    print(f"  db_password 12-char replay detected -> full id {tok}")


def test_struts_s2_057_signatures_fire():
    import signatures
    for payload in ["redirect:${233*233}", "redirectAction:${233*233}",
                    "${@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS}"]:
        hit = any(cve == "CVE-2018-11776" and pat.search(payload)
                  for cve, pat, _, _, _ in signatures.CVE_SIGNATURES)
        assert hit, f"S2-057 pattern still misses: {payload}"
    print("  CVE-2018-11776 matches all 3 real-world payload shapes")


def test_duplicate_header_payload_is_scanned():
    import main, signatures
    raw = [["referer", "harmless"], ["referer", "${jndi:ldap://x/a}"]]
    text = main._headers_haystack(raw)
    hit = any(cve == "CVE-2021-44228" and pat.search(text)
              for cve, pat, _, _, _ in signatures.CVE_SIGNATURES)
    assert hit, "payload in a duplicate header's 2nd occurrence still missed"
    print("  Log4Shell in duplicate header now scanned")


def test_internal_healthcheck_not_logged():
    import main
    c = TestClient(main.app)
    before = len(events("request"))
    c.get("/healthz")                                        # loopback, no XFF
    mid = len(events("request"))
    assert mid == before, "internal healthcheck polluted the dataset"
    c.get("/healthz", headers={"x-forwarded-for": "203.0.113.5"})   # via Caddy
    after = len(events("request"))
    assert after == mid + 1, "external /healthz probe was wrongly dropped"
    print("  internal healthcheck skipped, external probe still logged")


# --------------------------------------------------------------------------- #
# Fixes from the 2026-08 pre-publication review.
# --------------------------------------------------------------------------- #
def test_catch_all_post_credentials_are_redacted():
    """The non-retention promise applied to four handlers, not to the service.

    /admin is advertised in robots.txt but only registers GET, so a stuffing
    tool POSTing to the advertised URL fell through to catch_all and had its
    credentials written to body_excerpt verbatim.
    """
    import main
    c = TestClient(main.app)
    secret = "REAL-STOLEN-PW-DO-NOT-RETAIN"
    for path, body, ctype in [
        ("/admin", f"username=victim%40example.com&password={secret}",
         "application/x-www-form-urlencoded"),
        ("/login", f"user=victim2&pass={secret}",
         "application/x-www-form-urlencoded"),
        ("/user/login", json.dumps({"username": "victim3", "password": secret}),
         "application/json"),
    ]:
        c.post(path, content=body, headers={"content-type": ctype})
        rec = events("request")[-1]
        assert secret not in json.dumps(rec), f"{path} retained the password"
        assert rec["body_excerpt"].startswith("<redacted:credential-submission"), \
            f"{path} body_excerpt not redacted: {rec['body_excerpt']!r}"
        assert rec["creds_submitted"]["pass_present"] is True
        assert rec["creds_submitted"]["source"] == "body-inferred"
    print("  catch-all credential POSTs are redacted to shape only")


def test_sensitive_headers_are_redacted():
    """x-api-key and friends are exactly the headers this project is about."""
    import main
    c = TestClient(main.app)
    secret = "sk_live_REALVICTIMKEY"
    for header in ("x-api-key", "x-auth-token", "api-key", "x-amz-security-token"):
        c.get("/anything", headers={header: secret})
        rec = events("request")[-1]
        assert secret not in json.dumps(rec), f"{header} retained verbatim"
        assert rec["headers"][header].startswith("<redacted:key:"), rec["headers"][header]
    print("  api-key-family headers redacted with an hmac, not stored")


def test_redaction_digest_is_stable_within_a_run():
    """Same unknown credential twice must stay correlatable after redaction."""
    import main
    a = main._redaction_digest("hunter2")
    b = main._redaction_digest("hunter2")
    c_ = main._redaction_digest("hunter3")
    assert a == b and a != c_
    assert "hunter2" not in a
    print("  redaction digest correlates repeats without keeping the value")


def test_served_token_len_declarations_are_accurate():
    """The prefix bug's root cause: nothing checked what a formatter served."""
    import formatters
    tok = "0123456789abcdef"
    assert set(formatters.SERVED_TOKEN_LEN) == set(formatters.FORMATTERS), \
        "a formatter exists with no declared served length"
    for kind, declared in formatters.SERVED_TOKEN_LEN.items():
        actual = formatters.served_run_len(kind, tok, catcher_url=f"https://x/x/{tok}")
        assert actual == declared, f"{kind} declares {declared}, serves {actual}"
    import main
    assert main.TOKEN_PREFIX_LEN == min(formatters.SERVED_TOKEN_LEN.values())
    print(f"  all {len(formatters.SERVED_TOKEN_LEN)} kinds declare their served length correctly")


def test_reuse_detected_while_rate_limited():
    """A credential replay arrives as a burst; the detector slept through bursts."""
    import main
    c = TestClient(main.app)
    c.get("/.git/config")
    issued = events("honeytoken_issued")
    tok = issued[-1]["token"]

    for _ in range(main.RATE_MAX_REQ + 2):
        c.get("/filler")
    assert c.get("/filler").status_code == 429, "rate limiter did not engage"

    with reuse_events() as after:
        r = c.get("/probe", headers={"authorization": f"Bearer ghp_{tok}"})
        assert r.status_code == 429, "expected this request to be rate limited"
    assert after, "replay during a burst was NOT detected"
    assert after[-1]["token"] == tok and after[-1]["body_available"] is False
    print("  honeytoken replay detected even while rate limited")


def test_oversized_body_retains_leading_bytes():
    """A single oversized chunk used to discard the whole body, not the excess."""
    import main, asyncio

    class OneBigChunk:
        async def stream(self):
            yield b"P" * (main.BODY_CAP + 1)

    body, exceeded = asyncio.run(main._read_capped_body(OneBigChunk()))
    assert exceeded is True
    assert len(body) == main.BODY_CAP, f"retained {len(body)} bytes, expected {main.BODY_CAP}"
    print(f"  oversized single chunk retains {len(body)} bytes instead of 0")


def test_unissued_catcher_probe_is_separate_event():
    """/x/ is walkable; an unissued id is not proof of use."""
    import main
    c = TestClient(main.app)
    c.get("/x/ffffffffffffffff")
    # The middleware writes its `request` record after the handler runs, so
    # filter for the catcher event rather than taking the last line.
    probes = events("catcher_probe_unissued")
    assert probes and probes[-1]["token"] == "ffffffffffffffff"
    assert not events("honeytoken_triggered")

    c.get("/.env")
    tok = events("honeytoken_issued")[-1]["token"]
    c.get(f"/x/{tok}")
    trig = events("honeytoken_triggered")
    assert trig and trig[-1]["token"] == tok
    assert len(events("catcher_probe_unissued")) == len(probes)
    print("  unissued catcher probes no longer count as confirmed triggers")


def test_issued_token_index_rebuilds_from_log():
    """A restart used to empty the index, making every prior token unmatchable."""
    import main
    c = TestClient(main.app)
    c.get("/.env")
    tok = events("honeytoken_issued")[-1]["token"]

    clear_token_index(main)
    assert tok not in main._issued_token_ids

    restored = main.rebuild_issued_token_index()
    assert restored > 0 and tok in main._issued_token_ids

    with reuse_events() as after:
        c.get(f"/anything?k={tok}")
    assert after, "replay after a simulated restart was not detected"
    print(f"  index rebuilt from log ({restored} issuances), replay still detected")


def test_graphql_does_not_retain_raw_body():
    import main
    c = TestClient(main.app)
    secret = "GQL-REAL-PASSWORD"
    c.post("/graphql", content=json.dumps(
        {"query": f'mutation {{ login(user:"v", password:"{secret}") }}'}),
        headers={"content-type": "application/json"})
    gql = events("graphql_query")[-1]
    assert secret not in json.dumps(gql), f"graphql retained the password: {gql}"
    assert "<redacted>" in gql["query"]

    c.post("/graphql", content=b"\x00not-json-" + secret.encode(),
           headers={"content-type": "application/json"})
    gql = events("graphql_query")[-1]
    assert gql["parsed"] is False and gql["query"] == ""
    assert secret not in json.dumps(gql), "unparseable graphql body retained raw"
    print("  graphql retains neither inline credentials nor raw unparsed bodies")


def test_oversize_record_is_bounded_not_dropped():
    import main
    rec = {"event": "request", "ip": "203.0.113.9", "path": "/x",
           "status_served": 200, "route_kind": "catch-all",
           "junk": "z" * (main.RECORD_MAX_BYTES + 10)}
    main.writer.write(rec)
    last = events()[-1]
    assert last.get("oversize_record") is True
    assert last["ip"] == "203.0.113.9" and "junk" not in last
    assert last["original_len"] > main.RECORD_MAX_BYTES
    print("  oversize record truncated to identifying fields, still written")


def _import_analyze():
    import sys
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    import analyze
    return analyze


def test_signature_tables_are_not_duplicated():
    """analyze.py and main.py drifted because each had its own copy."""
    import main, signatures
    analyze = _import_analyze()
    assert analyze.CVE_SIGNATURES is signatures.CVE_SIGNATURES
    assert analyze.ROUTE_VARIANT is signatures.ROUTE_VARIANT
    assert analyze.TOOL_INVOCATION_SIGNATURES is signatures.TOOL_INVOCATION_SIGNATURES
    assert main.ROUTE_VARIANT is signatures.ROUTE_VARIANT
    print("  analyzer and service share one signature table")


def test_analyzer_output_matches_published_fixture():
    """A report must be reproducible from a published input.

    An earlier findings document claimed "the counts here are what the analyzer
    prints" while the analyzer did not compute half of them. A frozen fixture
    plus a frozen expected report makes that kind of sentence checkable by a
    reader instead of a claim they take on trust.
    """
    fixture = REPO_ROOT / "fixtures" / "sample_events.jsonl"
    expected = (REPO_ROOT / "fixtures" / "expected_analysis.txt").read_text()
    got = run_analyze(str(fixture), "--rescan").stdout
    # The fixture path is echoed by basename, so the report is location-independent.
    assert got == expected, (
        "analyzer output drifted from fixtures/expected_analysis.txt.\n"
        "If the change is intended, regenerate with:\n"
        "  python analyze.py fixtures/sample_events.jsonl --rescan > fixtures/expected_analysis.txt"
    )
    print("  analyzer reproduces the frozen fixture report exactly")


def test_fixture_demonstrates_retroactive_detection():
    """The fixture must actually exercise the live-vs-rescan gap it documents."""
    analyze = _import_analyze()
    expected = (REPO_ROOT / "fixtures" / "expected_analysis.txt").read_text()
    live = expected.split("LIVE")[1].split("RESCAN")[0]
    rescan = expected.split("RESCAN")[1]
    def ids(section):
        return {ln.split()[0] for ln in section.splitlines()
                if ln.strip().startswith("CVE-")}
    live_cves, rescan_cves = ids(live), ids(rescan)
    assert live_cves < rescan_cves, "fixture no longer shows a retroactive gap"
    # CVE-2025-55182's signature ships after the traffic it matches, which is
    # the situation FINDINGS.md's caveats exist to make an operator check for.
    assert "CVE-2025-55182" in rescan_cves and "CVE-2025-55182" not in live_cves
    print(f"  live found {len(live_cves)} CVE(s), rescan found {len(rescan_cves)}")


def test_analyzer_survives_a_torn_final_line():
    """pull-telemetry.sh rsyncs a file being appended to; a torn tail is normal."""
    import tempfile
    fixture = (REPO_ROOT / "fixtures" / "sample_events.jsonl").read_text()
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        fh.write(fixture + '{"ts":"2026-07-22T21:00:00+00:00","event":"req')
        torn = fh.name
    r = run_analyze(torn, check=False)
    assert r.returncode == 0, f"analyzer aborted on a torn line:\n{r.stderr}"
    assert "malformed lines skipped: 1" in r.stdout
    print("  torn final line skipped and counted, report still produced")


def test_analyzer_truncates_third_party_ips_by_default():
    """Truncation was once claimed as a property of the data with nothing behind it."""
    fixture = REPO_ROOT / "fixtures" / "sample_events.jsonl"
    out = run_analyze(str(fixture)).stdout
    assert "198.51.100.0/24" in out
    assert "198.51.100.10" not in out, "a full third-party address was printed"
    full = run_analyze(str(fixture), "--full-ips").stdout
    assert "198.51.100.10" in full, "--full-ips did not restore full addresses"
    print("  third-party IPs print as /24 unless --full-ips is passed")


def test_analyzer_excludes_self_test_traffic():
    fixture = REPO_ROOT / "fixtures" / "sample_events.jsonl"
    out = run_analyze(str(fixture), "--exclude-ip", "198.51.100.10").stdout
    # Request records, the issuances made to that address, and its reuse event.
    assert "excluded: 7 by --exclude-ip" in out, out[:400]
    print("  self-test exclusion is a documented flag, not a manual step")


# --------------------------------------------------------------------------- #
# Credential redaction across body formats. The first fix moved redaction into
# the middleware but the parser handled only flat form-encoded and flat
# top-level JSON, so nested JSON, arrays, XML, multipart and query strings all
# still wrote the secret verbatim while the docs claimed otherwise.
# --------------------------------------------------------------------------- #
_MULTIPART = ("--X\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nv7\r\n"
              "--X\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n"
              "MultiSecret9\r\n--X--\r\n")

CREDENTIAL_SHAPES = [
    ("flat form", "POST", "/login", "username=v1&password=FlatSecret1",
     "application/x-www-form-urlencoded", "FlatSecret1"),
    ("flat json", "POST", "/a0", '{"username":"v0","password":"FlatJson0"}',
     "application/json", "FlatJson0"),
    ("nested json", "POST", "/a1", '{"auth":{"username":"v2","password":"Hunter2Real"}}',
     "application/json", "Hunter2Real"),
    ("deeply nested json", "POST", "/a2", '{"a":{"b":{"c":{"password":"DeepSecret4"}}}}',
     "application/json", "DeepSecret4"),
    ("json array", "POST", "/a3", '[{"username":"v3","password":"ArraySecret1"}]',
     "application/json", "ArraySecret1"),
    ("xml body", "POST", "/soap", "<login><password>XmlSecret123</password></login>",
     "application/xml", "XmlSecret123"),
    ("yaml-ish body", "POST", "/cfg", "user: v5\npassword: YamlSecret7\n",
     "text/plain", "YamlSecret7"),
    ("multipart", "POST", "/panel", _MULTIPART,
     "multipart/form-data; boundary=X", "MultiSecret9"),
    ("query string on GET", "GET", "/q?username=v6&password=QuerySecret42", None,
     None, "QuerySecret42"),
    ("query string on POST", "POST", "/q2?pass=QpSecret8", "unrelated=1",
     "application/x-www-form-urlencoded", "QpSecret8"),
]


@pytest.mark.parametrize("label,method,path,body,ctype,secret", CREDENTIAL_SHAPES,
                         ids=[c[0] for c in CREDENTIAL_SHAPES])
def test_credentials_never_retained_in_any_shape(label, method, path, body, ctype, secret):
    import main
    c = TestClient(main.app)
    c.request(method, path, content=body, headers={"content-type": ctype} if ctype else {})
    rec = events("request")[-1]
    assert secret not in json.dumps(rec), f"{label}: secret written to the log"
    assert rec.get("creds_submitted", {}).get("pass_present") is True, \
        f"{label}: credential submission not recorded at all"


def test_query_string_credentials_are_redacted_in_the_query_field():
    """rec["query"] is its own field; redacting body_excerpt alone left it exposed."""
    import main
    c = TestClient(main.app)
    c.get("/q?username=v&password=QueryFieldSecret1")
    rec = events("request")[-1]
    assert "QueryFieldSecret1" not in rec["query"], rec["query"]
    assert "<redacted:len=17>" in rec["query"], rec["query"]
    assert "username=v" in rec["query"], "non-credential params should survive"
    print("  query credentials redacted, other params preserved")


def test_ordinary_body_is_not_over_redacted():
    """Over-redaction is the safer failure, but it still must not swallow everything."""
    import main
    c = TestClient(main.app)
    c.post("/plain", content="hello=world&page=2",
           headers={"content-type": "application/x-www-form-urlencoded"})
    rec = events("request")[-1]
    assert rec["body_excerpt"] == "hello=world&page=2"
    assert "creds_submitted" not in rec
    c.get("/search?q=how+to+reset+a+password")
    rec = events("request")[-1]
    assert "how+to+reset+a+password" in rec["query"], "a query merely mentioning a field name"
    print("  non-credential bodies and queries pass through intact")


# --------------------------------------------------------------------------- #
# Provenance, classification, canary state, and report sanitization.
# --------------------------------------------------------------------------- #
def test_every_record_carries_the_collection_window():
    """Derived events were unlabelled, so --window silently kept all of them."""
    import main
    c = TestClient(main.app)
    c.get("/.env")
    c.get("/x/ffffffffffffffff")
    kinds = {e["event"] for e in events()}
    assert {"request", "honeytoken_issued", "catcher_probe_unissued"} <= kinds
    unlabelled = [e for e in events() if "window" not in e]
    assert not unlabelled, f"records without a window: {[e['event'] for e in unlabelled]}"
    print(f"  all {len(kinds)} event kinds carry a window label")


def test_issuances_carry_ip_so_exclusions_reach_them():
    """--exclude-ip could not match an issuance: the address was packed in `session`."""
    import main
    c = TestClient(main.app)
    c.get("/.env", headers={"x-forwarded-for": "203.0.113.55"})
    issued = events("honeytoken_issued")[-1]
    assert issued["ip"] == "203.0.113.55", issued
    assert issued["session"].startswith("203.0.113.55|")
    print("  issuance records carry ip separately from session")


def test_signatures_declare_exploit_or_probe():
    """A path hit is reconnaissance; counting it as exploitation inflates the headline."""
    import signatures
    kinds = {cve: kind for cve, _p, _w, _s, kind in signatures.CVE_SIGNATURES}
    assert set(kinds.values()) <= {"exploit", "probe"}
    # Path-only detectors cannot see a payload, so they cannot evidence exploitation.
    for cve, _p, where, _s, kind in signatures.CVE_SIGNATURES:
        if where == "path" and cve in ("CVE-2017-9841", "CVE-2024-27956"):
            assert kind == "probe", f"{cve} is path-only and must not count as an exploit"
    assert kinds["CVE-2021-44228"] == "exploit"
    assert kinds["CVE-2025-55182"] == "exploit"
    print(f"  {sum(v == 'exploit' for v in kinds.values())} exploit, "
          f"{sum(v == 'probe' for v in kinds.values())} probe signatures")


def test_cve_events_record_kind_and_body_presence():
    import main
    c = TestClient(main.app)
    c.get("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php")
    hit = [e for e in events("cve_pattern_match") if e["cve_id"] == "CVE-2017-9841"][-1]
    assert hit["signature_kind"] == "probe" and hit["body_present"] is False
    print("  a bare path hit is recorded as a probe with no body")


def test_analyzer_separates_exploits_from_probes():
    fixture = REPO_ROOT / "fixtures" / "sample_events.jsonl"
    out = run_analyze(str(fixture), "--rescan").stdout
    assert "payload-bearing exploit attempts" in out
    assert "vulnerability probes (path/marker only)" in out
    rescan = out.split("RESCAN")[1]
    exploit_line = [l for l in rescan.splitlines() if "payload-bearing" in l][0]
    probe_line = [l for l in rescan.splitlines() if "vulnerability probes" in l][0]
    assert "3 hit(s)" in exploit_line, exploit_line
    assert "2 hit(s)" in probe_line, probe_line
    print("  rescan reports 3 exploit attempts and 2 probes rather than a combined 5")


def test_window_filter_reaches_derived_events():
    fixture = REPO_ROOT / "fixtures" / "sample_events.jsonl"
    out = run_analyze(str(fixture), "--window", "nonexistent").stdout
    assert "honeytoken_issued: 0" in out, out[:600]
    assert "confirmed triggers (issued ids only): 0" in out
    assert "runtime reuse events recorded by the service: 0" in out
    print("  a window that matches nothing yields nothing, derived events included")


def test_exclude_ip_reaches_issuances_and_reuse():
    fixture = REPO_ROOT / "fixtures" / "sample_events.jsonl"
    out = run_analyze(str(fixture), "--exclude-ip", "198.51.100.10").stdout
    assert "circumstantial reuse hits (issued value reappearing later elsewhere): 0" in out
    assert "honeytoken_issued: 1" in out, out[:600]
    print("  excluding a self-test address drops its issuances and its reuse hit")


def test_analyzer_does_not_print_raw_payloads_by_default():
    import main, tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        fh.write(json.dumps({
            "ts": "2026-07-20T00:00:00+00:00", "event": "request", "window": "w",
            "ip": "203.0.113.9", "ua": "curl key=SuperSecretValue1 https://evil.test/x",
            "method": "GET", "path": "/probe?apikey=AKIAEXAMPLESECRETKEY99",
            "query": "", "headers": {}, "status_served": 404, "route_kind": "catch-all",
            "body_len": 0, "body_excerpt": "",
        }) + "\n")
        path = fh.name
    out = run_analyze(path).stdout
    for leak in ("SuperSecretValue1", "https://evil.test/x", "AKIAEXAMPLESECRETKEY99"):
        assert leak not in out, f"default output leaked {leak!r}"
    raw = run_analyze(path, "--show-payloads").stdout
    assert "AKIAEXAMPLESECRETKEY99" in raw, "--show-payloads should restore raw text"
    print("  default report is paste-safe; --show-payloads opts back in")


def test_ipv6_truncation_is_valid():
    analyze = _import_analyze()
    analyze.ARGS.full_ips = False
    assert analyze.truncate_ip("2001:db8::1") == "2001:db8::/48"
    assert analyze.truncate_ip("2001:db8:85a3::8a2e:370:7334") == "2001:db8:85a3::/48"
    assert analyze.truncate_ip("198.51.100.10") == "198.51.100.0/24"
    assert analyze.truncate_ip("not-an-ip") == "<unparseable>"
    print("  IPv6 anonymization produces valid networks")


def test_security_txt_does_not_advertise_an_unmonitored_address():
    import main
    c = TestClient(main.app)
    body = c.get("/.well-known/security.txt").text
    if main.OPERATOR_CONTACT:
        assert f"mailto:{main.OPERATOR_CONTACT}" in body
    else:
        assert "http-bait.example" not in body, body
        assert "No operator contact configured" in body, body
    print("  security.txt says it is unconfigured rather than naming a dead mailbox")
