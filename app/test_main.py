import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


_TMP = tempfile.TemporaryDirectory()
os.environ["HB_LOG_DIR"] = _TMP.name
sys.path.insert(0, str(Path(__file__).parent))

import main  # noqa: E402  (environment must be set before app construction)


class HttpBaitTests(unittest.TestCase):
    def setUp(self):
        self.events = Path(_TMP.name) / "http_events.jsonl"
        self.events.unlink(missing_ok=True)
        self.client = TestClient(main.app)

    def rows(self):
        if not self.events.exists():
            return []
        return [json.loads(line) for line in self.events.read_text().splitlines()]

    def test_bait_schema_does_not_expose_real_routes(self):
        response = self.client.get("/openapi.json")
        self.assertEqual(response.status_code, 200)
        paths = response.json()["paths"]
        self.assertEqual(set(paths), {"/api/v1/system/status", "/api/v1/jobs/run"})
        serialized = response.text
        self.assertNotIn("/x/{token}", serialized)
        self.assertNotIn("/admin/login", serialized)
        self.assertEqual(self.client.get("/docs").status_code, 404)
        self.assertEqual(self.client.get("/redoc").status_code, 404)

    def test_react2shell_and_command_attempt_are_classified_only(self):
        payload = (
            '--hb\r\nContent-Disposition: form-data; name="0"\r\n\r\n'
            '{"then":"$1:__proto__:then","_response":{"_prefix":'
            '"process.mainModule.require(\'child_process\').execSync(\'printf HB_TEST\')"}}'
            "\r\n--hb--\r\n"
        )
        response = self.client.post(
            "/",
            content=payload,
            headers={"Next-Action": "x", "Content-Type": "multipart/form-data; boundary=hb"},
        )
        self.assertEqual(response.status_code, 404)
        rows = self.rows()
        self.assertTrue(any(r.get("event") == "rsc_action_probe" for r in rows))
        self.assertTrue(any(r.get("event") == "cve_pattern_match"
                            and r.get("cve_id") == "CVE-2025-55182" for r in rows))
        tool = next(r for r in rows if r.get("event") == "tool_invocation_attempt")
        self.assertEqual(tool["command"], "printf HB_TEST")
        request = next(r for r in rows if r.get("event") == "request")
        self.assertEqual(tool["request_id"], request["request_id"])

    def test_header_only_oversized_rsc_is_probe_not_confirmed_cve(self):
        response = self.client.post(
            "/",
            content=b"A" * (main.BODY_CAP + 1),
            headers={"Next-Action": "x", "Content-Type": "multipart/form-data; boundary=hb"},
        )
        self.assertEqual(response.status_code, 413)
        rows = self.rows()
        probe = next(r for r in rows if r.get("event") == "rsc_action_probe")
        self.assertFalse(probe["body_available"])
        self.assertFalse(any(r.get("event") == "cve_pattern_match" for r in rows))
        self.assertFalse(any(r.get("event") == "tool_invocation_attempt" for r in rows))

    def test_schema_operation_is_log_only_and_correlated(self):
        self.client.get("/openapi.json")
        response = self.client.post(
            "/api/v1/jobs/run",
            json={"job": "refresh-cache", "dry_run": False, "unexpected": "ignored"},
        )
        self.assertEqual(response.status_code, 503)
        rows = self.rows()
        event = next(r for r in rows if r.get("event") == "api_tool_call_attempt")
        request = next(r for r in rows if r.get("event") == "request"
                       and r.get("path") == "/api/v1/jobs/run")
        self.assertEqual(event["args"]["job"], "refresh-cache")
        self.assertEqual(event["request_id"], request["request_id"])

    def test_unknown_credentials_are_not_retained(self):
        response = self.client.post(
            "/wp-login.php",
            data={"log": "real-looking-user", "pwd": "do-not-store-this"},
            headers={"Authorization": "Bearer unknown-visitor-secret",
                     "Cookie": "session=unknown-visitor-cookie"},
        )
        self.assertEqual(response.status_code, 200)
        request = next(r for r in self.rows() if r.get("event") == "request")
        serialized = json.dumps(request)
        self.assertNotIn("real-looking-user", serialized)
        self.assertNotIn("do-not-store-this", serialized)
        self.assertNotIn("unknown-visitor-secret", serialized)
        self.assertNotIn("unknown-visitor-cookie", serialized)
        self.assertTrue(request["creds_submitted"]["user_present"])
        self.assertTrue(request["creds_submitted"]["pass_present"])


if __name__ == "__main__":
    unittest.main()
