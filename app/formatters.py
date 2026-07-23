"""
Per-kind fake-secret formatters for the http-bait honeypot.

Every value produced here is a honeytoken: syntactically shaped to pass a casual
scanner's regex/grep for that credential type, but never a real, usable secret —
no real key material, no resolvable real backend. Each formatter is a pure
function of a random per-issuance token id (minted and logged by main.py's
honeytoken()) so values are unique and attributable without any shared state.
"""
from __future__ import annotations

import base64
import json


def _hex_pad(tok: str, n: int, upper: bool = False) -> str:
    s = (tok * ((n // len(tok)) + 1))[:n]
    return s.upper() if upper else s


def _b64_pad(tok: str, n: int) -> str:
    raw = (tok * ((n // len(tok)) + 1)).encode()
    return base64.b64encode(raw).decode().rstrip("=")[:n]


def aws(tok: str, catcher_url: str | None) -> str:
    # AKIA + 16 uppercase alnum, paired with a 40-char secret. Public honeytoken
    # convention (canarytokens.org AWS keys use the same AKIA-prefixed shape).
    access_key = "AKIA" + _hex_pad(tok, 16, upper=True)
    secret = _b64_pad(tok, 40)
    return f"{access_key}:{secret}"


def aws_pair(tok: str, catcher_url: str | None = None) -> dict:
    access_key = "AKIA" + _hex_pad(tok, 16, upper=True)
    secret = _b64_pad(tok, 40)
    return {"aws_access_key_id": access_key, "aws_secret_access_key": secret}


def db_password(tok: str, catcher_url: str | None) -> str:
    return tok[:12]


def gcp(tok: str, catcher_url: str | None) -> dict:
    project = f"prod-{tok[:6]}"
    return {
        "type": "service_account",
        "project_id": project,
        "private_key_id": tok,
        "private_key": f"-----BEGIN PRIVATE KEY-----\n{_b64_pad(tok, 64)}\n-----END PRIVATE KEY-----\n",
        "client_email": f"svc-{tok[:8]}@{project}.iam.gserviceaccount.com",
        "client_id": _hex_pad(tok, 21),
        # can't redirect Google's real token endpoint to our catcher without
        # breaking the shape a scanner expects; see SPEC §5 known limitation.
        "token_uri": "https://oauth2.googleapis.com/token",
    }


def github_pat(tok: str, catcher_url: str | None) -> str:
    return "ghp_" + _hex_pad(tok, 36)


def slack_bot_token(tok: str, catcher_url: str | None) -> str:
    return "xoxb-" + _hex_pad(tok[:8], 12, upper=False).replace("a", "1").replace("b", "2") + "-" + tok


def slack_webhook(tok: str, catcher_url: str | None) -> str:
    # A webhook URL IS the "use" mechanism, so point it at our own catcher
    # instead of hooks.slack.com — a POST here is directly observable.
    return catcher_url or f"https://hooks.slack.com/services/T{_hex_pad(tok,8,True)}/B{_hex_pad(tok,8,True)}/{tok}"


def stripe_secret(tok: str, catcher_url: str | None) -> str:
    return "sk_live_" + _hex_pad(tok, 24)


def db_connection_string(tok: str, catcher_url: str | None) -> str:
    # Fake, non-resolvable internal host — a connection attempt just fails
    # (no real backend to exploit); reuse detection relies on the value
    # reappearing elsewhere (SPEC §5).
    user = "app"
    pw = tok[:12]
    return f"postgres://{user}:{pw}@db.internal-prod.local:5432/app"


def jwt(tok: str, catcher_url: str | None) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": f"svc-{tok[:8]}", "role": "admin", "iss": "internal-auth", "tok": tok,
    }, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = _hex_pad(tok, 32)
    return f"{header}.{payload}.{sig}"


def openai_key(tok: str, catcher_url: str | None) -> str:
    return "sk-" + _hex_pad(tok, 48)


def google_api_key(tok: str, catcher_url: str | None) -> str:
    # Real AIza keys are mixed-case base62; _hex_pad only ever emits [0-9a-f],
    # so upper() every other char to get a plausible mixed-case shape instead
    # of a same-shaped-but-wrong pure-lowercase-hex string.
    raw = _hex_pad(tok, 35, upper=False)
    return "AIza" + "".join(c.upper() if i % 2 else c for i, c in enumerate(raw))


def ssh_private_key(tok: str, catcher_url: str | None) -> str:
    # PEM-shaped filler that is NOT valid base64/DER — visually matches what
    # scanners grep for ("BEGIN ... PRIVATE KEY") but cannot be parsed as a
    # real key by any tool, so it can never be mistaken for a reusable one.
    body = "\n".join(_hex_pad(tok, 64) for _ in range(6))
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"


FORMATTERS = {
    "aws": aws,
    "aws_pair": aws_pair,
    "db_password": db_password,
    "gcp": gcp,
    "github_pat": github_pat,
    "slack_bot_token": slack_bot_token,
    "slack_webhook": slack_webhook,
    "stripe_secret": stripe_secret,
    "db_connection_string": db_connection_string,
    "jwt": jwt,
    "openai_key": openai_key,
    "google_api_key": google_api_key,
    "ssh_private_key": ssh_private_key,
}

# Kinds whose formatted value embeds catcher_url directly (a "use" is a GET/POST
# to that URL, directly observable). Everything else can only be detected via
# reappearance elsewhere (Authorization headers on other routes) — see SPEC §5.
CATCHER_EMBEDDED = {"slack_webhook"}
