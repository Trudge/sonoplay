import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Isolated interpreter: the other unit tests stub fastapi/starlette in
# sys.modules, and this test needs the real app plus real auth middleware.
_SCRIPT = r"""
from fastapi.testclient import TestClient
import plex.plex_auth as auth
import plex.plexserver as plexserver
from redaction import RedactSecretsFilter, RedactingFormatter, redact_secrets

# Sessions are signed and tamper-evident.
user = {"id": "1", "username": "tester"}
session = auth.issue_session(user)
assert auth.verify_session(session)["sub"] == "1"
body, signature = session.split(".", 1)
assert auth.verify_session(body[:-1] + ("A" if body[-1] != "A" else "B") + "." + signature) is None

# Allowlist matching accepts id/username and rejects others.
auth.settings.auth_allowed_users = "1,owner"
assert auth.is_user_allowed({"id": "1"})
assert auth.is_user_allowed({"username": "owner"})
assert not auth.is_user_allowed({"id": "2", "username": "guest"})

# DLNA callback HMACs are device-specific.
token = auth.callback_token("device-1")
assert auth.verify_callback_token("device-1", token)
assert not auth.verify_callback_token("device-2", token)
assert not auth.verify_callback_token("device-1", "wrong")

# Credential redaction covers URL and mapping forms.
redacted = redact_secrets("http://pms/:/timeline?X-Plex-Token=s3cr3t&state=playing")
assert "s3cr3t" not in redacted and "state=playing" in redacted
redacted = redact_secrets({"X-Plex-Token": "s3cr3t"})
assert "s3cr3t" not in redacted

# The formatter redacts exception tracebacks too.
import io
import logging
stream = io.StringIO()
handler = logging.StreamHandler(stream)
handler.setFormatter(RedactingFormatter("%(message)s"))
log = logging.getLogger("redaction-test")
log.addHandler(handler)
log.setLevel(logging.DEBUG)
try:
    raise RuntimeError("http://pms/:/timeline?X-Plex-Token=s3cr3t")
except RuntimeError:
    log.exception("request failed")
assert "s3cr3t" not in stream.getvalue()
assert "[REDACTED]" in stream.getvalue()

client = TestClient(plexserver.plex_server, follow_redirects=False)

# Public health, protected API, and HTML redirect to login.
assert client.get("/health").status_code == 200
assert client.get("/api/plex-status").status_code == 401
response = client.get("/", headers={"Accept": "text/html"})
assert response.status_code == 303
assert response.headers["location"] == "/auth/login"

# A valid session cookie authenticates the API.
session_header = {"Cookie": f"{auth.SESSION_COOKIE}={session}"}
assert client.get("/api/plex-status", headers=session_header).status_code == 200

# Cookie-authenticated state changes reject cross-site origins.
cross_site = client.post(
    "/api/plex-disconnect",
    headers={**session_header, "Origin": "http://evil.example"},
)
assert cross_site.status_code == 403
same_origin = client.post(
    "/api/plex-disconnect",
    headers={**session_header, "Origin": "http://testserver"},
)
assert same_origin.status_code == 200

# Auth settings can be read and updated by an authenticated session.
settings_response = client.get("/api/auth-settings", headers=session_header)
assert settings_response.status_code == 200
assert settings_response.json()["enabled"] is True
assert settings_response.json()["allowed_users"] == "1,owner"

lockout = client.post(
    "/api/auth-settings",
    headers=session_header,
    json={"enabled": True, "allowed_users": "", "allow_any_user": False},
)
assert lockout.status_code == 400

updated = client.post(
    "/api/auth-settings",
    headers=session_header,
    json={"session_ttl_hours": 12, "cookie_secure": False},
)
assert updated.status_code == 200
assert updated.json()["session_ttl_hours"] == 12
assert "session_secret" not in updated.json()
assert plexserver.settings.datastore.get_auth_settings()["session_ttl_hours"] == 12

# Enabling is two-step: pending until a successful Plex login completes it.
disabled = client.post("/api/auth-settings", headers=session_header, json={"enabled": False})
assert disabled.status_code == 200
assert disabled.json()["enabled"] is False
pending = client.post(
    "/api/auth-settings",
    headers=session_header,
    json={"enabled": True, "allowed_users": "1,owner"},
)
assert pending.status_code == 200
assert pending.json()["enabled"] is False
assert pending.json()["pending_enable"] is True
auth.complete_pending_enable()
assert plexserver.settings.auth_enabled is True
assert plexserver.settings.auth_pending_enable is False

# Emergency recovery token issues an admin session.
recovery = client.get("/api/plex-status?recovery=test-recovery", follow_redirects=False)
assert recovery.status_code == 303
recovery_cookie = recovery.headers["set-cookie"].split(";", 1)[0]
assert client.get("/api/plex-status", headers={"Cookie": recovery_cookie}).status_code == 200
"""


def test_plex_auth_prototype(tmp_path):
    env = os.environ.copy()
    env["CONFIG_PATH"] = str(tmp_path / "config")
    env["AUTH_ENABLED"] = "true"
    env["AUTH_SESSION_SECRET"] = "test-session-secret"
    env["AUTH_ALLOWED_USERS"] = "1,owner"
    env["AUTH_COOKIE_SECURE"] = "false"
    env["AUTH_RECOVERY_TOKEN"] = "test-recovery"

    result = subprocess.run(
        [sys.executable, "-c", _SCRIPT],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr
