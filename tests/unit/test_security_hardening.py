import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_SCRIPT = r"""
import os
import stat
from pathlib import Path

from fastapi.datastructures import QueryParams

from plex import plex_auth
from plex.adapters import PlexLib
from dlna.discover import is_safe_dlna_url
from settings import atomic_write_json
from utils import xml2dict
from datetime import datetime, timedelta, timezone
import asyncio
from plex.subscribe import SubscribeManager
from utils import g

# Client-supplied network overrides must be ignored.
plex_lib = PlexLib()
plex_lib.update(QueryParams("address=169.254.169.254&port=80&protocol=http&token=t&machineIdentifier=m"))
assert plex_lib.address == ""
assert plex_lib.port == ""
assert plex_lib.protocol == ""
assert plex_lib.token == "t"
assert plex_lib.machine_id == "m"

# Connection resolution only accepts trusted plex.tv resources, never the query.
class FakeResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def raise_for_status(self):
        return None

    async def json(self, *args, **kwargs):
        return [{
            "clientIdentifier": "m",
            "connections": [
                {"protocol": "https", "uri": "https://1.2.3.4:443", "local": False},
                {"protocol": "https", "uri": "https://10.0.0.5:32400", "local": True},
            ],
        }]


class FakeHttp:
    def get(self, *args, **kwargs):
        return FakeResponse()


g.http = FakeHttp()
plex_lib.token = "t"
plex_lib.machine_id = "m"
asyncio.run(plex_lib.resolve_connection())
assert plex_lib.address == "10.0.0.5"
assert plex_lib.port == "32400"
assert plex_lib.protocol == "https"

# DLNA URLs must stay on private LAN addresses.
assert is_safe_dlna_url("http://192.168.1.20:1400/desc.xml")
assert not is_safe_dlna_url("http://127.0.0.1:80/")
assert not is_safe_dlna_url("http://169.254.169.254/latest/meta-data/")
assert not is_safe_dlna_url("http://8.8.8.8/")
assert not is_safe_dlna_url("file:///etc/passwd")
assert not is_safe_dlna_url("http://192.168.1.21/desc.xml", "http://192.168.1.20/desc.xml")

# XML parser rejects DTDs/entities and oversized documents.
for xml in (
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY y "z">]><x>&y;</x>',
    '<?xml version="1.0"?><x>' + ("a" * (2 * 1024 * 1024 + 1)) + "</x>",
):
    try:
        xml2dict(xml)
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe XML was accepted")

# Stream proxy tokens are signed, expiring, and tamper-evident.
token = plex_auth.stream_token("device-1", "/library/parts/1/file.flac")
assert plex_auth.verify_stream_token(token) == ("device-1", "/library/parts/1/file.flac")
body, signature = token.split(".", 1)
assert plex_auth.verify_stream_token(body[:-1] + ("A" if body[-1] != "A" else "B") + "." + signature) is None
assert plex_auth.verify_stream_token(plex_auth.stream_token("device-1", "http://evil")) is None

# Auth fails closed for an empty allowlist unless explicitly opened.
plex_auth.settings.auth_allowed_users = ""
plex_auth.settings.auth_allow_any_user = False
assert not plex_auth.is_user_allowed({"id": "1"})
plex_auth.settings.auth_allow_any_user = True
assert plex_auth.is_user_allowed({"id": "1"})

# Re-subscribing refreshes last_seen so active subscribers survive TTL cleanup.
manager = SubscribeManager()
asyncio.run(manager.add_subscriber("target", "client", "192.168.1.50", 3005))
subscriber = manager.subscribers["target"][0]
old_seen = datetime.now(timezone.utc) - timedelta(seconds=600)
subscriber.last_seen = old_seen
asyncio.run(manager.add_subscriber("target", "client", "192.168.1.50", 3005))
assert subscriber.last_seen > old_seen

# Stream proxy rejects unsigned tokens; security headers are present.
from fastapi.testclient import TestClient
import plex.plexserver as plexserver
client = TestClient(plexserver.plex_server)
assert client.get("/stream/not-a-token").status_code == 403
health = client.get("/health")
assert health.headers.get("X-Content-Type-Options") == "nosniff"
assert "default-src 'self'" in health.headers.get("Content-Security-Policy", "")
auth_settings = client.get("/api/auth-settings")
assert auth_settings.status_code == 200
assert auth_settings.json()["enabled"] is False
lockout = client.post(
    "/api/auth-settings",
    json={"enabled": True, "allowed_users": "", "allow_any_user": False},
)
assert lockout.status_code == 400

# Config files are owner-only and written atomically.
path = Path(os.environ["CONFIG_PATH"]) / "secrets.json"
atomic_write_json(path, {"token": "s3cr3t"})
assert stat.S_IMODE(path.stat().st_mode) == 0o600
assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
"""


def test_security_hardening(tmp_path):
    env = os.environ.copy()
    env["CONFIG_PATH"] = str(tmp_path / "config")
    env["AUTH_ENABLED"] = "false"
    env["AUTH_ALLOWED_USERS"] = ""
    env["AUTH_ALLOW_ANY_USER"] = "false"
    env.pop("TRUSTED_HOSTS", None)

    result = subprocess.run(
        [sys.executable, "-c", _SCRIPT],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr
