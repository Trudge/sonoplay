"""Plex-backed authentication for the local SonoPlay UI and API.

This is a prototype. It uses Plex's PIN/OAuth flow as the identity provider
and issues a signed, HttpOnly session cookie. Plex access tokens are validated
against plex.tv and never stored in the browser or logs.

Enable with:
    AUTH_ENABLED=true
    AUTH_ALLOWED_USERS=<plex user id or username>[, ...]
    AUTH_SESSION_SECRET=<long random string>   # optional but recommended
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

import aiohttp
from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from settings import settings
from utils import g, xml2dict
from version import VERSION

logger = logging.getLogger(__name__)

PLEX_PINS = "https://plex.tv/api/v2/pins"
PLEX_PIN = "https://plex.tv/api/v2/pins/{pin_id}"
PLEX_USER = "https://plex.tv/api/v2/user"

SESSION_COOKIE = "sonoplay_session"
_PUBLIC_PATHS = {
    "/health",
    "/auth/login",
    "/auth/check",
    "/auth/logout",
    "/favicon.ico",
}
_PUBLIC_PREFIXES = ("/static/", "/stream/")
_CALLBACK_PREFIX = "/dlna/callback/"
_DOC_PATHS = {"/docs", "/openapi.json", "/redoc"}

_TOKEN_CACHE_TTL = 600
_token_cache: dict[str, tuple[float, dict | None]] = {}
_rate_windows: dict[tuple[str, str], deque] = defaultdict(deque)
_ephemeral_secret = secrets.token_bytes(32)


def _session_secret() -> bytes:
    if settings.auth_session_secret:
        return settings.auth_session_secret.encode("utf-8")
    return _ephemeral_secret


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def issue_session(user: dict, *, recovery: bool = False) -> str:
    """Create a signed session value containing only non-secret identity data."""
    now = int(time.time())
    payload = {
        "sub": "recovery" if recovery else str(user.get("id") or user.get("uuid") or ""),
        "name": "Recovery" if recovery else str(user.get("username") or user.get("title") or ""),
        "recovery": True if recovery else False,
        "iat": now,
        "exp": now + int(settings.auth_session_ttl_hours * 3600),
    }
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(_session_secret(), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64encode(signature)}"


def verify_session(value: str | None) -> dict | None:
    """Validate a session cookie and return its payload, or None."""
    if not value or "." not in value:
        return None
    body, encoded_signature = value.rsplit(".", 1)
    try:
        signature = _b64decode(encoded_signature)
        expected = hmac.new(_session_secret(), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(_b64decode(body))
        if int(payload.get("exp", 0)) <= int(time.time()):
            return None
        return payload
    except Exception:
        return None


def _allowed_users() -> set[str]:
    return {
        item.strip().lower()
        for item in settings.auth_allowed_users.split(",")
        if item.strip()
    }


def is_user_allowed(user: dict) -> bool:
    allowed = _allowed_users()
    if not allowed:
        # Fail closed unless the operator explicitly opts into open signup.
        return bool(settings.auth_allow_any_user)
    candidates = {
        str(user.get("id", "")).lower(),
        str(user.get("sub", "")).lower(),
        str(user.get("uuid", "")).lower(),
        str(user.get("username", "")).lower(),
        str(user.get("title", "")).lower(),
        str(user.get("email", "")).lower(),
    }
    return bool(candidates & allowed)


def _auth_headers(extra: dict | None = None) -> dict:
    headers = {
        "X-Plex-Product": settings.product or "SonoPlay",
        "X-Plex-Client-Identifier": settings.auth_client_identifier,
        "X-Plex-Device-Name": "SonoPlay Web",
        "X-Plex-Platform": settings.platform,
        "X-Plex-Platform-Version": settings.platform_version,
        "X-Plex-Version": VERSION,
    }
    if extra:
        headers.update(extra)
    return headers


async def create_pin() -> tuple[str, str]:
    """Request a Plex PIN and return (code, pin_id)."""
    if g.http is None:
        raise RuntimeError("HTTP client is not initialized")
    timeout = aiohttp.ClientTimeout(total=settings.http_timeout_plex_tv)
    async with g.http.post(
        PLEX_PINS,
        params={"strong": "true"},
        headers=_auth_headers({"Accept": "application/xml"}),
        timeout=timeout,
    ) as response:
        response.raise_for_status()
        data = xml2dict(await response.text())
        pin = data["pin"]
        return pin["@code"], str(pin["@id"])


async def check_pin(pin_id: str) -> str | None:
    """Check a Plex PIN and return its auth token once approved."""
    if g.http is None:
        return None
    timeout = aiohttp.ClientTimeout(total=settings.http_timeout_plex_tv)
    async with g.http.get(
        PLEX_PIN.format(pin_id=pin_id),
        headers=_auth_headers({"Accept": "application/xml"}),
        timeout=timeout,
    ) as response:
        if response.status == 404:
            return None
        response.raise_for_status()
        data = xml2dict(await response.text())
        token = data["pin"].get("@authToken")
        return str(token) if token else None


async def validate_plex_token(token: str) -> dict | None:
    """Validate a Plex token against plex.tv, with a short-lived cache.

    Only a SHA-256 hash of the token is used as the cache key; the token itself
    is never written to logs or persisted.
    """
    if not token or g.http is None:
        return None
    cache_key = hashlib.sha256(token.encode("utf-8")).hexdigest()
    cached = _token_cache.get(cache_key)
    now = time.time()
    if cached is not None and cached[0] > now:
        return cached[1]

    timeout = aiohttp.ClientTimeout(total=settings.http_timeout_plex_tv)
    headers = _auth_headers({
        "Accept": "application/json",
        "X-Plex-Token": token,
    })
    try:
        async with g.http.get(PLEX_USER, headers=headers, timeout=timeout) as response:
            if response.status in (401, 403):
                _token_cache[cache_key] = (now + 60, None)
                return None
            response.raise_for_status()
            user = await response.json(content_type=None)
    except Exception as exc:
        logger.warning("Plex token validation failed: %s", exc.__class__.__name__)
        _token_cache[cache_key] = (now + 30, None)
        return None

    if not isinstance(user, dict) or not user.get("id"):
        _token_cache[cache_key] = (now + 60, None)
        return None
    if len(_token_cache) > 2048:
        _token_cache.clear()
    _token_cache[cache_key] = (now + _TOKEN_CACHE_TTL, user)
    return user


def callback_token(uuid: str) -> str:
    """Return a stable HMAC for authenticating DLNA event callbacks."""
    return hmac.new(
        _session_secret(),
        f"dlna-callback:{uuid}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_callback_token(uuid: str, token: str | None) -> bool:
    if not token:
        return False
    return hmac.compare_digest(token, callback_token(uuid))


def stream_token(uuid: str, resource: str, ttl_seconds: int = 21600) -> str:
    """Create a signed, expiring proxy token for one Plex media resource."""
    payload = {
        "u": uuid,
        "r": resource,
        "exp": int(time.time()) + ttl_seconds,
    }
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(_session_secret(), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64encode(signature)}"


def verify_stream_token(token: str) -> tuple[str, str] | None:
    """Validate a signed media-proxy token and return (uuid, resource)."""
    if not token or "." not in token:
        return None
    body, encoded_signature = token.rsplit(".", 1)
    try:
        signature = _b64decode(encoded_signature)
        expected = hmac.new(_session_secret(), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(_b64decode(body))
        if int(payload.get("exp", 0)) <= int(time.time()):
            return None
        resource = str(payload.get("r", ""))
        uuid = str(payload.get("u", ""))
        if not resource.startswith("/") or not uuid:
            return None
        return uuid, resource
    except Exception:
        return None


def rate_limit(request: Request, bucket: str, limit: int | None = None) -> bool:
    """Simple per-client sliding-window limiter for login endpoints."""
    limit = limit or settings.auth_rate_limit_per_minute
    client = request.client.host if request.client else "unknown"
    key = (bucket, client)
    window = _rate_windows[key]
    now = time.monotonic()
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= limit:
        return False
    window.append(now)
    if len(_rate_windows) > 1024:
        for k in list(_rate_windows):
            if not _rate_windows[k]:
                del _rate_windows[k]
    return True


def complete_pending_enable() -> None:
    """Enable auth only after a successful, allowed Plex login."""
    settings.datastore.set_auth_settings({"enabled": True, "pending_enable": False})
    object.__setattr__(settings, "auth_enabled", True)
    object.__setattr__(settings, "auth_pending_enable", False)


def _same_origin(request: Request) -> bool:
    """Reject browser cross-site state changes when using cookie auth."""
    origin = request.headers.get("origin")
    if origin:
        parsed = urlparse(origin)
        if parsed.netloc != request.headers.get("host", ""):
            return False
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site and fetch_site not in ("same-origin", "none"):
        return False
    return True


def _unauthorized(request: Request):
    if request.method in ("GET", "HEAD") and "text/html" in request.headers.get("accept", ""):
        return RedirectResponse("/auth/login", status_code=303)
    return JSONResponse({"detail": "Authentication required"}, status_code=401)


async def auth_middleware(request: Request, call_next):
    """Protect every route except health, static assets, and login endpoints."""
    if not settings.auth_enabled:
        return await call_next(request)

    path = request.url.path
    if path in _PUBLIC_PATHS or path.startswith(_PUBLIC_PREFIXES):
        return await call_next(request)
    if path.startswith(_CALLBACK_PREFIX):
        # The callback route verifies its own per-device HMAC.
        return await call_next(request)
    if path in _DOC_PATHS:
        return JSONResponse({"detail": "Not Found"}, status_code=404)

    recovery_token = settings.auth_recovery_token
    if recovery_token and request.query_params.get("recovery") == recovery_token:
        cookie_value = issue_session({}, recovery=True)
        if request.method in ("GET", "HEAD"):
            response = RedirectResponse(request.url.path, status_code=303)
        else:
            response = await call_next(request)
        response.set_cookie(
            SESSION_COOKIE,
            cookie_value,
            max_age=int(settings.auth_session_ttl_hours * 3600),
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite="strict",
            path="/",
        )
        return response

    token = request.headers.get("X-Plex-Token") or request.query_params.get("token")
    if token:
        user = await validate_plex_token(token)
        if user is not None and is_user_allowed(user):
            request.state.auth_method = "token"
            request.state.plex_user = user
            return await call_next(request)

    session = verify_session(request.cookies.get(SESSION_COOKIE))
    if session is not None and (session.get("recovery") or is_user_allowed(session)):
        if request.method not in ("GET", "HEAD", "OPTIONS") and not _same_origin(request):
            return JSONResponse({"detail": "Cross-site request rejected"}, status_code=403)
        request.state.auth_method = "session"
        request.state.plex_user = session
        return await call_next(request)

    return _unauthorized(request)


def install_middleware(app) -> None:
    app.middleware("http")(auth_middleware)
    if settings.auth_enabled:
        if not settings.auth_allowed_users.strip() and not settings.auth_allow_any_user:
            logger.warning(
                "AUTH_ENABLED is on but AUTH_ALLOWED_USERS is empty; "
                "all Plex logins will be rejected. Set AUTH_ALLOWED_USERS."
            )
        if not settings.auth_session_secret:
            logger.warning(
                "AUTH_SESSION_SECRET is not set; sessions will be invalidated on restart"
            )
