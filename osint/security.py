"""Host/Origin checks and per-session CSRF for a local unauthenticated app."""

from __future__ import annotations

import hmac
import secrets
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from osint.config import STRICT_HOSTS, session_secret

SAFE_HOSTS = {
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "[::1]",
    "::1",
}

RELAXED_SUFFIXES = (
    ".googleusercontent.com",
    ".colab.research.google.com",
    ".grok.x.ai",
    ".x.ai",
    ".trycloudflare.com",
    ".ngrok-free.app",
    ".ngrok.io",
    ".loca.lt",
)


def host_allowed(host: str) -> bool:
    host = (host or "").split(":")[0].lower()
    if host in SAFE_HOSTS:
        return True
    if host.endswith(".localhost"):
        return True
    if not STRICT_HOSTS:
        if host:
            return True
    return False


def origin_ok(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    parsed = urlparse(origin)
    return host_allowed(parsed.hostname or "")


def ensure_session(request: Request) -> str:
    existing = request.cookies.get("session")
    if existing:
        return existing
    minted = getattr(request.state, "session", None)
    if minted:
        return minted
    minted = secrets.token_urlsafe(32)
    request.state.session = minted
    request.state.new_session = True
    return minted


def _csrf_from_session(session: str) -> str:
    return hmac.new(session_secret().encode("utf-8"), session.encode("utf-8"), "sha256").hexdigest()


def csrf_token(request: Request) -> str:
    session = ensure_session(request)
    return _csrf_from_session(session)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        host = request.headers.get("host", "")
        if not host_allowed(host):
            return JSONResponse({"error": "invalid host"}, status_code=421)
        ensure_session(request)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not origin_ok(request):
                return JSONResponse({"error": "invalid origin"}, status_code=403)
            if request.url.path.startswith("/api/"):
                token = request.headers.get("x-csrf-token") or request.cookies.get("csrf_token")
                session = request.cookies.get("session") or getattr(request.state, "session", "")
                expected = _csrf_from_session(session) if session else ""
                if not session or not token or not hmac.compare_digest(str(token), expected):
                    return JSONResponse({"error": "csrf"}, status_code=403)
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://grok.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'self'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        session = request.cookies.get("session") or getattr(request.state, "session", None)
        if session and (getattr(request.state, "new_session", False) or "csrf_token" not in request.cookies):
            if getattr(request.state, "new_session", False):
                response.set_cookie("session", session, httponly=True, samesite="lax", path="/")
            response.set_cookie(
                "csrf_token",
                _csrf_from_session(session),
                httponly=False,
                samesite="lax",
                path="/",
            )
        return response
