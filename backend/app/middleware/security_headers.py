"""ASGI middleware that injects security headers on every response.

Headers follow OWASP best-practice recommendations and the project's
Content-Security-Policy baseline.  HSTS is only emitted when
``settings.is_production`` is true to avoid locking development
environments into HTTPS.
"""

from __future__ import annotations

from typing import Any, Callable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import settings

# Pre-computed header pairs (name, value) — avoids re-encoding per request.
_COMMON_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"x-xss-protection", b"0"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (
        b"content-security-policy",
        b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
    ),
    (b"cache-control", b"no-store"),
]

_HSTS_HEADER: tuple[bytes, bytes] = (
    b"strict-transport-security",
    b"max-age=63072000; includeSubDomains",
)


class SecurityHeadersMiddleware:
    """Pure ASGI middleware that appends security headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        # Build the full header list once at startup.
        self._headers = list(_COMMON_HEADERS)
        if settings.is_production:
            self._headers.append(_HSTS_HEADER)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def _inject_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers: list[tuple[bytes, bytes]] = list(
                    message.get("headers", [])
                )
                headers.extend(self._headers)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, _inject_headers)
