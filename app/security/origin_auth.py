"""Origin-auth middleware: only requests that traversed Cloudflare reach the app.

Cloudflare injects ``X-Origin-Auth: <shared secret>`` on every request for this
site through a zone Transform Rule (request-header modification, which runs
before Workers, and the ``*-proxy`` Workers forward request headers). Anything
that arrives without the header came straight to the Railway hostname and is
answered 401, so the WAF, rate limits and bot rules in front of the site cannot
be bypassed.

Enforcement is keyed on the ``CF_ORIGIN_AUTH`` environment variable: unset
(local development, tests) means pass-through; set (production) means enforce.
Bypass paths are exact matches only (health checks that Railway sends directly).
The comparison is constant-time.
"""
from __future__ import annotations

import hmac
import logging
import os
from typing import Final, Iterable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

HEADER: Final[str] = "x-origin-auth"
ENV_VAR: Final[str] = "CF_ORIGIN_AUTH"


class OriginAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, bypass_paths: Iterable[str] = ()) -> None:
        super().__init__(app)
        self._secret = os.getenv(ENV_VAR, "").strip()
        self._bypass = frozenset(bypass_paths)
        if not self._secret:
            logger.warning("%s is unset: origin auth is OPEN (direct Railway access is not blocked)", ENV_VAR)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self._secret or request.url.path in self._bypass:
            return await call_next(request)
        provided = request.headers.get(HEADER, "")
        if not provided or not hmac.compare_digest(provided, self._secret):
            logger.warning(
                "origin_auth: missing or invalid X-Origin-Auth on %s %s (peer=%s)",
                request.method, request.url.path, request.client.host if request.client else "?",
            )
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)
