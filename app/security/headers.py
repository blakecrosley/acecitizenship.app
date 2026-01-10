"""
Plus Ultra Security Headers Module

Implements hardened security headers for A+ ratings on:
- SecurityHeaders.com
- Mozilla Observatory

Headers implemented:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection (legacy, but still useful)
- Referrer-Policy
- Permissions-Policy (comprehensive deny list)
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Resource-Policy (CORP) - for API endpoints only
"""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add hardened security headers to all responses.

    This middleware implements Plus Ultra security headers for maximum
    protection while maintaining compatibility with CDN-loaded resources.
    """

    # Comprehensive Permissions-Policy denying all unused features
    PERMISSIONS_POLICY = ", ".join([
        "accelerometer=()",
        "ambient-light-sensor=()",
        "autoplay=()",
        "battery=()",
        "camera=()",
        "cross-origin-isolated=()",
        "display-capture=()",
        "document-domain=()",
        "encrypted-media=()",
        "execution-while-not-rendered=()",
        "execution-while-out-of-viewport=()",
        "fullscreen=()",
        "geolocation=()",
        "gyroscope=()",
        "keyboard-map=()",
        "magnetometer=()",
        "microphone=()",
        "midi=()",
        "navigation-override=()",
        "payment=()",
        "picture-in-picture=()",
        "publickey-credentials-get=()",
        "screen-wake-lock=()",
        "sync-xhr=()",
        "usb=()",
        "web-share=()",
        "xr-spatial-tracking=()",
    ])

    # Content Security Policy for sites using CDN resources
    # Note: 'unsafe-inline' required for Alpine.js x-data attributes
    CSP_DIRECTIVES = {
        "default-src": "'self'",
        "script-src": "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://static.cloudflareinsights.com",
        "style-src": "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
        "font-src": "'self' https://cdn.jsdelivr.net https://fonts.gstatic.com",
        "img-src": "'self' data: https:",
        "connect-src": "'self' https://cloudflareinsights.com",
        "media-src": "'self'",
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
        "upgrade-insecure-requests": "",
    }

    def __init__(self, app, csp_overrides: dict | None = None):
        """Initialize with optional CSP directive overrides.

        Args:
            app: The ASGI application
            csp_overrides: Optional dict to override default CSP directives
        """
        super().__init__(app)
        self.csp_directives = {**self.CSP_DIRECTIVES}
        if csp_overrides:
            self.csp_directives.update(csp_overrides)

        # Build CSP string
        self.csp = "; ".join(
            f"{key} {value}".strip() if value else key
            for key, value in self.csp_directives.items()
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # === Core Security Headers ===

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking (redundant with CSP frame-ancestors but broader support)
        response.headers["X-Frame-Options"] = "DENY"

        # Legacy XSS protection (modern browsers use CSP, but older ones need this)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Control referrer information leakage
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # === Transport Security ===

        # Enforce HTTPS for 1 year, include subdomains
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # === Cross-Origin Policies ===

        # Prevent other sites from opening this site in a popup and accessing window.opener
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        # Note: Cross-Origin-Embedder-Policy (COEP) is intentionally NOT set
        # because it requires all CDN resources to have CORP headers, which
        # most CDNs (jsdelivr, unpkg, etc.) don't provide. Setting COEP
        # would break Bootstrap, HTMX, and Alpine.js loaded from CDNs.

        # === Content Security Policy ===
        response.headers["Content-Security-Policy"] = self.csp

        # === Feature/Permissions Policy ===
        # Comprehensive deny list for browser features we don't use
        response.headers["Permissions-Policy"] = self.PERMISSIONS_POLICY

        # === Cache Headers for Static Assets ===
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            # Add CORP for static assets (safe since they're self-hosted)
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        return response


class APISecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Stricter security headers for API-only endpoints.

    This middleware adds Cross-Origin-Resource-Policy: same-origin
    to all responses, which is safe for API endpoints that don't
    serve resources to cross-origin contexts.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # API responses should not be embeddable cross-origin
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # API responses typically don't need caching
        if "Cache-Control" not in response.headers:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"

        return response
