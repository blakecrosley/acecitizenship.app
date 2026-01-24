"""
Rate limiting middleware with verified bot classification.

Bot Tiers (with verification):
- VERIFIED_SEARCH: FCrDNS verified search engines - UNLIMITED access
- VERIFIED_AI: IP range verified AI crawlers - UNLIMITED access
- ALLOWED: Legitimate bots without verification method - High limits (1000/min)
- UNVERIFIED_CLAIM: Claims to be a bot but failed verification - SUSPICIOUS
- BLOCKED: Known attack tools - 403 Forbidden
- ANONYMOUS: No bot claim - Regular limits (30/min)

Security Note:
    Bot identity is now verified cryptographically (FCrDNS for search engines,
    IP range for AI crawlers) to prevent UA spoofing attacks on rate limiting.
"""

import logging
import time
from collections import defaultdict
from typing import Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.security.bot_verification import (
    BotTier,
    BotVerificationResult,
    get_bot_verifier,
    verify_bot,
)

logger = logging.getLogger(__name__)

# =============================================================================
# RATE LIMIT TIERS
# =============================================================================

RATE_LIMITS = {
    "anonymous": "30/minute",
    # Verified bots - unlimited (cryptographically verified identity)
    "verified_search": "unlimited",
    "verified_ai": "unlimited",
    # Allowed bots - high limits (trusted but unverifiable)
    "allowed": "1000/minute",
    # Unverified claims - treat as suspicious, lower than anonymous
    "unverified_claim": "10/minute",
    # Legacy keys (backwards compatibility)
    "trusted_bot": "unlimited",
    "allowed_bot": "1000/minute",
}

# =============================================================================
# BOT TIER TO RATE LIMIT MAPPING
# =============================================================================

BOT_TIER_RATE_LIMITS: dict[BotTier, str] = {
    BotTier.VERIFIED_SEARCH: "verified_search",
    BotTier.VERIFIED_AI: "verified_ai",
    BotTier.ALLOWED: "allowed",
    BotTier.UNVERIFIED_CLAIM: "unverified_claim",
    BotTier.BLOCKED: "blocked",
    BotTier.ANONYMOUS: "anonymous",
}

RATE_LIMIT_VALUES = {}
for key, value in RATE_LIMITS.items():
    if value == "unlimited":
        RATE_LIMIT_VALUES[key] = None
    else:
        RATE_LIMIT_VALUES[key] = int(value.split("/")[0])


async def classify_bot_verified(
    user_agent: str,
    client_ip: str,
) -> tuple[str, Optional[BotVerificationResult]]:
    """Classify request with cryptographic bot verification."""
    result = await verify_bot(user_agent, client_ip)
    category = BOT_TIER_RATE_LIMITS.get(result.tier, "anonymous")

    if result.is_suspicious:
        logger.warning(
            f"Unverified bot claim: claimed={result.claimed_bot} "
            f"ip={client_ip} method={result.verification_method} "
            f"details={result.details}"
        )
    elif result.is_verified:
        logger.debug(
            f"Verified bot: {result.verified_as} ip={client_ip} "
            f"method={result.verification_method}"
        )

    return category, result


def get_client_ip(request: Request) -> str:
    """Extract client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class InMemoryRateLimiter:
    """Sliding window rate limiter."""

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.time()

    def _cleanup(self):
        now = time.time()
        if now - self._last_cleanup < 60:
            return
        cutoff = now - self.window_seconds
        for key in list(self._requests.keys()):
            self._requests[key] = [t for t in self._requests[key] if t > cutoff]
            if not self._requests[key]:
                del self._requests[key]
        self._last_cleanup = now

    def check(self, key: str, limit: int) -> tuple[bool, int, int]:
        """Check if allowed. Returns (allowed, remaining, reset_seconds)."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._cleanup()
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]
        current = len(self._requests[key])
        if current >= limit:
            oldest = min(self._requests[key]) if self._requests[key] else now
            reset = int(oldest + self.window_seconds - now) + 1
            return False, 0, reset
        self._requests[key].append(now)
        return True, limit - current - 1, self.window_seconds


_rate_limiter = InMemoryRateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware with verified bot classification."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        if path.startswith("/health") or path.startswith("/static"):
            return await call_next(request)

        user_agent = request.headers.get("user-agent", "")
        client_ip = get_client_ip(request)

        # Verify bot identity (FCrDNS for search engines, IP for AI crawlers)
        category, verification = await classify_bot_verified(user_agent, client_ip)

        # BLOCKED: Known attack tools - reject immediately
        if category == "blocked":
            logger.warning(
                f"Blocked attack tool: ip={client_ip} path={path} "
                f"user_agent={user_agent[:100]}"
            )
            return JSONResponse(status_code=403, content={"error": "Forbidden"})

        # VERIFIED BOTS: Skip rate limiting entirely (cryptographically verified)
        if category in ("verified_search", "verified_ai"):
            response = await call_next(request)
            response.headers["X-RateLimit-Category"] = category
            if verification:
                response.headers["X-Bot-Verified"] = verification.verified_as or ""
            return response

        # Get rate limit for this category
        limit = RATE_LIMIT_VALUES.get(category)
        if limit is None:
            response = await call_next(request)
            response.headers["X-RateLimit-Category"] = category
            return response

        # Check rate limit
        rate_key = f"{client_ip}:{category}"
        allowed, remaining, reset = _rate_limiter.check(rate_key, limit)

        if not allowed:
            log_extra = ""
            if verification and verification.is_suspicious:
                log_extra = f" claimed_bot={verification.claimed_bot}"
            logger.warning(
                f"Rate limit exceeded: ip={client_ip} category={category} "
                f"path={path}{log_extra} user_agent={user_agent[:100]}"
            )
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded"},
                headers={
                    "Retry-After": str(reset),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Category": category,
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Category"] = category
        return response
