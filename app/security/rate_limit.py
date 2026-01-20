"""
Rate limiting middleware with bot classification.

Bot Tiers:
- TRUSTED: Search engines & AI crawlers - UNLIMITED access
- ALLOWED: SEO tools, social previews - Very high limits (1000/min)
- BLOCKED: Known attack tools - 403 Forbidden
- Everyone else: Regular anonymous limits (30/min)
"""

import logging
import re
import time
from collections import defaultdict
from typing import Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# =============================================================================
# RATE LIMIT TIERS
# =============================================================================

RATE_LIMITS = {
    "anonymous": "30/minute",
    "trusted_bot": "unlimited",
    "allowed_bot": "1000/minute",
}

# =============================================================================
# BOT CLASSIFICATION
# =============================================================================

TRUSTED_BOTS = {
    "googlebot", "bingbot", "applebot", "applebot-extended", "duckduckbot",
    "yandexbot", "baiduspider", "slurp", "seznambot", "qwantify",
    "gptbot", "chatgpt-user", "oai-searchbot", "claudebot", "claude-web",
    "anthropic-ai", "perplexitybot", "google-extended", "gemini",
    "meta-externalagent", "meta-externalfetcher", "xai", "grok",
    "ccbot", "bytespider", "cohere-ai", "amazonbot", "ai2bot", "diffbot",
    "youbot", "mistral", "deepmind", "huggingface", "ai21", "fireworksai",
    "togetherai", "inflection", "replicatebot", "runwayml", "stabilityai",
}

ALLOWED_BOTS = {
    "facebookexternalhit", "facebookbot", "twitterbot", "linkedinbot",
    "discordbot", "slackbot", "telegrambot", "whatsapp", "pinterestbot",
    "redditbot", "ahrefsbot", "semrushbot", "mj12bot", "dotbot", "seranking",
    "dataforseobot", "serpstatbot", "rogerbot", "screaming frog",
    "uptimerobot", "pingdom", "gtmetrix", "lighthouse", "pagespeedonline",
    "neevabot", "img2dataset",
}

BLOCKED_PATTERNS = [
    r"nikto", r"sqlmap", r"masscan", r"nmap", r"wp-scan", r"wpscan",
    r"havij", r"acunetix", r"nessus", r"openvas", r"burpsuite",
    r"dirbuster", r"gobuster", r"nuclei", r"zgrab",
]

RATE_LIMIT_VALUES = {}
for key, value in RATE_LIMITS.items():
    if value == "unlimited":
        RATE_LIMIT_VALUES[key] = None
    else:
        RATE_LIMIT_VALUES[key] = int(value.split("/")[0])


def classify_bot(user_agent: str) -> Optional[str]:
    if not user_agent:
        return None
    ua_lower = user_agent.lower()
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, ua_lower):
            return "blocked"
    for bot in TRUSTED_BOTS:
        if bot in ua_lower:
            return "trusted_bot"
    for bot in ALLOWED_BOTS:
        if bot in ua_lower:
            return "allowed_bot"
    return None


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class InMemoryRateLimiter:
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
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if path.startswith("/health") or path.startswith("/static"):
            return await call_next(request)

        user_agent = request.headers.get("user-agent", "")
        bot_type = classify_bot(user_agent)
        client_ip = get_client_ip(request)

        if bot_type == "blocked":
            logger.warning(f"Blocked: ip={client_ip} path={path} ua={user_agent[:100]}")
            return JSONResponse(status_code=403, content={"error": "Forbidden"})

        if bot_type == "trusted_bot":
            response = await call_next(request)
            response.headers["X-RateLimit-Category"] = "trusted_bot"
            return response

        if bot_type == "allowed_bot":
            limit = RATE_LIMIT_VALUES["allowed_bot"]
            category = "allowed_bot"
        else:
            limit = RATE_LIMIT_VALUES["anonymous"]
            category = "anonymous"

        rate_key = f"{client_ip}:{category}"
        allowed, remaining, reset = _rate_limiter.check(rate_key, limit)

        if not allowed:
            logger.warning(f"Rate limit: ip={client_ip} cat={category} path={path}")
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded"},
                headers={"Retry-After": str(reset), "X-RateLimit-Limit": str(limit)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
