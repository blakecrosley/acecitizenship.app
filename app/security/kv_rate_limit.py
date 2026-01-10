"""
Cloudflare KV-backed rate limiting for FastAPI endpoints.

Provides distributed, persistent rate limiting that survives deploys
and works across multiple instances. Falls back to in-memory if KV
is unavailable.

Usage:
    @rate_limit_form_kv
    async def submit_form(request: Request, ...):
        ...
"""

import asyncio
import os
import time
from collections import defaultdict
from functools import wraps
from typing import Callable

import httpx
from fastapi import HTTPException, Request


# Cloudflare KV configuration
CF_ACCOUNT_ID = os.getenv("CF_ACCOUNT_ID", "0cbfc64a7f11a17453d2cb691107fa45")
CF_API_TOKEN = os.getenv("CF_API_TOKEN", "")
KV_NAMESPACE_ID = os.getenv("KV_RATE_LIMIT_NAMESPACE", "102b222e36ef416298b3414fa9d294a5")
SITE_NAME = os.getenv("SITE_NAME", "unknown")

# Rate limit settings
FORM_LIMIT = int(os.getenv("RATE_LIMIT_FORM", "5"))  # requests per minute
AUTH_LIMIT = int(os.getenv("RATE_LIMIT_AUTH", "10"))  # requests per minute
WINDOW_SECONDS = 60


class KVRateLimiter:
    """Cloudflare KV-backed rate limiter with in-memory fallback.

    Uses a simple counter approach with TTL-based expiration.
    If KV is unavailable, falls back to in-memory limiting.
    """

    def __init__(
        self,
        requests_per_minute: int,
        prefix: str = "rate",
        site_name: str = SITE_NAME,
    ):
        self.requests_per_minute = requests_per_minute
        self.prefix = prefix
        self.site_name = site_name

        # In-memory fallback
        self._fallback: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.time()

        # KV API configuration
        self._kv_base_url = (
            f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}"
            f"/storage/kv/namespaces/{KV_NAMESPACE_ID}/values"
        )
        self._headers = {
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Content-Type": "text/plain",
        }

        # Track if KV is available
        self._kv_available = bool(CF_API_TOKEN)

    def _get_window_key(self, client_ip: str) -> str:
        """Generate a unique key for the current time window."""
        window = int(time.time() // WINDOW_SECONDS)
        return f"{self.prefix}:{self.site_name}:{client_ip}:{window}"

    async def _kv_get(self, key: str) -> int | None:
        """Get value from Cloudflare KV."""
        if not self._kv_available:
            return None

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(
                    f"{self._kv_base_url}/{key}",
                    headers=self._headers,
                )
                if resp.status_code == 200:
                    return int(resp.text)
                elif resp.status_code == 404:
                    return 0
                return None
        except Exception:
            return None

    async def _kv_increment(self, key: str) -> bool:
        """Increment counter in Cloudflare KV with TTL."""
        if not self._kv_available:
            return False

        try:
            # Get current value
            current = await self._kv_get(key) or 0
            new_value = current + 1

            # Set new value with TTL
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.put(
                    f"{self._kv_base_url}/{key}",
                    headers=self._headers,
                    content=str(new_value),
                    params={"expiration_ttl": WINDOW_SECONDS + 10},  # Extra buffer
                )
                return resp.status_code == 200
        except Exception:
            return False

    def _fallback_check(self, key: str) -> bool:
        """In-memory fallback rate limiting."""
        current_time = time.time()
        cutoff = current_time - WINDOW_SECONDS

        # Cleanup old entries periodically
        if current_time - self._last_cleanup > WINDOW_SECONDS:
            for k in list(self._fallback.keys()):
                self._fallback[k] = [t for t in self._fallback[k] if t > cutoff]
                if not self._fallback[k]:
                    del self._fallback[k]
            self._last_cleanup = current_time

        # Filter to recent requests
        recent = [t for t in self._fallback[key] if t > cutoff]
        self._fallback[key] = recent

        if len(recent) >= self.requests_per_minute:
            return True  # Rate limited

        self._fallback[key].append(current_time)
        return False

    async def is_rate_limited(self, client_ip: str) -> bool:
        """Check if client is rate limited.

        Args:
            client_ip: Client's IP address

        Returns:
            True if rate limited, False otherwise
        """
        key = self._get_window_key(client_ip)

        # Try KV first
        count = await self._kv_get(key)
        if count is not None:
            if count >= self.requests_per_minute:
                return True

            # Increment counter
            if await self._kv_increment(key):
                return False

        # Fallback to in-memory
        return self._fallback_check(key)


def get_client_ip(request: Request) -> str:
    """Extract client IP from request, handling Cloudflare and proxies."""
    # Cloudflare provides the real IP in CF-Connecting-IP
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip

    # Standard forwarded header
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.client.host if request.client else "unknown"


# Global rate limiter instances
form_limiter_kv = KVRateLimiter(
    requests_per_minute=FORM_LIMIT,
    prefix="form",
)
auth_limiter_kv = KVRateLimiter(
    requests_per_minute=AUTH_LIMIT,
    prefix="auth",
)


def rate_limit_form_kv(func: Callable) -> Callable:
    """Decorator to rate limit form submissions using KV."""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = kwargs.get("request") or next(
            (arg for arg in args if isinstance(arg, Request)), None
        )
        if request:
            ip = get_client_ip(request)
            if await form_limiter_kv.is_rate_limited(ip):
                raise HTTPException(
                    status_code=429,
                    detail="Too many requests. Please try again later.",
                )
        return await func(*args, **kwargs)

    return wrapper


def rate_limit_auth_kv(func: Callable) -> Callable:
    """Decorator to rate limit authentication attempts using KV."""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = kwargs.get("request") or next(
            (arg for arg in args if isinstance(arg, Request)), None
        )
        if request:
            ip = get_client_ip(request)
            if await auth_limiter_kv.is_rate_limited(ip):
                raise HTTPException(
                    status_code=429,
                    detail="Too many login attempts. Please try again later.",
                )
        return await func(*args, **kwargs)

    return wrapper


# Async context manager for custom rate limiting
class RateLimitContext:
    """Context manager for custom rate limiting scenarios."""

    def __init__(
        self,
        request: Request,
        requests_per_minute: int = 10,
        prefix: str = "custom",
    ):
        self.request = request
        self.limiter = KVRateLimiter(
            requests_per_minute=requests_per_minute,
            prefix=prefix,
        )

    async def __aenter__(self):
        ip = get_client_ip(self.request)
        if await self.limiter.is_rate_limited(ip):
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please try again later.",
            )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
