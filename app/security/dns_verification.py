"""
DNS verification for search engine bots using FCrDNS.

FCrDNS (Forward-Confirmed Reverse DNS) is Google's official verification method:
1. Reverse DNS: Get hostname from IP address
2. Verify pattern: Hostname must match expected suffix (e.g., .googlebot.com)
3. Forward DNS: Resolve hostname back to IP, must match original

Security Note:
    This is the industry-standard method for verifying legitimate search engine bots.
    It prevents UA spoofing because attackers cannot forge DNS records.

Reference:
    https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
"""

import asyncio
import logging
import socket
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    """Status of a verification attempt."""
    VERIFIED = "verified"
    FAILED_PATTERN = "failed_pattern"  # Hostname didn't match expected pattern
    FAILED_FORWARD = "failed_forward"  # Forward DNS didn't confirm IP
    FAILED_NO_PTR = "failed_no_ptr"  # No reverse DNS record
    FAILED_DNS_ERROR = "failed_dns_error"  # DNS lookup error
    CACHED = "cached"  # Result from cache


@dataclass
class VerificationResult:
    """Result of a bot verification attempt."""
    is_verified: bool
    status: VerificationStatus
    hostname: Optional[str] = None
    details: Optional[str] = None
    cached: bool = False
    cache_age_seconds: Optional[float] = None

    def __str__(self) -> str:
        if self.is_verified:
            return f"VERIFIED via {self.hostname}"
        return f"FAILED: {self.status.value} - {self.details}"


@dataclass
class CacheEntry:
    """A cached verification result with TTL."""
    result: VerificationResult
    expires_at: float


class DNSVerifier:
    """
    Async DNS verifier using FCrDNS with caching.

    Cache TTLs:
    - Verified: 24 hours (legitimate bots are stable)
    - Failed (pattern/forward): 1 hour (allow retry for config changes)
    - Error (DNS issues): 5 minutes (transient errors)
    """

    # Cache TTLs in seconds
    TTL_VERIFIED = 86400  # 24 hours
    TTL_FAILED = 3600  # 1 hour
    TTL_ERROR = 300  # 5 minutes

    def __init__(self):
        self._cache: dict[str, CacheEntry] = {}
        self._last_cleanup = time.time()

    def _cleanup_cache(self) -> None:
        """Remove expired cache entries."""
        now = time.time()
        # Only cleanup every 5 minutes
        if now - self._last_cleanup < 300:
            return

        expired = [
            key for key, entry in self._cache.items()
            if entry.expires_at < now
        ]
        for key in expired:
            del self._cache[key]
        self._last_cleanup = now

    def _get_cached(self, cache_key: str) -> Optional[VerificationResult]:
        """Get a result from cache if not expired."""
        self._cleanup_cache()
        entry = self._cache.get(cache_key)
        if entry is None:
            return None
        if entry.expires_at < time.time():
            del self._cache[cache_key]
            return None
        # Return cached result with metadata
        result = VerificationResult(
            is_verified=entry.result.is_verified,
            status=VerificationStatus.CACHED,
            hostname=entry.result.hostname,
            details=f"Cached: {entry.result.status.value}",
            cached=True,
            cache_age_seconds=time.time() - (entry.expires_at - self._get_ttl(entry.result))
        )
        return result

    def _get_ttl(self, result: VerificationResult) -> float:
        """Get the appropriate TTL for a result."""
        if result.is_verified:
            return self.TTL_VERIFIED
        if result.status in (VerificationStatus.FAILED_NO_PTR, VerificationStatus.FAILED_DNS_ERROR):
            return self.TTL_ERROR
        return self.TTL_FAILED

    def _cache_result(self, cache_key: str, result: VerificationResult) -> None:
        """Cache a verification result with appropriate TTL."""
        ttl = self._get_ttl(result)
        self._cache[cache_key] = CacheEntry(
            result=result,
            expires_at=time.time() + ttl
        )

    async def verify_fcrdns(
        self,
        ip_address: str,
        expected_patterns: list[str],
        bot_name: str = "unknown"
    ) -> VerificationResult:
        """
        Verify an IP address using FCrDNS.

        Args:
            ip_address: The IP address to verify
            expected_patterns: List of DNS suffix patterns (e.g., [".googlebot.com", ".google.com"])
            bot_name: Name of the bot for logging

        Returns:
            VerificationResult with verification status
        """
        cache_key = f"{ip_address}:{bot_name}"

        # Check cache first
        cached = self._get_cached(cache_key)
        if cached is not None:
            logger.debug(f"DNS verification cache hit for {ip_address} ({bot_name})")
            return cached

        try:
            # Step 1: Reverse DNS lookup (IP -> hostname)
            hostname = await self._reverse_lookup(ip_address)
            if hostname is None:
                result = VerificationResult(
                    is_verified=False,
                    status=VerificationStatus.FAILED_NO_PTR,
                    details=f"No PTR record for {ip_address}"
                )
                self._cache_result(cache_key, result)
                logger.info(f"FCrDNS failed for {bot_name}: No PTR record for {ip_address}")
                return result

            hostname = hostname.lower()

            # Step 2: Verify hostname matches expected pattern
            pattern_match = any(
                hostname.endswith(pattern.lower())
                for pattern in expected_patterns
            )
            if not pattern_match:
                result = VerificationResult(
                    is_verified=False,
                    status=VerificationStatus.FAILED_PATTERN,
                    hostname=hostname,
                    details=f"Hostname {hostname} doesn't match patterns {expected_patterns}"
                )
                self._cache_result(cache_key, result)
                logger.warning(
                    f"FCrDNS failed for {bot_name}: {hostname} doesn't match "
                    f"expected patterns {expected_patterns} (IP: {ip_address})"
                )
                return result

            # Step 3: Forward DNS lookup (hostname -> IP)
            resolved_ips = await self._forward_lookup(hostname)
            if ip_address not in resolved_ips:
                result = VerificationResult(
                    is_verified=False,
                    status=VerificationStatus.FAILED_FORWARD,
                    hostname=hostname,
                    details=f"Forward DNS for {hostname} returned {resolved_ips}, expected {ip_address}"
                )
                self._cache_result(cache_key, result)
                logger.warning(
                    f"FCrDNS failed for {bot_name}: Forward DNS mismatch "
                    f"(hostname={hostname}, expected={ip_address}, got={resolved_ips})"
                )
                return result

            # Success!
            result = VerificationResult(
                is_verified=True,
                status=VerificationStatus.VERIFIED,
                hostname=hostname,
                details=f"Verified via FCrDNS: {hostname}"
            )
            self._cache_result(cache_key, result)
            logger.info(f"FCrDNS verified {bot_name}: {ip_address} -> {hostname}")
            return result

        except socket.herror as e:
            result = VerificationResult(
                is_verified=False,
                status=VerificationStatus.FAILED_DNS_ERROR,
                details=f"DNS error: {e}"
            )
            self._cache_result(cache_key, result)
            logger.error(f"DNS error verifying {bot_name} ({ip_address}): {e}")
            return result

        except Exception as e:
            result = VerificationResult(
                is_verified=False,
                status=VerificationStatus.FAILED_DNS_ERROR,
                details=f"Unexpected error: {e}"
            )
            self._cache_result(cache_key, result)
            logger.error(f"Unexpected error verifying {bot_name} ({ip_address}): {e}")
            return result

    async def _reverse_lookup(self, ip_address: str) -> Optional[str]:
        """
        Perform reverse DNS lookup (IP -> hostname).

        Returns the hostname or None if no PTR record exists.
        """
        try:
            result = await asyncio.to_thread(
                socket.gethostbyaddr, ip_address
            )
            return result[0]  # (hostname, aliaslist, ipaddrlist)
        except socket.herror:
            return None

    async def _forward_lookup(self, hostname: str) -> list[str]:
        """
        Perform forward DNS lookup (hostname -> IPs).

        Returns list of IP addresses the hostname resolves to.
        """
        try:
            result = await asyncio.to_thread(
                socket.gethostbyname_ex, hostname
            )
            return result[2]  # (hostname, aliaslist, ipaddrlist)
        except socket.gaierror:
            return []

    def clear_cache(self) -> None:
        """Clear the verification cache."""
        self._cache.clear()

    def cache_stats(self) -> dict:
        """Get cache statistics."""
        now = time.time()
        valid_entries = sum(
            1 for entry in self._cache.values()
            if entry.expires_at > now
        )
        return {
            "total_entries": len(self._cache),
            "valid_entries": valid_entries,
            "expired_entries": len(self._cache) - valid_entries,
        }


# Global instance for convenience
_dns_verifier: Optional[DNSVerifier] = None


def get_dns_verifier() -> DNSVerifier:
    """Get or create the global DNS verifier instance."""
    global _dns_verifier
    if _dns_verifier is None:
        _dns_verifier = DNSVerifier()
    return _dns_verifier


async def verify_fcrdns(
    ip_address: str,
    expected_patterns: list[str],
    bot_name: str = "unknown"
) -> VerificationResult:
    """
    Convenience function for FCrDNS verification using the global instance.

    Args:
        ip_address: The IP address to verify
        expected_patterns: List of DNS suffix patterns
        bot_name: Name of the bot for logging

    Returns:
        VerificationResult with verification status
    """
    verifier = get_dns_verifier()
    return await verifier.verify_fcrdns(ip_address, expected_patterns, bot_name)
