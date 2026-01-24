"""
Bot Verification Module

Combines user-agent detection with DNS/IP verification to accurately
identify legitimate bots and prevent user-agent spoofing.

Verification Tiers:
- VERIFIED_SEARCH: Search bots verified via FCrDNS (Googlebot, Bingbot, etc.)
- VERIFIED_AI: AI crawlers verified via IP ranges (GPTBot, etc.)
- ALLOWED: Legitimate bots without verification method (Lighthouse, etc.)
- UNVERIFIED_CLAIM: Claims to be a bot but not verified (potential spoof)
- ANONYMOUS: No bot claim

Usage:
    from app.security.bot_verification import BotVerifier, BotTier

    verifier = BotVerifier()
    result = await verifier.verify(user_agent, client_ip)

    if result.tier == BotTier.VERIFIED_SEARCH:
        # Trusted search engine bot
        pass
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .bot_patterns import (
    identify_search_bot,
    identify_ai_crawler,
    is_allowed_bot,
    is_blocked,
    get_fcrdns_patterns,
)
from .dns_verification import DNSVerifier, VerificationResult, get_dns_verifier
from .ip_verifier import IPRangeVerifier, IPVerificationResult, get_ip_verifier

logger = logging.getLogger(__name__)


class BotTier(Enum):
    """Bot classification tiers for rate limiting."""
    VERIFIED_SEARCH = "verified_search"  # FCrDNS verified (Google, Bing, etc.)
    VERIFIED_AI = "verified_ai"  # IP range verified (OpenAI, etc.)
    ALLOWED = "allowed"  # Trusted but unverifiable (Lighthouse, etc.)
    UNVERIFIED_CLAIM = "unverified_claim"  # Claims bot UA but not verified
    BLOCKED = "blocked"  # Known attack tools
    ANONYMOUS = "anonymous"  # No bot claim


@dataclass
class BotVerificationResult:
    """Result of bot verification."""
    tier: BotTier
    claimed_bot: Optional[str] = None
    verified_as: Optional[str] = None
    verification_method: Optional[str] = None  # "fcrdns", "ip_range", "ua_match", None
    details: Optional[str] = None

    # DNS verification details (if applicable)
    dns_result: Optional[VerificationResult] = None

    # IP verification details (if applicable)
    ip_result: Optional[IPVerificationResult] = None

    @property
    def is_verified(self) -> bool:
        """Returns True if bot identity is cryptographically verified."""
        return self.tier in (BotTier.VERIFIED_SEARCH, BotTier.VERIFIED_AI)

    @property
    def is_trusted(self) -> bool:
        """Returns True if bot should get elevated rate limits."""
        return self.tier in (
            BotTier.VERIFIED_SEARCH,
            BotTier.VERIFIED_AI,
            BotTier.ALLOWED,
        )

    @property
    def is_suspicious(self) -> bool:
        """Returns True if bot claim couldn't be verified (potential spoof)."""
        return self.tier == BotTier.UNVERIFIED_CLAIM


class BotVerifier:
    """
    Main bot verification orchestrator.

    Combines DNS verification (for search engines) and IP verification
    (for AI crawlers) with UA pattern matching.
    """

    def __init__(
        self,
        dns_verifier: Optional[DNSVerifier] = None,
        ip_verifier: Optional[IPRangeVerifier] = None,
    ):
        self._dns_verifier = dns_verifier or get_dns_verifier()
        self._ip_verifier = ip_verifier or get_ip_verifier()

    async def verify(
        self,
        user_agent: str,
        client_ip: str,
    ) -> BotVerificationResult:
        """
        Verify a request's bot status.

        Args:
            user_agent: The User-Agent header
            client_ip: The client's IP address

        Returns:
            BotVerificationResult with tier and verification details
        """
        # Check for blocked attack tools first
        if is_blocked(user_agent):
            logger.warning(f"Blocked attack tool detected: ip={client_ip}")
            return BotVerificationResult(
                tier=BotTier.BLOCKED,
                details="Blocked attack tool pattern matched"
            )

        # Check for search engine bots (require FCrDNS verification)
        search_bot = identify_search_bot(user_agent)
        if search_bot:
            return await self._verify_search_bot(search_bot, client_ip, user_agent)

        # Check for AI crawlers (require IP range verification)
        ai_crawler = identify_ai_crawler(user_agent)
        if ai_crawler:
            return self._verify_ai_crawler(ai_crawler, client_ip, user_agent)

        # Check for allowed bots (no verification, but trusted)
        if is_allowed_bot(user_agent):
            return BotVerificationResult(
                tier=BotTier.ALLOWED,
                claimed_bot="allowed_bot",
                verification_method="ua_match",
                details="Matched allowed bot pattern"
            )

        # No bot claim - anonymous user
        return BotVerificationResult(
            tier=BotTier.ANONYMOUS,
            details="No bot pattern matched"
        )

    async def _verify_search_bot(
        self,
        bot_name: str,
        client_ip: str,
        user_agent: str,
    ) -> BotVerificationResult:
        """Verify a search engine bot using FCrDNS."""
        patterns = get_fcrdns_patterns(bot_name)

        if not patterns:
            # No DNS patterns for this bot - allow but mark as unverified
            logger.debug(f"No FCrDNS patterns for {bot_name}")
            return BotVerificationResult(
                tier=BotTier.ALLOWED,
                claimed_bot=bot_name,
                verification_method="ua_match",
                details=f"No FCrDNS patterns available for {bot_name}"
            )

        # Perform FCrDNS verification
        dns_result = await self._dns_verifier.verify_fcrdns(
            client_ip, patterns, bot_name
        )

        if dns_result.is_verified:
            return BotVerificationResult(
                tier=BotTier.VERIFIED_SEARCH,
                claimed_bot=bot_name,
                verified_as=bot_name,
                verification_method="fcrdns",
                details=f"FCrDNS verified: {dns_result.hostname}",
                dns_result=dns_result,
            )

        # FCrDNS failed - potential spoof
        logger.warning(
            f"Search bot verification failed: claimed={bot_name} ip={client_ip} "
            f"reason={dns_result.status.value}"
        )
        return BotVerificationResult(
            tier=BotTier.UNVERIFIED_CLAIM,
            claimed_bot=bot_name,
            verification_method="fcrdns",
            details=f"FCrDNS verification failed: {dns_result.details}",
            dns_result=dns_result,
        )

    def _verify_ai_crawler(
        self,
        crawler_name: str,
        client_ip: str,
        user_agent: str,
    ) -> BotVerificationResult:
        """Verify an AI crawler using IP ranges."""
        # Check if we have IP ranges for this crawler
        if not self._ip_verifier.has_ranges(crawler_name):
            # No IP ranges - allow with lower tier
            return BotVerificationResult(
                tier=BotTier.ALLOWED,
                claimed_bot=crawler_name,
                verification_method="ua_match",
                details=f"No IP ranges available for {crawler_name}"
            )

        # Verify IP
        ip_result = self._ip_verifier.verify_ip(client_ip, crawler_name)

        if ip_result.is_verified:
            return BotVerificationResult(
                tier=BotTier.VERIFIED_AI,
                claimed_bot=crawler_name,
                verified_as=crawler_name,
                verification_method="ip_range",
                details=f"IP verified in {ip_result.matched_range}",
                ip_result=ip_result,
            )

        # IP not in known ranges - potential spoof
        logger.warning(
            f"AI crawler verification failed: claimed={crawler_name} ip={client_ip} "
            f"reason={ip_result.details}"
        )
        return BotVerificationResult(
            tier=BotTier.UNVERIFIED_CLAIM,
            claimed_bot=crawler_name,
            verification_method="ip_range",
            details=f"IP verification failed: {ip_result.details}",
            ip_result=ip_result,
        )

    def verify_sync(
        self,
        user_agent: str,
        client_ip: str,
    ) -> BotVerificationResult:
        """
        Synchronous verification (without async DNS lookup).

        Note: This skips FCrDNS verification for search bots.
        Use the async verify() method when possible.
        """
        # Check for blocked attack tools
        if is_blocked(user_agent):
            return BotVerificationResult(
                tier=BotTier.BLOCKED,
                details="Blocked attack tool pattern matched"
            )

        # Check for search engine bots - cannot verify without async DNS
        search_bot = identify_search_bot(user_agent)
        if search_bot:
            return BotVerificationResult(
                tier=BotTier.UNVERIFIED_CLAIM,
                claimed_bot=search_bot,
                verification_method=None,
                details="FCrDNS verification requires async (use verify() instead)"
            )

        # Check for AI crawlers
        ai_crawler = identify_ai_crawler(user_agent)
        if ai_crawler:
            return self._verify_ai_crawler(ai_crawler, client_ip, user_agent)

        # Check for allowed bots
        if is_allowed_bot(user_agent):
            return BotVerificationResult(
                tier=BotTier.ALLOWED,
                claimed_bot="allowed_bot",
                verification_method="ua_match",
                details="Matched allowed bot pattern"
            )

        return BotVerificationResult(
            tier=BotTier.ANONYMOUS,
            details="No bot pattern matched"
        )


# Global instance
_bot_verifier: Optional[BotVerifier] = None


def get_bot_verifier() -> BotVerifier:
    """Get or create the global bot verifier instance."""
    global _bot_verifier
    if _bot_verifier is None:
        _bot_verifier = BotVerifier()
    return _bot_verifier


async def verify_bot(user_agent: str, client_ip: str) -> BotVerificationResult:
    """
    Convenience function for bot verification using the global instance.

    Args:
        user_agent: The User-Agent header
        client_ip: The client's IP address

    Returns:
        BotVerificationResult with tier and verification details
    """
    verifier = get_bot_verifier()
    return await verifier.verify(user_agent, client_ip)


def verify_bot_sync(user_agent: str, client_ip: str) -> BotVerificationResult:
    """
    Synchronous bot verification (skips FCrDNS for search bots).

    Use verify_bot() async version when possible.
    """
    verifier = get_bot_verifier()
    return verifier.verify_sync(user_agent, client_ip)
