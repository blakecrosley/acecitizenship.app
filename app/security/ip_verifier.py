"""
IP range verification for AI crawlers.

Some AI crawlers publish their IP ranges (e.g., OpenAI's GPTBot).
This module verifies that requests claiming to be from these crawlers
actually originate from their published IP ranges.

Security Note:
    This is a secondary verification method. Unlike FCrDNS, IP ranges can
    be spoofed in some network configurations, but it's still useful for
    reducing the attack surface.

Reference:
    OpenAI: https://openai.com/gptbot.json
"""

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class IPVerificationResult:
    """Result of IP range verification."""
    is_verified: bool
    matched_range: Optional[str] = None
    bot_name: Optional[str] = None
    details: Optional[str] = None

    def __str__(self) -> str:
        if self.is_verified:
            return f"VERIFIED: {self.bot_name} ({self.matched_range})"
        return f"NOT VERIFIED: {self.details}"


@dataclass
class IPRangeVerifier:
    """
    Verifies IP addresses against known bot IP ranges.

    Supports both IPv4 and IPv6 CIDR notation.
    """

    # Pre-loaded IP ranges for known bots
    # These are manually maintained based on published sources
    _ranges: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = field(
        default_factory=dict
    )

    def __post_init__(self):
        """Initialize with known IP ranges."""
        self._load_default_ranges()

    def _load_default_ranges(self) -> None:
        """Load default known IP ranges for bots."""
        # OpenAI GPTBot ranges (from https://openai.com/gptbot.json)
        # These should be updated periodically
        openai_ranges = [
            # IPv4 ranges
            "20.15.240.64/28",
            "20.15.240.80/28",
            "20.15.240.96/28",
            "20.15.240.176/28",
            "20.15.241.0/28",
            "20.15.242.128/28",
            "20.15.242.144/28",
            "20.15.242.192/28",
            "40.83.2.64/28",
            "52.230.152.0/24",
            "52.233.106.0/24",
            # Add more as needed
        ]

        # Anthropic ClaudeBot ranges
        # From: https://docs.anthropic.com/en/docs/resources/ip-addresses
        anthropic_ranges = [
            "160.79.104.0/23",
        ]

        # Common Crawl (ccbot) - uses AWS ranges, too broad to list
        # We'll rely on UA matching + rate limiting for these

        # Store parsed networks
        self._ranges = {
            "openai": self._parse_ranges(openai_ranges),
            "anthropic": self._parse_ranges(anthropic_ranges),
        }

        logger.info(
            f"Loaded IP ranges: {', '.join(f'{k}={len(v)}' for k, v in self._ranges.items())}"
        )

    def _parse_ranges(
        self, cidr_strings: list[str]
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse CIDR strings into network objects."""
        networks = []
        for cidr in cidr_strings:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                networks.append(network)
            except ValueError as e:
                logger.warning(f"Invalid CIDR {cidr}: {e}")
        return networks

    def add_ranges(self, bot_name: str, cidr_strings: list[str]) -> int:
        """
        Add IP ranges for a bot.

        Args:
            bot_name: Name of the bot (e.g., "openai", "anthropic")
            cidr_strings: List of CIDR strings (e.g., ["20.15.240.64/28"])

        Returns:
            Number of valid ranges added
        """
        networks = self._parse_ranges(cidr_strings)
        if bot_name in self._ranges:
            self._ranges[bot_name].extend(networks)
        else:
            self._ranges[bot_name] = networks

        logger.info(f"Added {len(networks)} IP ranges for {bot_name}")
        return len(networks)

    def clear_ranges(self, bot_name: Optional[str] = None) -> None:
        """
        Clear IP ranges for a bot or all bots.

        Args:
            bot_name: Bot to clear ranges for, or None to clear all
        """
        if bot_name:
            self._ranges.pop(bot_name, None)
        else:
            self._ranges.clear()

    def verify_ip(self, ip_address: str, bot_name: str) -> IPVerificationResult:
        """
        Verify an IP address is in the known ranges for a bot.

        Args:
            ip_address: The IP address to verify
            bot_name: The claimed bot identity

        Returns:
            IPVerificationResult with verification status
        """
        # Check if we have ranges for this bot
        if bot_name not in self._ranges:
            return IPVerificationResult(
                is_verified=False,
                bot_name=bot_name,
                details=f"No IP ranges registered for {bot_name}"
            )

        if not self._ranges[bot_name]:
            return IPVerificationResult(
                is_verified=False,
                bot_name=bot_name,
                details=f"Empty IP range list for {bot_name}"
            )

        try:
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return IPVerificationResult(
                is_verified=False,
                bot_name=bot_name,
                details=f"Invalid IP address: {ip_address}"
            )

        # Check against all ranges for this bot
        for network in self._ranges[bot_name]:
            if ip in network:
                return IPVerificationResult(
                    is_verified=True,
                    matched_range=str(network),
                    bot_name=bot_name,
                    details=f"IP {ip_address} verified in {network}"
                )

        return IPVerificationResult(
            is_verified=False,
            bot_name=bot_name,
            details=f"IP {ip_address} not in any {bot_name} range"
        )

    def has_ranges(self, bot_name: str) -> bool:
        """Check if we have IP ranges for a bot."""
        return bool(self._ranges.get(bot_name))

    def list_bots_with_ranges(self) -> list[str]:
        """List all bots that have IP ranges configured."""
        return [name for name, ranges in self._ranges.items() if ranges]

    def get_range_count(self, bot_name: str) -> int:
        """Get the number of IP ranges for a bot."""
        return len(self._ranges.get(bot_name, []))

    def stats(self) -> dict:
        """Get statistics about loaded IP ranges."""
        return {
            "bots_with_ranges": self.list_bots_with_ranges(),
            "total_ranges": sum(len(r) for r in self._ranges.values()),
            "ranges_by_bot": {name: len(ranges) for name, ranges in self._ranges.items()},
        }


# Global instance
_ip_verifier: Optional[IPRangeVerifier] = None


def get_ip_verifier() -> IPRangeVerifier:
    """Get or create the global IP verifier instance."""
    global _ip_verifier
    if _ip_verifier is None:
        _ip_verifier = IPRangeVerifier()
    return _ip_verifier


def verify_ip(ip_address: str, bot_name: str) -> IPVerificationResult:
    """
    Convenience function for IP verification using the global instance.

    Args:
        ip_address: The IP address to verify
        bot_name: The claimed bot identity

    Returns:
        IPVerificationResult with verification status
    """
    verifier = get_ip_verifier()
    return verifier.verify_ip(ip_address, bot_name)
