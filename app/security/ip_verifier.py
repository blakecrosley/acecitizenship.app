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
        # OpenAI combined ranges (GPTBot + ChatGPT-User + SearchBot)
        # Sources: gptbot.json, chatgpt-user.json, searchbot.json
        # Updated: 2026-01-24 - 270 unique IPv4 ranges
        openai_ranges = [
            "104.210.139.192/28", "104.210.139.224/28", "104.210.140.128/28",
            "13.65.138.112/28", "13.65.138.96/28", "13.67.46.240/28",
            "13.67.72.16/28", "13.70.107.160/28", "13.71.2.208/28",
            "13.76.115.224/28", "13.76.115.240/28", "13.76.116.80/28",
            "13.76.223.48/28", "13.76.32.208/28", "13.79.43.0/28",
            "13.83.167.128/28", "13.83.237.176/28", "132.196.82.48/28",
            "132.196.86.0/24", "135.119.134.128/28", "135.119.134.192/28",
            "135.220.73.208/28", "135.220.73.240/28", "135.234.64.0/24",
            "135.237.131.208/28", "135.237.133.112/28", "135.237.133.48/28",
            "137.135.183.96/28", "137.135.190.240/28", "137.135.191.176/28",
            "137.135.191.32/28", "138.91.30.48/28", "138.91.46.96/28",
            "168.63.252.240/28", "172.178.140.144/28", "172.178.141.112/28",
            "172.178.141.128/28", "172.182.193.224/28", "172.182.193.80/28",
            "172.182.194.144/28", "172.182.194.32/28", "172.182.195.48/28",
            "172.182.202.0/25", "172.182.204.0/24", "172.182.207.0/25",
            "172.182.209.208/28", "172.182.211.192/28", "172.182.213.192/28",
            "172.182.214.0/24", "172.182.215.0/24", "172.182.224.0/28",
            "172.183.143.224/28", "172.183.222.128/28", "172.203.190.128/28",
            "172.204.16.64/28", "172.212.159.64/28", "172.213.11.144/28",
            "172.213.12.112/28", "172.213.21.112/28", "172.213.21.144/28",
            "172.213.21.16/28", "191.233.1.128/28", "191.233.194.32/28",
            "191.233.196.112/28", "191.233.199.160/28", "191.233.2.0/28",
            "191.234.167.128/28", "191.235.66.16/28", "191.235.98.144/28",
            "191.235.99.80/28", "191.237.249.64/28", "191.239.245.16/28",
            "20.0.53.96/28", "20.102.212.144/28", "20.117.22.224/28",
            "20.125.112.224/28", "20.125.144.144/28", "20.125.66.80/28",
            "20.14.99.96/28", "20.161.75.208/28", "20.168.18.32/28",
            "20.168.7.192/28", "20.168.7.240/28", "20.169.6.224/28",
            "20.169.7.48/28", "20.169.72.112/28", "20.169.72.96/28",
            "20.169.73.176/28", "20.169.73.32/28", "20.169.73.64/28",
            "20.169.77.0/25", "20.169.78.112/28", "20.169.78.128/28",
            "20.169.78.144/28", "20.169.78.160/28", "20.169.78.176/28",
            "20.169.78.192/28", "20.169.78.48/28", "20.169.78.64/28",
            "20.169.78.80/28", "20.169.78.96/28", "20.171.123.64/28",
            "20.171.206.0/24", "20.171.207.0/24", "20.171.53.224/28",
            "20.172.29.32/28", "20.193.50.32/28", "20.194.0.208/28",
            "20.194.1.0/28", "20.194.157.176/28", "20.198.67.96/28",
            "20.204.24.240/28", "20.210.154.128/28", "20.210.174.208/28",
            "20.210.211.192/28", "20.215.187.208/28", "20.215.188.192/28",
            "20.215.214.16/28", "20.215.219.128/28", "20.215.219.160/28",
            "20.215.219.208/28", "20.215.220.112/28", "20.215.220.128/28",
            "20.215.220.144/28", "20.215.220.160/28", "20.215.220.176/28",
            "20.215.220.192/28", "20.215.220.208/28", "20.215.220.64/28",
            "20.215.220.80/28", "20.215.220.96/28", "20.227.140.32/28",
            "20.228.106.176/28", "20.235.75.208/28", "20.235.87.224/28",
            "20.249.63.208/28", "20.25.151.224/28", "20.27.94.128/28",
            "20.42.10.176/28", "20.45.178.144/28", "20.55.229.144/28",
            "20.63.221.64/28", "20.90.7.144/28", "20.97.189.96/28",
            "23.102.140.144/28", "23.102.141.32/28", "23.97.109.224/28",
            "23.98.142.176/28", "23.98.179.16/28", "23.98.186.176/28",
            "23.98.186.192/28", "23.98.186.64/28", "23.98.186.96/28",
            "4.151.119.48/28", "4.151.241.240/28", "4.151.71.176/28",
            "4.189.118.208/28", "4.189.119.48/28", "4.196.118.112/28",
            "4.196.198.80/28", "4.197.115.112/28", "4.197.19.176/28",
            "4.197.22.112/28", "4.197.64.0/28", "4.197.64.16/28",
            "4.197.64.48/28", "4.197.64.64/28", "4.205.128.176/28",
            "4.227.36.0/25", "40.116.73.208/28", "40.67.175.0/25",
            "40.67.183.160/28", "40.67.183.176/28", "40.75.14.224/28",
            "40.81.134.128/28", "40.81.134.144/28", "40.81.234.144/28",
            "40.84.181.32/28", "40.84.221.208/28", "40.84.221.224/28",
            "40.90.214.16/28", "51.8.102.0/24", "51.8.155.112/28",
            "51.8.155.48/28", "51.8.155.64/28", "51.8.155.80/28",
            "52.148.129.32/28", "52.154.22.48/28", "52.156.77.144/28",
            "52.159.227.32/28", "52.159.249.96/28", "52.165.212.16/28",
            "52.165.212.32/28", "52.165.212.48/28", "52.172.129.160/28",
            "52.173.123.0/28", "52.173.219.112/28", "52.173.219.96/28",
            "52.173.221.16/28", "52.173.221.176/28", "52.173.221.208/28",
            "52.173.234.16/28", "52.173.234.80/28", "52.173.235.80/28",
            "52.176.139.176/28", "52.187.246.128/28", "52.190.137.144/28",
            "52.190.137.16/28", "52.190.139.48/28", "52.190.142.64/28",
            "52.190.190.16/28", "52.225.75.208/28", "52.230.152.0/24",
            "52.230.163.32/28", "52.230.164.176/28", "52.231.30.48/28",
            "52.231.34.176/28", "52.231.39.144/28", "52.231.39.192/28",
            "52.231.49.48/28", "52.231.50.64/28", "52.236.94.144/28",
            "52.242.132.224/28", "52.242.132.240/28", "52.242.245.208/28",
            "52.252.113.240/28", "52.255.109.112/28", "52.255.109.128/28",
            "52.255.109.144/28", "52.255.109.80/28", "52.255.109.96/28",
            "52.255.111.0/28", "52.255.111.112/28", "52.255.111.16/28",
            "52.255.111.32/28", "52.255.111.48/28", "52.255.111.80/28",
            "57.154.174.112/28", "57.154.175.0/28", "57.154.187.32/28",
            "68.154.28.96/28", "68.218.30.112/28", "68.220.57.64/28",
            "68.221.67.160/28", "68.221.67.192/28", "68.221.67.224/28",
            "68.221.67.240/28", "68.221.75.16/28", "74.226.253.160/28",
            "74.249.86.176/28", "74.7.175.128/25", "74.7.227.0/25",
            "74.7.227.128/25", "74.7.228.0/25", "74.7.228.128/25",
            "74.7.229.0/25", "74.7.229.128/25", "74.7.230.0/25",
            "74.7.241.0/25", "74.7.241.128/25", "74.7.242.0/25",
            "74.7.242.128/25", "74.7.243.0/25", "74.7.243.128/25",
            "74.7.244.0/25", "74.7.35.112/28", "74.7.35.48/28",
            "74.7.36.64/28", "74.7.36.80/28", "74.7.36.96/28",
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
