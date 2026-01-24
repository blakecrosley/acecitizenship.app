"""
Bot patterns for verification-based rate limiting.

This module defines:
- SEARCH_BOT_PATTERNS: Bots verifiable via FCrDNS (Forward-Confirmed Reverse DNS)
- FCRDNS_PATTERNS: DNS suffix patterns for each search engine
- AI_CRAWLER_PATTERNS: AI bots with published IP ranges
- AI_CRAWLER_IP_SOURCES: URLs to fetch IP ranges for AI crawlers
- ALLOWED_BOTS: Legitimate bots without verification method (high limits, not unlimited)
- BLOCKED_PATTERNS: Known attack tools (immediate 403)

Security Note:
    SEARCH_BOT_PATTERNS and AI_CRAWLER_PATTERNS require verification.
    ALLOWED_BOTS get high limits but cannot be verified, so not unlimited.
"""

import re
from typing import Pattern

# =============================================================================
# SEARCH ENGINE BOTS (Verifiable via FCrDNS)
# =============================================================================

# UA patterns that claim to be search engine bots
# These MUST be verified via FCrDNS before granting unlimited access
SEARCH_BOT_PATTERNS: dict[str, list[str]] = {
    "google": [
        "googlebot",
        "google-extended",
        "googleother",
        "google-inspectiontool",
        "storebot-google",
        "apis-google",
    ],
    "bing": [
        "bingbot",
        "bingpreview",
        "msnbot",
    ],
    "apple": [
        "applebot",
        "applebot-extended",
    ],
    "yandex": [
        "yandexbot",
        "yandexaccessibilitybot",
        "yandexmobilebot",
        "yandexdirectdyn",
        "yandexscreenshotbot",
        "yandexblogs",
        "yandexfavicons",
        "yandexvideo",
        "yandexwebmaster",
        "yandexnews",
    ],
    "duckduckgo": [
        "duckduckbot",
        "duckduckgo-favicons-bot",
    ],
    "baidu": [
        "baiduspider",
        "baiduspider-mobile",
        "baiduspider-image",
        "baiduspider-video",
        "baiduspider-news",
    ],
}

# DNS suffix patterns for FCrDNS verification
# Reverse DNS hostname must end with one of these suffixes
FCRDNS_PATTERNS: dict[str, list[str]] = {
    "google": [
        ".googlebot.com",
        ".google.com",
    ],
    "bing": [
        ".search.msn.com",
    ],
    "apple": [
        ".applebot.apple.com",
    ],
    "yandex": [
        ".yandex.ru",
        ".yandex.net",
        ".yandex.com",
    ],
    "duckduckgo": [
        ".duckduckgo.com",
    ],
    "baidu": [
        ".baidu.com",
        ".baidu.jp",
    ],
}

# =============================================================================
# AI CRAWLER BOTS (Verifiable via IP Ranges)
# =============================================================================

# UA patterns that claim to be AI crawlers
# These should be verified via published IP ranges
AI_CRAWLER_PATTERNS: dict[str, list[str]] = {
    "openai": [
        "gptbot",
        "chatgpt-user",
        "oai-searchbot",
    ],
    "anthropic": [
        "claudebot",
        "claude-web",
        "anthropic-ai",
    ],
    "perplexity": [
        "perplexitybot",
    ],
    "meta": [
        "meta-externalagent",
        "meta-externalfetcher",
        "facebookbot",
    ],
    "google_ai": [
        "gemini",
    ],
    "xai": [
        "xai",
        "grok",
    ],
    "amazon": [
        "amazonbot",
    ],
    "cohere": [
        "cohere-ai",
    ],
    "bytedance": [
        "bytespider",
    ],
    "commoncrawl": [
        "ccbot",
    ],
}

# URLs to fetch published IP ranges for AI crawlers
# None means no published source (verify manually or allow with limits)
AI_CRAWLER_IP_SOURCES: dict[str, str | None] = {
    "openai": "https://openai.com/gptbot.json",
    "anthropic": None,  # Check docs manually
    "perplexity": None,  # No published list
    "meta": None,  # No published list for crawlers
    "google_ai": None,  # Part of Google's broader ranges
    "xai": None,  # No published list
    "amazon": None,  # No published list
    "cohere": None,  # No published list
    "bytedance": None,  # No published list
    "commoncrawl": None,  # Uses AWS IPs, no static list
}

# =============================================================================
# ALLOWED BOTS (No verification method - high limits, not unlimited)
# =============================================================================

# These bots are legitimate but cannot be verified
# They get high limits (1000/min) but not unlimited access
ALLOWED_BOTS: set[str] = {
    # Testing
    "testclient",  # FastAPI TestClient - bypasses rate limits in tests
    # Social media link previews
    "facebookexternalhit",
    "twitterbot",
    "linkedinbot",
    "discordbot",
    "slackbot",
    "telegrambot",
    "whatsapp",
    "pinterestbot",
    "redditbot",
    # SEO tools
    "ahrefsbot",
    "semrushbot",
    "mj12bot",
    "dotbot",
    "seranking",
    "dataforseobot",
    "serpstatbot",
    "rogerbot",
    "screaming frog",
    # Monitoring tools
    "uptimerobot",
    "pingdom",
    "gtmetrix",
    "lighthouse",
    "pagespeedonline",
    "chrome-lighthouse",
    # Feed readers
    "feedly",
    "feedbin",
    "newsblur",
    # Other legitimate
    "neevabot",
    "img2dataset",
    "archive.org_bot",
    "ia_archiver",
}

# =============================================================================
# BLOCKED PATTERNS (Known attack tools)
# =============================================================================

# Regex patterns for known attack tools - return 403 immediately
BLOCKED_PATTERNS: list[Pattern[str]] = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"nikto",
        r"sqlmap",
        r"masscan",
        r"nmap",
        r"wp-scan",
        r"wpscan",
        r"havij",
        r"acunetix",
        r"nessus",
        r"openvas",
        r"burpsuite",
        r"dirbuster",
        r"gobuster",
        r"nuclei",
        r"zgrab",
        r"wfuzz",
        r"hydra",
        r"metasploit",
    ]
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def identify_search_bot(user_agent: str) -> str | None:
    """
    Identify which search bot is claimed in the user agent.

    Returns the bot category (google, bing, etc.) or None if not a search bot.
    """
    ua_lower = user_agent.lower()
    for bot_name, patterns in SEARCH_BOT_PATTERNS.items():
        for pattern in patterns:
            if pattern in ua_lower:
                return bot_name
    return None


def identify_ai_crawler(user_agent: str) -> str | None:
    """
    Identify which AI crawler is claimed in the user agent.

    Returns the crawler category (openai, anthropic, etc.) or None if not an AI crawler.
    """
    ua_lower = user_agent.lower()
    for crawler_name, patterns in AI_CRAWLER_PATTERNS.items():
        for pattern in patterns:
            if pattern in ua_lower:
                return crawler_name
    return None


def is_allowed_bot(user_agent: str) -> bool:
    """Check if the user agent matches an allowed (unverifiable) bot."""
    ua_lower = user_agent.lower()
    return any(bot in ua_lower for bot in ALLOWED_BOTS)


def is_blocked(user_agent: str) -> bool:
    """Check if the user agent matches a blocked attack tool pattern."""
    return any(pattern.search(user_agent) for pattern in BLOCKED_PATTERNS)


def get_fcrdns_patterns(bot_name: str) -> list[str]:
    """Get the FCrDNS patterns for a given search bot."""
    return FCRDNS_PATTERNS.get(bot_name, [])


def get_ip_source(crawler_name: str) -> str | None:
    """Get the IP range source URL for an AI crawler."""
    return AI_CRAWLER_IP_SOURCES.get(crawler_name)
