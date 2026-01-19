"""Security Logging Middleware"""

import os
import re
import time
from typing import Pattern

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.security.axiom import get_axiom_client, create_event


THREAT_PATTERNS: dict[str, Pattern] = {
    "sql_injection": re.compile(
        r"(\%27)|(\')|(--)|(\%23)|(#)|"
        r"(union\s+(all\s+)?select)|"
        r"(select\s+.+\s+from)|"
        r"(insert\s+into)|"
        r"(drop\s+table)|"
        r"(update\s+.+\s+set)|"
        r"(delete\s+from)|"
        r"(exec\s*\()|"
        r"(execute\s*\()",
        re.IGNORECASE,
    ),
    "xss": re.compile(
        r"(<script)|"
        r"(javascript\s*:)|"
        r"(on(error|load|click|mouse|focus|blur)\s*=)|"
        r"(<img[^>]+onerror)|"
        r"(<svg[^>]+onload)|"
        r"(expression\s*\()",
        re.IGNORECASE,
    ),
    "path_traversal": re.compile(
        r"(\.\./)|"
        r"(\.\.\\)|"
        r"(%2e%2e%2f)|"
        r"(%2e%2e/)|"
        r"(\.%2e/)|"
        r"(%2e\./)|(etc/passwd)|(etc/shadow)",
        re.IGNORECASE,
    ),
    "wordpress_probe": re.compile(
        r"(/wp-admin)|"
        r"(/wp-content)|"
        r"(/wp-includes)|"
        r"(/xmlrpc\.php)|"
        r"(/wp-login\.php)|"
        r"(/wp-config)|"
        r"(/wordpress/)",
        re.IGNORECASE,
    ),
    "admin_probe": re.compile(
        r"(/phpmyadmin)|"
        r"(/adminer)|"
        r"(/admin\.php)|"
        r"(/manager/)|"
        r"(/administrator/)|"
        r"(/cgi-bin/)|"
        r"(/\.env)|"
        r"(/\.git)|"
        r"(/config\.php)|"
        r"(/database\.yml)",
        re.IGNORECASE,
    ),
}

SCANNER_AGENTS: Pattern = re.compile(
    r"(nikto)|"
    r"(sqlmap)|"
    r"(nmap)|"
    r"(masscan)|"
    r"(zgrab)|"
    r"(gobuster)|"
    r"(dirbuster)|"
    r"(wpscan)|"
    r"(nuclei)|"
    r"(httpx)|"
    r"(curl/)|"
    r"(python-requests)|"
    r"(go-http-client)|"
    r"(libwww-perl)|"
    r"(wget)|"
    r"(scrapy)",
    re.IGNORECASE,
)

SUSPICIOUS_METHODS = {"TRACE", "TRACK", "OPTIONS", "CONNECT"}
SITE_NAME = os.getenv("SITE_NAME", "acecitizenship.app")


def detect_threats(
    path: str, query: str, user_agent: str, method: str
) -> tuple[str | None, str | None]:
    target = f"{path}?{query}" if query else path
    for threat_type, pattern in THREAT_PATTERNS.items():
        match = pattern.search(target)
        if match:
            return threat_type, match.group(0)
    if user_agent:
        match = SCANNER_AGENTS.search(user_agent)
        if match:
            return "scanner", match.group(0)
    if method.upper() in SUSPICIOUS_METHODS:
        return "suspicious_method", method
    return None, None


def get_client_ip(request: Request) -> str:
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"


class SecurityLogMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        site_name: str = SITE_NAME,
        log_all: bool = True,
        log_threats_only: bool = False,
    ):
        super().__init__(app)
        self.site_name = site_name
        self.log_all = log_all
        self.log_threats_only = log_threats_only
        self.axiom = get_axiom_client()

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.perf_counter()
        ip = get_client_ip(request)
        country = request.headers.get("CF-IPCountry", "")
        user_agent = request.headers.get("User-Agent", "")
        path = request.url.path
        query = str(request.query_params)
        method = request.method
        ray_id = request.headers.get("CF-Ray", "")
        referer = request.headers.get("Referer")
        threat_type, threat_details = detect_threats(path, query, user_agent, method)
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start_time) * 1000
        rate_limited = response.status_code == 429
        should_log = (
            self.log_all
            or threat_type is not None
            or rate_limited
            or response.status_code >= 400
        )
        if self.log_threats_only:
            should_log = threat_type is not None or rate_limited
        if should_log:
            event = create_event(
                site=self.site_name,
                ip=ip,
                country=country,
                user_agent=user_agent[:500] if user_agent else "",
                method=method,
                path=path,
                query=query[:500] if query else "",
                status=response.status_code,
                duration_ms=round(duration_ms, 2),
                ray_id=ray_id,
                threat_type=threat_type,
                threat_details=threat_details,
                rate_limited=rate_limited,
                referer=referer[:500] if referer else None,
            )
            await self.axiom.log_event(event)
        return response
