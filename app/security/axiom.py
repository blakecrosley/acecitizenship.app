"""Axiom Log Shipping Client"""

import asyncio
import json
import os
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any

import httpx


@dataclass
class SecurityEvent:
    timestamp: str
    site: str
    ip: str
    country: str
    user_agent: str
    method: str
    path: str
    query: str
    status: int
    duration_ms: float
    ray_id: str
    threat_type: str | None = None
    threat_details: str | None = None
    rate_limited: bool = False
    bot_score: int | None = None
    referer: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


class AxiomClient:
    def __init__(
        self,
        token: str | None = None,
        dataset: str = "security",
        batch_size: int = 100,
        flush_interval: float = 10.0,
        site_name: str = "acecitizenship.app",
    ):
        self.token = token or os.getenv("AXIOM_TOKEN", "")
        self.dataset = dataset
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.site_name = site_name
        self.ingest_url = f"https://api.axiom.co/v1/datasets/{dataset}/ingest"
        self._buffer: list[dict] = []
        self._last_flush = time.time()
        self._flush_lock = asyncio.Lock()
        self._flush_task: asyncio.Task | None = None
        self.events_sent = 0
        self.events_failed = 0
        self._headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/x-ndjson",
        }

    @property
    def is_enabled(self) -> bool:
        return bool(self.token)

    async def log_event(self, event: "SecurityEvent") -> None:
        if not self.is_enabled:
            return
        self._buffer.append(event.to_dict())
        should_flush = (
            len(self._buffer) >= self.batch_size
            or time.time() - self._last_flush >= self.flush_interval
        )
        if should_flush:
            asyncio.create_task(self._safe_flush())

    async def _safe_flush(self) -> None:
        try:
            await self.flush()
        except Exception:
            pass

    async def flush(self) -> None:
        if not self._buffer or not self.is_enabled:
            return
        async with self._flush_lock:
            if not self._buffer:
                return
            events = self._buffer
            self._buffer = []
            self._last_flush = time.time()
            ndjson = "\n".join(json.dumps(e) for e in events)
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.post(
                        self.ingest_url, headers=self._headers, content=ndjson
                    )
                    if response.status_code == 200:
                        self.events_sent += len(events)
                    else:
                        self.events_failed += len(events)
                        self._buffer = events + self._buffer
            except Exception:
                self.events_failed += len(events)
                self._buffer = events + self._buffer

    async def stop(self) -> None:
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self.flush()


_axiom_client: AxiomClient | None = None


def get_axiom_client() -> AxiomClient:
    global _axiom_client
    if _axiom_client is None:
        _axiom_client = AxiomClient(
            dataset=os.getenv("AXIOM_DATASET", "security"),
            site_name=os.getenv("SITE_NAME", "acecitizenship.app"),
        )
    return _axiom_client


def create_event(
    *,
    site: str,
    ip: str,
    country: str,
    user_agent: str,
    method: str,
    path: str,
    query: str,
    status: int,
    duration_ms: float,
    ray_id: str,
    threat_type: str | None = None,
    threat_details: str | None = None,
    rate_limited: bool = False,
    bot_score: int | None = None,
    referer: str | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        site=site,
        ip=ip,
        country=country or "Unknown",
        user_agent=user_agent or "Unknown",
        method=method,
        path=path,
        query=query,
        status=status,
        duration_ms=duration_ms,
        ray_id=ray_id or "local",
        threat_type=threat_type,
        threat_details=threat_details,
        rate_limited=rate_limited,
        bot_score=bot_score,
        referer=referer,
    )
