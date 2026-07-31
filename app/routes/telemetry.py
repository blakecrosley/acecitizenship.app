"""
Telemetry ingest for the Ace Citizenship iOS app.

One endpoint, write-only, no auth: the app POSTs small batches of anonymous
product-interaction events. This is the missing half of the monetization
picture — App Store Connect reports installs and purchases, but nothing about
what happens in between (how much people study, whether the daily free
allowance actually binds, whether they ever reach the paywall).

Privacy posture, which the client mirrors:
- `install_id` is a random UUID the app makes up about itself. Not the IDFV,
  not the IDFA, not derived from hardware or the user.
- No names, emails, answers, or free text. `props` is counters only.
- Nothing here identifies a person, so nothing here needs to be deleted on
  request — there is no person to tie it to.
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import TelemetryEvent

router = APIRouter(tags=["telemetry"])

# Bounds. The client batches ~10 at a time; anything far past that is either a
# long offline backlog or someone poking at the endpoint.
MAX_EVENTS_PER_BATCH = 200
MAX_PROP_KEYS = 20
MAX_STRING = 128

# Only names the app actually sends. An unknown name is dropped rather than
# stored, so a typo in a future client can't quietly pollute the table.
ALLOWED_EVENTS = {
    "app_opened",
    "set_completed",
    "paywall_shown",
    "purchase_tapped",
    "purchase_succeeded",
    "restore_tapped",
}


class IncomingEvent(BaseModel):
    name: str = Field(max_length=64)
    at: str = Field(max_length=64)
    props: dict[str, str] = Field(default_factory=dict)

    @field_validator("props")
    @classmethod
    def bound_props(cls, v: dict[str, str]) -> dict[str, str]:
        trimmed = {}
        for i, (key, value) in enumerate(v.items()):
            if i >= MAX_PROP_KEYS:
                break
            trimmed[str(key)[:MAX_STRING]] = str(value)[:MAX_STRING]
        return trimmed


class TelemetryBatch(BaseModel):
    install_id: str = Field(max_length=64)
    app_version: str = Field(default="?", max_length=32)
    events: list[IncomingEvent] = Field(default_factory=list)


def _parse_at(value: str) -> datetime:
    """Client timestamps are ISO8601 UTC. Fall back to now on anything odd —
    a malformed clock should not cost us the event."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, TypeError):
        return datetime.utcnow()


@router.post("/api/telemetry")
async def ingest(
    batch: TelemetryBatch,
    request: Request,
    db: Session = Depends(get_db),
):
    """Accept a batch of events. Always 200 on a well-formed body so the client
    clears its queue; malformed events are dropped, not retried forever."""
    if len(batch.events) > MAX_EVENTS_PER_BATCH:
        batch.events = batch.events[:MAX_EVENTS_PER_BATCH]

    stored = 0
    for event in batch.events:
        if event.name not in ALLOWED_EVENTS:
            continue
        db.add(
            TelemetryEvent(
                install_id=batch.install_id[:64],
                app_version=batch.app_version[:32],
                name=event.name,
                at=_parse_at(event.at),
                props=json.dumps(event.props) if event.props else None,
            )
        )
        stored += 1

    if stored:
        db.commit()

    return JSONResponse({"ok": True, "stored": stored})
