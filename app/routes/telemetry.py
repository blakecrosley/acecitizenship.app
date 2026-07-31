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

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import TelemetryEvent
from app.routes.auth import limiter

router = APIRouter(tags=["telemetry"])

# Bounds. The client batches ~10 at a time; anything far past that is either a
# long offline backlog or someone poking at the endpoint.
#
# These are enforced BEFORE the body is parsed (byte cap) and DURING validation
# (Field constraints), not after. Truncating a parsed model is too late: by then
# an attacker has already made us allocate whatever they sent.
MAX_EVENTS_PER_BATCH = 200
MAX_PROP_KEYS = 20
MAX_STRING = 128

# A full 200-event batch of bounded events is comfortably under 100 KB. Anything
# larger is not our client.
MAX_BODY_BYTES = 256 * 1024

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
    props: dict[str, str] = Field(default_factory=dict, max_length=MAX_PROP_KEYS)

    @field_validator("props")
    @classmethod
    def bound_props(cls, v: dict[str, str]) -> dict[str, str]:
        # Key/value lengths still need clamping — max_length above bounds the
        # number of keys, not their size.
        return {str(k)[:MAX_STRING]: str(val)[:MAX_STRING] for k, val in v.items()}


class TelemetryBatch(BaseModel):
    install_id: str = Field(max_length=64)
    app_version: str = Field(default="?", max_length=32)
    # Bounded during validation: an oversized batch is rejected (422), not
    # silently parsed and then trimmed.
    events: list[IncomingEvent] = Field(
        default_factory=list, max_length=MAX_EVENTS_PER_BATCH
    )


def _parse_at(value: str) -> datetime:
    """Client timestamps are ISO8601 UTC. Fall back to now on anything odd —
    a malformed clock should not cost us the event."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, TypeError):
        return datetime.utcnow()


@router.post("/api/telemetry")
@limiter.limit("30/minute")
async def ingest(
    request: Request,
    batch: TelemetryBatch,
    db: Session = Depends(get_db),
):
    """Accept a batch of events. Always 200 on a well-formed body so the client
    clears its queue; unknown events are dropped, not retried forever.

    This endpoint is unauthenticated by design — the client has no account and
    no credential to present. That makes it a public, persistent write, so it is
    bounded on three axes instead: requests per IP (decorator above), body bytes
    (below), and rows per request (model constraints). A real client sends one
    small batch every few minutes; 30/minute is far above that and far below
    anything that could grow the table meaningfully.
    """
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Batch too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="Bad Content-Length")

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
