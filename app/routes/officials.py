"""
Current-officials data for the iOS app.

The August 2026 content audit found three stale officials baked into the app
binary (two governors sworn in January 2026, one senator appointed after a
death). Officials change on election night; App Store review takes days. This
endpoint is the fix: the app fetches it on launch and overrides its bundled
names, so correcting a governor is a one-line JSON edit and a deploy.

The data file is app/data/officials.json — edit it, commit, push. Railway
deploys it. Nothing else to touch.
"""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

router = APIRouter(tags=["officials"])

DATA_PATH = Path(__file__).parent.parent / "data" / "officials.json"


@router.get("/api/officials")
async def officials() -> JSONResponse:
    """Serve the current officials with a modest cache: clients and CDNs may
    hold it for an hour, which is fresh enough for names that change a few
    times a year while sparing the disk read on most requests."""
    try:
        data = json.loads(DATA_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        raise HTTPException(status_code=503, detail="Officials data unavailable")
    return JSONResponse(data, headers={"Cache-Control": "public, max-age=3600"})
