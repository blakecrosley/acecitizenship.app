from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.cache_assets import build_asset_map, make_asset_url

router = APIRouter()
_app_dir = Path(__file__).parent.parent
templates = Jinja2Templates(directory=_app_dir / "templates")

# Content-hash asset versioning
_asset_map = build_asset_map(_app_dir / "static")
templates.env.globals["asset"] = lambda path: make_asset_url(_asset_map, path)


@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/privacy")
async def privacy(request: Request):
    return templates.TemplateResponse("privacy.html", {"request": request})


@router.get("/terms")
async def terms(request: Request):
    return templates.TemplateResponse("terms.html", {"request": request})


@router.get("/support")
async def support(request: Request):
    return templates.TemplateResponse("support.html", {"request": request})
