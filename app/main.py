from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from pathlib import Path

from app.routes import pages, blog, admin, auth, seo, telemetry, officials
from app.routes.auth import limiter  # Import rate limiter
from app.db.database import init_db, SessionLocal
from app.services import posts as posts_service
from app.security.headers import SecurityHeadersMiddleware
from app.security.logging import SecurityLogMiddleware
from app.security.rate_limit import RateLimitMiddleware
from app.cache_assets import build_asset_map, make_asset_url


class HeadRequestMiddleware(BaseHTTPMiddleware):
    """Handle HEAD requests by converting them to GET and stripping the body.

    FastAPI doesn't automatically support HEAD method for all routes.
    This middleware ensures HEAD requests work for SEO tools like Googlebot.
    """

    async def dispatch(self, request: Request, call_next):
        if request.method == "HEAD":
            request.scope["method"] = "GET"
            response = await call_next(request)
            response.body = b""
            return response
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and sync blog posts on startup."""
    # Initialize database tables
    init_db()

    # Sync markdown files to database
    db = SessionLocal()
    try:
        synced = posts_service.sync_all_files(db)
        print(f"Synced {len(synced)} blog posts from markdown files")
    finally:
        db.close()

    yield


app = FastAPI(
    title="Ace Citizenship",
    description="Prepare for your U.S. citizenship test",
    lifespan=lifespan,
)

# Rate limiter setup
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware
app.add_middleware(HeadRequestMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityLogMiddleware, site_name="acecitizenship.app")

# Static files
app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent / "static"),
    name="static",
)

# Templates
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

# Content-hash asset versioning
_static_dir = Path(__file__).parent / "static"
_asset_map = build_asset_map(_static_dir)
templates.env.globals["asset"] = lambda path: make_asset_url(_asset_map, path)

# Early Hints: preload Link header for critical CSS
app.state.preload_links = [
    f'<{make_asset_url(_asset_map, "css/custom.css")}>; rel=preload; as=style',
]

# IndexNow verification key file (instant URL submission to Bing + IndexNow network)
INDEXNOW_KEY = "8d2dd7f66c0ef04557322e0f3d0d443b"


@app.get(f"/{INDEXNOW_KEY}.txt", response_class=PlainTextResponse)
async def indexnow_key_file() -> str:
    """IndexNow ownership-verification key file (https://www.indexnow.org)."""
    return INDEXNOW_KEY


# Include routes
app.include_router(seo.router)  # SEO routes first (sitemap, robots.txt)
app.include_router(pages.router)
app.include_router(blog.router)
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(telemetry.router)  # iOS product telemetry ingest
app.include_router(officials.router)  # current officials for the iOS app
