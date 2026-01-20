from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from pathlib import Path

from app.routes import pages, blog, admin, auth, seo
from app.routes.auth import limiter  # Import rate limiter
from app.db.database import init_db, SessionLocal
from app.services import posts as posts_service
from app.security.headers import SecurityHeadersMiddleware
from app.security.logging import SecurityLogMiddleware
from app.security.rate_limit import RateLimitMiddleware


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

# Include routes
app.include_router(seo.router)  # SEO routes first (sitemap, robots.txt)
app.include_router(pages.router)
app.include_router(blog.router)
app.include_router(auth.router)
app.include_router(admin.router)
