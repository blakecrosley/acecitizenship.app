from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from pathlib import Path

from app.routes import pages, blog, admin, auth, seo
from app.db.database import init_db, SessionLocal
from app.services import posts as posts_service


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Content Security Policy - allow CDN resources
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Content-Security-Policy"] = csp

        return response


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

# Security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

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
