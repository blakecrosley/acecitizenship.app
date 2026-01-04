from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.routes import pages, blog, admin, auth, seo
from app.db.database import init_db, SessionLocal
from app.services import posts as posts_service


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
