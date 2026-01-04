"""
SEO routes for Ace Citizenship.
Handles sitemap.xml, robots.txt, and other SEO-related endpoints.
"""

from datetime import datetime

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.services import posts as posts_service

router = APIRouter(tags=["seo"])

SITE_URL = "https://acecitizenship.app"


@router.get("/sitemap.xml")
async def sitemap(db: Session = Depends(get_db)):
    """
    Dynamic XML sitemap including all pages and blog posts.
    Updates automatically when new posts are published.
    """
    # Static pages with their priorities and change frequencies
    static_pages = [
        {"loc": "/", "priority": "1.0", "changefreq": "weekly"},
        {"loc": "/blog", "priority": "0.9", "changefreq": "daily"},
        {"loc": "/support", "priority": "0.5", "changefreq": "monthly"},
        {"loc": "/privacy", "priority": "0.3", "changefreq": "yearly"},
        {"loc": "/terms", "priority": "0.3", "changefreq": "yearly"},
    ]

    # Get all published blog posts
    posts, _ = posts_service.get_published_posts(db, limit=1000, offset=0)

    # Build URL entries
    urls = []

    # Static pages
    for page in static_pages:
        lastmod = datetime.now().strftime("%Y-%m-%d")
        urls.append(f"""
    <url>
        <loc>{SITE_URL}{page['loc']}</loc>
        <lastmod>{lastmod}</lastmod>
        <changefreq>{page['changefreq']}</changefreq>
        <priority>{page['priority']}</priority>
    </url>""")

    # Blog posts
    for post in posts:
        lastmod = post.updated_at.strftime("%Y-%m-%d") if post.updated_at else post.published_at.strftime("%Y-%m-%d")
        urls.append(f"""
    <url>
        <loc>{SITE_URL}/blog/{post.slug}</loc>
        <lastmod>{lastmod}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.7</priority>
    </url>""")

    sitemap_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9
        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">{"".join(urls)}
</urlset>"""

    response = Response(content=sitemap_xml.strip(), media_type="application/xml")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@router.get("/robots.txt")
async def robots():
    """
    Robots.txt file for search engine crawlers.
    """
    robots_txt = f"""# Ace Citizenship robots.txt
# https://acecitizenship.app

User-agent: *
Allow: /

# Sitemap location
Sitemap: {SITE_URL}/sitemap.xml

# Disallow admin areas
Disallow: /admin/

# Crawl-delay for politeness
Crawl-delay: 1
"""

    response = Response(content=robots_txt.strip(), media_type="text/plain")
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response
