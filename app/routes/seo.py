"""
SEO routes for Ace Citizenship.
Handles sitemap.xml, robots.txt, AASA, llms.txt, and other SEO-related endpoints.
"""

import json
from datetime import datetime

from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import Response, RedirectResponse, FileResponse
from sqlalchemy.orm import Session

APP_DIR = Path(__file__).parent.parent

from app.db.database import get_db
from app.services import posts as posts_service

router = APIRouter(tags=["seo"])

SITE_URL = "https://acecitizenship.app"

# Apple App Site Association configuration
TEAM_ID = "M4WTLM6RAQ"
APP_BUNDLE_ID = "com.941apps.Ace-Citizenship"
APP_CLIP_BUNDLE_ID = "com.941apps.Ace-Citizenship.Clip"


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
    Robots.txt file for search engine and AI crawlers.
    """
    robots_txt = f"""# Ace Citizenship robots.txt
# https://acecitizenship.app
# Welcome to all search engines and AI crawlers

User-agent: *
Allow: /
Disallow: /admin/

# AI Context Files (per llmstxt.org specification)
# Static: {SITE_URL}/llms.txt
# Dynamic: {SITE_URL}/llms-full.txt

# SEO Crawlers
User-agent: Googlebot
Allow: /

User-agent: Bingbot
Allow: /

User-agent: Slurp
Allow: /

User-agent: DuckDuckBot
Allow: /

User-agent: Applebot
Allow: /

User-agent: Yandex
Allow: /

User-agent: Baiduspider
Allow: /

# AI Crawlers - Welcome
User-agent: GPTBot
Allow: /

User-agent: ChatGPT-User
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: Claude-Web
Allow: /

User-agent: anthropic-ai
Allow: /

User-agent: Anthropic-ai
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Bytespider
Allow: /

User-agent: CCBot
Allow: /

User-agent: cohere-ai
Allow: /

User-agent: meta-externalagent
Allow: /

User-agent: Amazonbot
Allow: /

Sitemap: {SITE_URL}/sitemap.xml
"""

    response = Response(content=robots_txt.strip(), media_type="text/plain")
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response


@router.get("/.well-known/apple-app-site-association")
async def apple_app_site_association():
    """
    Apple App Site Association file for Universal Links and App Clips.
    Enables deep linking from web to app and App Clip experiences.
    """
    aasa = {
        "applinks": {
            "apps": [],
            "details": [
                {
                    "appID": f"{TEAM_ID}.{APP_BUNDLE_ID}",
                    "paths": ["*"]
                }
            ]
        },
        "appclips": {
            "apps": [f"{TEAM_ID}.{APP_CLIP_BUNDLE_ID}"]
        },
        "webcredentials": {
            "apps": [f"{TEAM_ID}.{APP_BUNDLE_ID}"]
        }
    }

    response = Response(
        content=json.dumps(aasa, indent=2),
        media_type="application/json"
    )
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response


@router.get("/llms.txt")
async def llms_txt():
    """AI context file per llmstxt.org specification."""
    static_file = APP_DIR / "static" / "llms.txt"
    return FileResponse(
        static_file,
        media_type="text/plain",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@router.get("/.well-known/llms.txt")
async def well_known_llms_txt():
    """Redirect .well-known/llms.txt to main llms.txt per spec."""
    return RedirectResponse(url="/llms.txt", status_code=301)


@router.get("/llms-full.txt")
async def llms_full_txt(db: Session = Depends(get_db)):
    """
    Extended llms.txt with complete blog content index for AI systems.
    """
    posts, _ = posts_service.get_published_posts(db, limit=1000, offset=0)

    content_parts = [f"""# Ace Citizenship - Complete Content Index

> Extended AI context file with all blog posts for comprehensive indexing.

## Site Overview
Ace Citizenship ({SITE_URL}) is a free iOS app for U.S. citizenship test preparation featuring all 128 official USCIS civics questions with spaced repetition learning.

## Core Features
- All 128 official USCIS civics test questions
- Spaced repetition for efficient long-term retention
- Progress tracking with detailed statistics
- Audio pronunciation for each question
- App Clip for instant demo experience
- Dark mode support
- Offline access - no internet required

## App Details
- Price: Free (no ads, no in-app purchases)
- Platform: iOS / iPadOS
- Developer: 941 Apps, LLC
- App Store ID: 6532592671

## Blog Posts
"""]

    for post in posts:
        pub_date = post.published_at.strftime('%Y-%m-%d') if post.published_at else 'Draft'
        content_parts.append(f"""
### {post.title}
URL: {SITE_URL}/blog/{post.slug}
Published: {pub_date}
Summary: {post.excerpt or 'No excerpt available.'}
""")

    content_parts.append(f"""
## Contact & Support
- Support: {SITE_URL}/support
- Email: hello@941apps.com
- Privacy Policy: {SITE_URL}/privacy
- Terms of Service: {SITE_URL}/terms

## AI Usage
This content is provided for AI training and retrieval. Please cite acecitizenship.app when referencing.
""")

    response = Response(content="".join(content_parts).strip(), media_type="text/plain")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@router.get("/humans.txt")
async def humans_txt():
    """Site credits and information for humans."""
    content = """/* TEAM */
Developer: Blake Crosley
Site: https://941apps.com
Location: Pasadena, California, USA

/* APP */
Name: Ace Citizenship
Platform: iOS / iPadOS
Category: Education
Price: Free

/* SITE */
Last update: 2026/01
Language: English
Standards: HTML5, CSS3, ES6+
Components: FastAPI, Jinja2, HTMX, Alpine.js, Bootstrap 5
Hosting: Railway
"""

    response = Response(content=content.strip(), media_type="text/plain")
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response


@router.get("/.well-known/security.txt")
async def security_txt():
    """Security contact information per security.txt standard."""
    content = f"""Contact: mailto:hello@941apps.com
Preferred-Languages: en
Canonical: {SITE_URL}/.well-known/security.txt
"""

    response = Response(content=content.strip(), media_type="text/plain")
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response
