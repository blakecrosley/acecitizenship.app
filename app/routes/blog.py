"""
Public blog routes for Ace Citizenship.
"""

from typing import Optional

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.services import posts as posts_service
from app.routes.pages import templates

router = APIRouter(prefix="/blog", tags=["blog"])

POSTS_PER_PAGE = 12


@router.get("")
async def blog_index(
    request: Request,
    page: int = 1,
    q: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Blog index - list published posts with pagination and search."""
    if page < 1:
        page = 1

    offset = (page - 1) * POSTS_PER_PAGE

    if q and q.strip():
        posts, total = posts_service.search_published_posts(
            db, q.strip(), limit=POSTS_PER_PAGE, offset=offset
        )
    else:
        posts, total = posts_service.get_published_posts(
            db, limit=POSTS_PER_PAGE, offset=offset
        )

    total_pages = (total + POSTS_PER_PAGE - 1) // POSTS_PER_PAGE

    response = templates.TemplateResponse(
        "blog/list.html",
        {
            "request": request,
            "posts": posts,
            "page": page,
            "per_page": POSTS_PER_PAGE,
            "total_pages": total_pages,
            "total": total,
            "search_query": q or ""
        }
    )
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@router.get("/feed.xml")
async def blog_rss_feed(db: Session = Depends(get_db)):
    """RSS 2.0 feed of published blog posts."""
    posts, _ = posts_service.get_published_posts(db, limit=20, offset=0)

    items = []
    for post in posts:
        pub_date = post.published_at.strftime("%a, %d %b %Y %H:%M:%S +0000") if post.published_at else ""
        items.append(f"""
        <item>
            <title><![CDATA[{post.title}]]></title>
            <link>https://acecitizenship.app/blog/{post.slug}</link>
            <guid isPermaLink="true">https://acecitizenship.app/blog/{post.slug}</guid>
            <description><![CDATA[{post.excerpt or ''}]]></description>
            <pubDate>{pub_date}</pubDate>
        </item>""")

    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
    <channel>
        <title>Ace Citizenship Blog</title>
        <link>https://acecitizenship.app/blog</link>
        <description>Tips and guides for passing the U.S. citizenship test.</description>
        <language>en-us</language>
        <atom:link href="https://acecitizenship.app/blog/feed.xml" rel="self" type="application/rss+xml"/>
        {"".join(items)}
    </channel>
</rss>"""

    response = Response(content=rss.strip(), media_type="application/rss+xml")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@router.get("/{slug}")
async def blog_post(request: Request, slug: str, db: Session = Depends(get_db)):
    """Single blog post view."""
    post = posts_service.get_post_by_slug(db, slug)

    if not post or post.status not in ('published', 'scheduled'):
        raise HTTPException(status_code=404, detail="Post not found")

    related_posts = posts_service.get_related_posts(db, post.id, limit=3)

    # Extract FAQ items from post content for Schema.org FAQPage markup
    faq_items = []
    if post.content_html:
        faq_items = posts_service.extract_faq_items(post.content_html)

    response = templates.TemplateResponse(
        "blog/post.html",
        {
            "request": request,
            "post": post,
            "related_posts": related_posts,
            "faq_items": faq_items
        }
    )
    response.headers["Cache-Control"] = "public, max-age=300"
    return response
