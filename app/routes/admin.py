"""
Admin routes for Ace Citizenship blog management.
Protected by session-based authentication.
"""

import os
from datetime import datetime

from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.services import posts as posts_service
from app.routes.pages import templates
from app.routes.auth import get_current_admin

router = APIRouter(prefix="/admin", tags=["admin"])


def require_admin(request: Request):
    """Check if user is authenticated as admin."""
    if not get_current_admin(request):
        # Redirect to login with next URL
        raise HTTPException(
            status_code=302,
            headers={"Location": f"/admin/login?next={request.url.path}"}
        )


@router.get("/posts")
async def admin_posts(
    request: Request,
    db: Session = Depends(get_db)
):
    """List all posts for admin."""
    require_admin(request)
    posts = posts_service.list_posts(db)
    return templates.TemplateResponse(
        "admin/posts.html",
        {"request": request, "posts": posts}
    )


@router.get("/posts/new")
async def admin_new_post(request: Request):
    """New post form."""
    require_admin(request)
    return templates.TemplateResponse(
        "admin/edit.html",
        {"request": request, "post": None}
    )


@router.post("/posts/new")
async def admin_create_post(
    request: Request,
    title: str = Form(...),
    slug: str = Form(...),
    excerpt: str = Form(""),
    content_md: str = Form(...),
    featured_image: str = Form(""),
    seo_title: str = Form(""),
    seo_description: str = Form(""),
    db: Session = Depends(get_db)
):
    """Create a new post."""
    require_admin(request)
    existing = posts_service.get_post_by_slug(db, slug)
    if existing:
        return templates.TemplateResponse(
            "admin/edit.html",
            {
                "request": request,
                "post": None,
                "error": f"Slug '{slug}' already exists"
            }
        )

    post = posts_service.create_post(
        db,
        title=title,
        slug=slug,
        content_md=content_md,
        excerpt=excerpt or None,
        featured_image=featured_image or None,
        seo_title=seo_title or None,
        seo_description=seo_description or None
    )

    return RedirectResponse(url=f"/admin/posts/{post.id}/edit", status_code=303)


@router.get("/posts/{post_id}/edit")
async def admin_edit_post(
    request: Request,
    post_id: int,
    db: Session = Depends(get_db)
):
    """Edit post form."""
    require_admin(request)
    post = posts_service.get_post(db, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    return templates.TemplateResponse(
        "admin/edit.html",
        {"request": request, "post": post}
    )


@router.post("/posts/{post_id}/edit")
async def admin_update_post(
    request: Request,
    post_id: int,
    title: str = Form(...),
    slug: str = Form(...),
    excerpt: str = Form(""),
    content_md: str = Form(...),
    featured_image: str = Form(""),
    seo_title: str = Form(""),
    seo_description: str = Form(""),
    db: Session = Depends(get_db)
):
    """Update a post."""
    require_admin(request)
    post = posts_service.get_post(db, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Check slug uniqueness if changed
    if slug != post.slug:
        existing = posts_service.get_post_by_slug(db, slug)
        if existing:
            return templates.TemplateResponse(
                "admin/edit.html",
                {
                    "request": request,
                    "post": post,
                    "error": f"Slug '{slug}' already exists"
                }
            )

    posts_service.update_post(
        db,
        post,
        title=title,
        slug=slug,
        content_md=content_md,
        excerpt=excerpt or None,
        featured_image=featured_image or None,
        seo_title=seo_title or None,
        seo_description=seo_description or None
    )

    return templates.TemplateResponse(
        "admin/edit.html",
        {"request": request, "post": post, "success": "Post updated successfully"}
    )


@router.post("/posts/{post_id}/publish")
async def admin_publish_post(
    request: Request,
    post_id: int,
    db: Session = Depends(get_db)
):
    """Publish a post."""
    require_admin(request)
    post = posts_service.get_post(db, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    posts_service.publish_post(db, post)
    return RedirectResponse(url=f"/admin/posts/{post_id}/edit", status_code=303)


@router.post("/posts/{post_id}/unpublish")
async def admin_unpublish_post(
    request: Request,
    post_id: int,
    db: Session = Depends(get_db)
):
    """Unpublish a post."""
    require_admin(request)
    post = posts_service.get_post(db, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    posts_service.unpublish_post(db, post)
    return RedirectResponse(url=f"/admin/posts/{post_id}/edit", status_code=303)


@router.post("/posts/{post_id}/schedule")
async def admin_schedule_post(
    request: Request,
    post_id: int,
    scheduled_at: str = Form(...),
    db: Session = Depends(get_db)
):
    """Schedule a post for future publication."""
    require_admin(request)
    post = posts_service.get_post(db, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    try:
        schedule_time = datetime.fromisoformat(scheduled_at)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format")

    posts_service.schedule_post(db, post, schedule_time)
    return RedirectResponse(url=f"/admin/posts/{post_id}/edit", status_code=303)


@router.post("/posts/{post_id}/delete")
async def admin_delete_post(
    request: Request,
    post_id: int,
    db: Session = Depends(get_db)
):
    """Delete a post."""
    require_admin(request)
    post = posts_service.get_post(db, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    posts_service.delete_post(db, post)
    return RedirectResponse(url="/admin/posts", status_code=303)
