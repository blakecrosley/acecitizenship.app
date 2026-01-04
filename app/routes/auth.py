"""
Admin authentication routes for Ace Citizenship.
Simple password-based auth with secure session cookies.
"""

import os
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.routes.pages import templates

router = APIRouter(prefix="/admin", tags=["auth"])

# Session configuration
SESSION_COOKIE_NAME = "ace_admin_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days in seconds

# Get secret key from env or generate one (will invalidate sessions on restart if not set)
SECRET_KEY = os.getenv("ACE_SECRET_KEY", secrets.token_hex(32))
serializer = URLSafeTimedSerializer(SECRET_KEY)


def get_admin_password() -> str:
    """Get admin password from environment."""
    password = os.getenv("ACE_ADMIN_PASSWORD", "")
    if not password:
        raise ValueError("ACE_ADMIN_PASSWORD environment variable not set")
    return password


def create_session_token() -> str:
    """Create a signed session token."""
    data = {
        "authenticated": True,
        "created_at": datetime.utcnow().isoformat()
    }
    return serializer.dumps(data)


def verify_session_token(token: str) -> bool:
    """Verify a session token is valid and not expired."""
    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
        return data.get("authenticated", False)
    except (BadSignature, SignatureExpired):
        return False


def get_current_admin(request: Request) -> bool:
    """Check if request has valid admin session."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return False
    return verify_session_token(token)


@router.get("/login")
async def login_page(request: Request, error: str = None, next: str = "/admin/posts"):
    """Render login page."""
    # If already logged in, redirect to admin
    if get_current_admin(request):
        return RedirectResponse(url=next, status_code=302)

    return templates.TemplateResponse(
        "admin/login.html",
        {"request": request, "error": error, "next": next}
    )


@router.post("/login")
async def login(
    request: Request,
    password: str = Form(...),
    next: str = Form("/admin/posts")
):
    """Process login form."""
    try:
        admin_password = get_admin_password()
    except ValueError:
        # No password configured - admin not available
        raise HTTPException(status_code=503, detail="Admin not configured")

    # Check password (constant-time comparison)
    if not secrets.compare_digest(password, admin_password):
        return templates.TemplateResponse(
            "admin/login.html",
            {"request": request, "error": "Invalid password", "next": next},
            status_code=401
        )

    # Create session and redirect
    token = create_session_token()
    response = RedirectResponse(url=next, status_code=302)

    # Set secure cookie
    is_production = os.getenv("RAILWAY_ENVIRONMENT") == "production"
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=is_production,
        samesite="lax",
        max_age=SESSION_MAX_AGE
    )

    return response


@router.get("/logout")
async def logout():
    """Log out and clear session."""
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response
