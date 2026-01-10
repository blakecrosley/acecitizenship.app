"""
Admin authentication routes for Ace Citizenship.
Simple password-based auth with secure session cookies.
"""

import os
import secrets
import warnings
from datetime import datetime, timedelta
from urllib.parse import urlparse

from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.routes.pages import templates

router = APIRouter(prefix="/admin", tags=["auth"])

# Session configuration
SESSION_COOKIE_NAME = "ace_admin_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days in seconds
CSRF_COOKIE_NAME = "ace_csrf_token"

# Rate limiter for login attempts
limiter = Limiter(key_func=get_remote_address)

# Security: Get secret key from environment
# In production, this MUST be set via environment variable
SECRET_KEY = os.getenv("ACE_SECRET_KEY")
IS_PRODUCTION = os.getenv("RAILWAY_ENVIRONMENT") == "production"

if not SECRET_KEY:
    if IS_PRODUCTION:
        raise RuntimeError("ACE_SECRET_KEY must be set in production environment")
    # Only allow fallback in development
    warnings.warn("ACE_SECRET_KEY not set - using random key (sessions won't persist across restarts)")
    SECRET_KEY = secrets.token_hex(32)

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


def is_safe_redirect_url(url: str) -> bool:
    """Validate that URL is safe for redirect (same-origin only).

    Prevents open redirect attacks by only allowing relative URLs
    that start with / and don't contain protocol or netloc.
    """
    if not url:
        return False
    parsed = urlparse(url)
    # Only allow relative URLs (no scheme or netloc)
    return not parsed.scheme and not parsed.netloc and url.startswith('/')


def generate_csrf_token() -> str:
    """Generate a CSRF token."""
    return secrets.token_urlsafe(32)


def verify_csrf_token(request: Request, submitted_token: str) -> bool:
    """Verify CSRF token from cookie matches submitted token."""
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not cookie_token or not submitted_token:
        return False
    return secrets.compare_digest(cookie_token, submitted_token)


@router.get("/login")
async def login_page(request: Request, error: str = None, next: str = "/admin/posts"):
    """Render login page."""
    # Validate redirect URL to prevent open redirect
    if not is_safe_redirect_url(next):
        next = "/admin/posts"

    # If already logged in, redirect to admin
    if get_current_admin(request):
        return RedirectResponse(url=next, status_code=302)

    # Generate CSRF token
    csrf_token = generate_csrf_token()

    response = templates.TemplateResponse(
        "admin/login.html",
        {"request": request, "error": error, "next": next, "csrf_token": csrf_token}
    )

    # Set CSRF cookie (double-submit pattern)
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="strict",
        max_age=3600  # 1 hour
    )

    return response


@router.post("/login")
@limiter.limit("5/minute")  # Rate limit: 5 attempts per minute per IP
async def login(
    request: Request,
    password: str = Form(...),
    next: str = Form("/admin/posts"),
    csrf_token: str = Form(...)
):
    """Process login form."""
    # Verify CSRF token
    if not verify_csrf_token(request, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    # Validate redirect URL to prevent open redirect
    if not is_safe_redirect_url(next):
        next = "/admin/posts"

    try:
        admin_password = get_admin_password()
    except ValueError:
        # No password configured - use generic error to avoid info disclosure
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check password (constant-time comparison)
    if not secrets.compare_digest(password, admin_password):
        # Generate new CSRF token for retry
        new_csrf_token = generate_csrf_token()
        response = templates.TemplateResponse(
            "admin/login.html",
            {"request": request, "error": "Invalid password", "next": next, "csrf_token": new_csrf_token},
            status_code=401
        )
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=new_csrf_token,
            httponly=True,
            secure=IS_PRODUCTION,
            samesite="strict",
            max_age=3600
        )
        return response

    # Create session and redirect
    token = create_session_token()
    response = RedirectResponse(url=next, status_code=302)

    # Set secure session cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="lax",
        max_age=SESSION_MAX_AGE
    )

    # Clear CSRF cookie after successful login
    response.delete_cookie(key=CSRF_COOKIE_NAME)

    return response


@router.get("/logout")
async def logout():
    """Log out and clear session."""
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="lax"
    )
    return response
