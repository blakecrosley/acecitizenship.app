"""
SQLAlchemy models for Ace Citizenship Blog.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, CheckConstraint, Index
from app.db.database import Base


class TelemetryEvent(Base):
    """
    A single product-interaction event from the iOS app.

    Deliberately contains no personal data: `install_id` is a random UUID the
    app generates about itself (not the IDFV/IDFA, not derived from hardware or
    the user), and `props` is a small JSON blob of counters. This exists to
    answer one question we have never been able to answer — what free users
    actually do before they hit the paywall.
    """
    __tablename__ = "telemetry_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    install_id = Column(String(64), nullable=False, index=True)
    app_version = Column(String(32))
    name = Column(String(64), nullable=False, index=True)
    at = Column(DateTime, nullable=False)
    props = Column(Text)  # JSON object of string->string
    received_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index('idx_telemetry_name_at', 'name', 'at'),
        Index('idx_telemetry_install', 'install_id', 'at'),
    )


class Post(Base):
    """
    Blog post model.
    Author is always Blake Crosley (hardcoded in templates).
    """
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    slug = Column(String(200), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    excerpt = Column(Text)
    content_md = Column(Text, nullable=False)
    content_html = Column(Text)
    featured_image = Column(String(500))
    seo_title = Column(String(200))
    seo_description = Column(String(500))
    status = Column(String(20), default='draft', nullable=False)
    published_at = Column(DateTime)
    scheduled_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    file_path = Column(String(500))
    checksum = Column(String(64))

    __table_args__ = (
        CheckConstraint(
            "status IN ('draft', 'published', 'scheduled', 'archived')",
            name='check_post_status'
        ),
        Index('idx_posts_status', 'status'),
        Index('idx_posts_published_at', 'published_at'),
        Index('idx_posts_scheduled_at', 'scheduled_at'),
    )

    @property
    def reading_time(self) -> int:
        """Calculate reading time in minutes (~200 words/min)."""
        if not self.content_md:
            return 1
        word_count = len(self.content_md.split())
        minutes = max(1, round(word_count / 200))
        return minutes

    def __repr__(self):
        return f"<Post {self.slug}>"
