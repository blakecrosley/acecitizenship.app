"""
SQLAlchemy models for Ace Citizenship Blog.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, CheckConstraint, Index
from app.db.database import Base


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
