"""
Posts service for Ace Citizenship Blog.
CRUD operations and markdown file sync.
"""

import hashlib
from datetime import datetime, date
from pathlib import Path
from typing import Optional, Union

import frontmatter
import markdown
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.db.models import Post

# Content directory for markdown files
CONTENT_DIR = Path(__file__).parent.parent.parent / "content" / "blog"
CONTENT_DIR.mkdir(parents=True, exist_ok=True)


def parse_date(value: Union[str, date, datetime, None]) -> Optional[datetime]:
    """Parse a date value from frontmatter to datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time())
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    return None


def render_markdown(content: str) -> str:
    """Convert markdown to HTML."""
    md = markdown.Markdown(extensions=['extra', 'codehilite', 'toc'])
    return md.convert(content)


def compute_checksum(content: str) -> str:
    """Compute SHA-256 checksum for sync detection."""
    return hashlib.sha256(content.encode()).hexdigest()


def extract_faq_items(content_html: str, max_items: int = 10) -> list[dict]:
    """
    Extract FAQ items from HTML content for Schema.org FAQPage markup.

    Looks for h2/h3 headers that are questions (end with ?) and pairs them
    with the following paragraph text as answers.

    Returns list of {"question": str, "answer": str} dicts.
    """
    import re

    faq_items = []

    # Pattern: h2 or h3 ending with ? followed by content until next h2/h3
    # This regex finds question headers and captures their text
    question_pattern = re.compile(
        r'<h[23][^>]*>([^<]*\?)</h[23]>\s*<p>([^<]+(?:<[^/][^>]*>[^<]*</[^>]+>)*[^<]*)</p>',
        re.IGNORECASE | re.DOTALL
    )

    # Simpler approach: find h2/h3 questions, then get next paragraph
    header_pattern = re.compile(r'<h[23][^>]*>([^<]*\?)</h[23]>', re.IGNORECASE)
    headers = list(header_pattern.finditer(content_html))

    for match in headers[:max_items]:
        question = match.group(1).strip()
        # Find the content after this header until the next header
        start_pos = match.end()
        next_header = re.search(r'<h[1-6]', content_html[start_pos:], re.IGNORECASE)
        end_pos = start_pos + next_header.start() if next_header else len(content_html)

        answer_section = content_html[start_pos:end_pos]
        # Extract text from paragraphs
        para_pattern = re.compile(r'<p[^>]*>(.*?)</p>', re.IGNORECASE | re.DOTALL)
        paras = para_pattern.findall(answer_section)

        if paras:
            # Clean HTML tags from answer
            answer = ' '.join(paras[:2])  # Take first 2 paragraphs
            answer = re.sub(r'<[^>]+>', '', answer).strip()
            answer = ' '.join(answer.split())  # Normalize whitespace

            if answer and len(answer) > 20:  # Skip very short answers
                faq_items.append({
                    "question": question,
                    "answer": answer[:500]  # Limit answer length
                })

    return faq_items


# =============================================================================
# READ OPERATIONS
# =============================================================================

def get_post(db: Session, post_id: int) -> Optional[Post]:
    """Get a post by ID."""
    return db.query(Post).filter(Post.id == post_id).first()


def get_post_by_slug(db: Session, slug: str) -> Optional[Post]:
    """Get a post by slug."""
    return db.query(Post).filter(Post.slug == slug).first()


def list_posts(
    db: Session,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> list[Post]:
    """List posts with optional filtering."""
    query = db.query(Post)

    if status:
        query = query.filter(Post.status == status)

    return query.order_by(Post.created_at.desc()).offset(offset).limit(limit).all()


def get_published_posts(
    db: Session,
    limit: int = 12,
    offset: int = 0
) -> tuple[list[Post], int]:
    """Get published posts ordered by publish date with pagination.

    Returns posts that are either:
    - status='published' (immediately published)
    - status='scheduled' AND scheduled_at <= now (scheduled time has passed)

    Returns:
        Tuple of (posts, total_count)
    """
    now = datetime.utcnow()
    query = db.query(Post).filter(
        or_(
            Post.status == 'published',
            and_(
                Post.status == 'scheduled',
                Post.scheduled_at <= now
            )
        )
    )

    total = query.count()
    posts = query.order_by(Post.published_at.desc()).offset(offset).limit(limit).all()

    return posts, total


def get_related_posts(
    db: Session,
    current_post_id: int,
    limit: int = 3
) -> list[Post]:
    """Get related posts for display at end of article."""
    now = datetime.utcnow()
    return db.query(Post).filter(
        Post.id != current_post_id,
        or_(
            Post.status == 'published',
            and_(
                Post.status == 'scheduled',
                Post.scheduled_at <= now
            )
        )
    ).order_by(Post.published_at.desc()).limit(limit).all()


def search_published_posts(
    db: Session,
    query_text: str,
    limit: int = 12,
    offset: int = 0
) -> tuple[list[Post], int]:
    """Search published posts by title and content."""
    now = datetime.utcnow()
    search_pattern = f"%{query_text}%"

    query = db.query(Post).filter(
        or_(
            Post.status == 'published',
            and_(
                Post.status == 'scheduled',
                Post.scheduled_at <= now
            )
        ),
        or_(
            Post.title.ilike(search_pattern),
            Post.content_md.ilike(search_pattern),
            Post.excerpt.ilike(search_pattern)
        )
    )

    total = query.count()
    posts = query.order_by(Post.published_at.desc()).offset(offset).limit(limit).all()

    return posts, total


# =============================================================================
# WRITE OPERATIONS
# =============================================================================

def create_post(
    db: Session,
    title: str,
    slug: str,
    content_md: str,
    excerpt: Optional[str] = None,
    featured_image: Optional[str] = None,
    seo_title: Optional[str] = None,
    seo_description: Optional[str] = None,
    sync_to_file: bool = True
) -> Post:
    """Create a new post."""
    content_html = render_markdown(content_md)

    post = Post(
        title=title,
        slug=slug,
        excerpt=excerpt,
        content_md=content_md,
        content_html=content_html,
        featured_image=featured_image,
        seo_title=seo_title,
        seo_description=seo_description,
        status='draft',
        checksum=compute_checksum(content_md)
    )

    db.add(post)
    db.commit()
    db.refresh(post)

    if sync_to_file:
        sync_post_to_file(post)
        db.commit()

    return post


def update_post(
    db: Session,
    post: Post,
    title: Optional[str] = None,
    slug: Optional[str] = None,
    excerpt: Optional[str] = None,
    content_md: Optional[str] = None,
    featured_image: Optional[str] = None,
    seo_title: Optional[str] = None,
    seo_description: Optional[str] = None,
    status: Optional[str] = None,
    sync_to_file: bool = True
) -> Post:
    """Update an existing post."""
    if title is not None:
        post.title = title
    if slug is not None:
        post.slug = slug
    if excerpt is not None:
        post.excerpt = excerpt
    if content_md is not None:
        post.content_md = content_md
        post.content_html = render_markdown(content_md)
        post.checksum = compute_checksum(content_md)
    if featured_image is not None:
        post.featured_image = featured_image
    if seo_title is not None:
        post.seo_title = seo_title
    if seo_description is not None:
        post.seo_description = seo_description
    if status is not None:
        post.status = status

    post.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(post)

    if sync_to_file:
        sync_post_to_file(post)
        db.commit()

    return post


def delete_post(db: Session, post: Post) -> None:
    """Delete a post and its markdown file."""
    if post.file_path:
        file_path = Path(post.file_path)
        if file_path.exists():
            file_path.unlink()

    db.delete(post)
    db.commit()


def publish_post(db: Session, post: Post) -> Post:
    """Publish a post."""
    post.status = 'published'
    post.published_at = datetime.utcnow()
    post.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(post)

    sync_post_to_file(post)
    db.commit()

    return post


def unpublish_post(db: Session, post: Post) -> Post:
    """Revert post to draft status."""
    post.status = 'draft'
    post.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(post)

    sync_post_to_file(post)
    db.commit()

    return post


def schedule_post(db: Session, post: Post, scheduled_at: datetime) -> Post:
    """Schedule a post for future publication."""
    post.status = 'scheduled'
    post.scheduled_at = scheduled_at
    post.published_at = scheduled_at
    post.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(post)

    sync_post_to_file(post)
    db.commit()

    return post


# =============================================================================
# MARKDOWN FILE SYNC
# =============================================================================

def sync_post_to_file(post: Post) -> Path:
    """Sync post to markdown file with YAML frontmatter."""
    file_path = CONTENT_DIR / f"{post.slug}.md"

    metadata = {
        'title': post.title,
        'slug': post.slug,
        'status': post.status,
    }

    if post.excerpt:
        metadata['excerpt'] = post.excerpt
    if post.featured_image:
        metadata['featured_image'] = post.featured_image
    if post.seo_title:
        metadata['seo_title'] = post.seo_title
    if post.seo_description:
        metadata['seo_description'] = post.seo_description
    if post.published_at:
        metadata['published_at'] = post.published_at.isoformat()

    fm_post = frontmatter.Post(post.content_md, **metadata)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(frontmatter.dumps(fm_post))

    post.file_path = str(file_path)

    return file_path


def sync_file_to_post(db: Session, file_path: Path) -> Optional[Post]:
    """Sync markdown file to database."""
    if not file_path.exists():
        return None

    with open(file_path, 'r', encoding='utf-8') as f:
        fm_post = frontmatter.load(f)

    slug = fm_post.metadata.get('slug') or file_path.stem
    content_md = fm_post.content
    checksum = compute_checksum(content_md)

    post = get_post_by_slug(db, slug)

    if post:
        if post.checksum == checksum:
            return post

        post.title = fm_post.metadata.get('title', post.title)
        post.excerpt = fm_post.metadata.get('excerpt')
        post.content_md = content_md
        post.content_html = render_markdown(content_md)
        post.featured_image = fm_post.metadata.get('featured_image')
        post.seo_title = fm_post.metadata.get('seo_title')
        post.seo_description = fm_post.metadata.get('seo_description')
        post.status = fm_post.metadata.get('status', 'draft')
        post.file_path = str(file_path)
        post.checksum = checksum
        post.updated_at = datetime.utcnow()

        if fm_post.metadata.get('published_at'):
            post.published_at = parse_date(fm_post.metadata['published_at'])
    else:
        post = Post(
            title=fm_post.metadata.get('title', slug.replace('-', ' ').title()),
            slug=slug,
            excerpt=fm_post.metadata.get('excerpt'),
            content_md=content_md,
            content_html=render_markdown(content_md),
            featured_image=fm_post.metadata.get('featured_image'),
            seo_title=fm_post.metadata.get('seo_title'),
            seo_description=fm_post.metadata.get('seo_description'),
            status=fm_post.metadata.get('status', 'draft'),
            file_path=str(file_path),
            checksum=checksum
        )

        if fm_post.metadata.get('published_at'):
            post.published_at = parse_date(fm_post.metadata['published_at'])

        db.add(post)

    db.commit()
    db.refresh(post)

    return post


def sync_all_files(db: Session) -> list[Post]:
    """Sync all markdown files in content directory to database."""
    posts = []

    for file_path in CONTENT_DIR.glob('*.md'):
        post = sync_file_to_post(db, file_path)
        if post:
            posts.append(post)

    return posts
