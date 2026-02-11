"""
Content-hash asset versioning for static files.

Computes MD5 hashes of static assets at startup and provides
an asset() Jinja2 global that appends ?v=<hash> for cache busting.
"""

import hashlib
from pathlib import Path


def build_asset_map(static_dir: Path) -> dict[str, str]:
    """Compute content hashes for all static files at startup."""
    asset_map = {}
    if not static_dir.exists():
        return asset_map
    for filepath in static_dir.rglob("*"):
        if filepath.is_file():
            rel_path = str(filepath.relative_to(static_dir))
            content_hash = hashlib.md5(filepath.read_bytes()).hexdigest()[:10]
            asset_map[rel_path] = content_hash
    return asset_map


def make_asset_url(asset_map: dict[str, str], path: str) -> str:
    """Generate versioned URL for a static asset."""
    clean_path = path.lstrip("/")
    version = asset_map.get(clean_path, "0")
    return f"/static/{clean_path}?v={version}"
