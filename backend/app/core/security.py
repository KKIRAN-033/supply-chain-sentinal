"""Security utilities: API key validation, hashing, audit helpers."""
import hashlib
import logging
import uuid
from datetime import datetime, timezone
from fastapi import Request, HTTPException, Security
from fastapi.security import APIKeyHeader

from app.core.config import settings

logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name=settings.API_KEY_HEADER, auto_error=False)


def generate_id(prefix: str = "") -> str:
    """Generate a unique ID with optional prefix."""
    uid = uuid.uuid4().hex[:12]
    return f"{prefix}_{uid}" if prefix else uid


def compute_sha256(content: bytes) -> str:
    """Compute SHA-256 hash of content."""
    return hashlib.sha256(content).hexdigest()


def utc_now() -> datetime:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc)


def get_expected_api_key() -> str | None:
    """Retrieve expected API key from environment configuration."""
    if settings.API_KEY:
        return settings.API_KEY
    if settings.SECRET_KEY:
        return settings.SECRET_KEY
    return None


async def validate_api_key(api_key: str = Security(api_key_header)) -> str:
    """Validate API key on protected mutation endpoints if configured."""
    expected = get_expected_api_key()
    if not expected:
        # Development / local mode: No authentication key required
        return ""
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail={"code": "UNAUTHORIZED", "message": "Missing required API key header (X-API-Key)"}
        )
    if api_key != expected:
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "Invalid API key"}
        )
    return api_key



def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to prevent path traversal."""
    import os
    basename = os.path.basename(filename)
    # Remove any remaining suspicious characters
    safe = "".join(c for c in basename if c.isalnum() or c in ".-_")
    return safe or "unnamed"
