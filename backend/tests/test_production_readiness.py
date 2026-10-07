"""Production readiness and hardening automated test suite."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from main import app
from app.core.config import settings
from app.core.rate_limiter import limiter
from app.db.base import engine, SessionLocal


@pytest.fixture(autouse=True)
def reset_limiter_state():
    """Ensure rate limiter is fresh for every test run."""
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def client():
    return TestClient(app)


def test_health_overview(client):
    """Test general health endpoint."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["app"] == settings.APP_NAME
    assert data["version"] == settings.APP_VERSION


def test_liveness_probe(client):
    """Test fast container liveness probe."""
    res = client.get("/health/live")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "alive"
    assert "timestamp" in data


def test_readiness_probe(client):
    """Test deep readiness probe verifying DB connectivity and disk storage."""
    res = client.get("/health/ready")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert data["checks"]["database"] is True
    assert data["checks"]["storage"] is True


def test_production_security_headers(client):
    """Verify all defense-in-depth security headers are present on responses."""
    res = client.get("/health")
    headers = res.headers

    assert headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "frame-ancestors 'self'" in headers.get("Content-Security-Policy", "")
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert "geolocation=()" in headers.get("Permissions-Policy", "")


def test_correlation_id_and_response_time_headers(client):
    """Verify observability headers are attached to every response."""
    # Without incoming header
    res1 = client.get("/health")
    assert "X-Correlation-ID" in res1.headers
    assert "X-Response-Time" in res1.headers

    # With incoming custom correlation ID
    custom_id = "test-corr-abc-123"
    res2 = client.get("/health", headers={"X-Correlation-ID": custom_id})
    assert res2.headers.get("X-Correlation-ID") == custom_id


def test_rate_limiting_enforcement(client):
    """Verify client is throttled with 429 when burst limit is exceeded."""
    original_limit = settings.RATE_LIMIT_PER_MINUTE
    settings.RATE_LIMIT_PER_MINUTE = 5
    try:
        # Rapidly send 5 requests (allowed)
        for _ in range(5):
            res = client.get("/api/v1/projects")
            assert res.status_code == 200

        # 6th request should be blocked
        res_blocked = client.get("/api/v1/projects")
        assert res_blocked.status_code == 429
        data = res_blocked.json()
        assert data.get("code") == "RATE_LIMIT_EXCEEDED" or data.get("detail", {}).get("code") == "RATE_LIMIT_EXCEEDED"
        assert "Retry-After" in res_blocked.headers
    finally:
        settings.RATE_LIMIT_PER_MINUTE = original_limit


def test_sqlite_wal_pragmas():
    """Verify SQLite connection is configured with WAL journal mode and busy timeout."""
    if "sqlite" in settings.DATABASE_URL:
        db = SessionLocal()
        try:
            journal_mode = db.execute(text("PRAGMA journal_mode")).scalar()
            # In SQLite, journal mode should be wal (or memory in ephemeral memory DBs)
            assert journal_mode.lower() in ("wal", "memory")

            busy_timeout = db.execute(text("PRAGMA busy_timeout")).scalar()
            assert busy_timeout >= 5000
        finally:
            db.close()
