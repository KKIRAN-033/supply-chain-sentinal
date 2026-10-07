"""Supply-Chain Sentinel — Production-Grade FastAPI Application Entry Point."""
import logging
import sys
import uuid
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.core.config import settings
from app.core.rate_limiter import limiter
from app.db.base import init_db, SessionLocal
from app.api.v1.router import api_router

# Configure structured logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("sentinel")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: initialize database, verify environment on startup."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [Env: {settings.ENVIRONMENT}]")
    init_db()
    logger.info("Database initialized with WAL mode and schema constraints")
    yield
    logger.info("Graceful shutdown completed")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Software Supply-Chain Security Platform — Production Grade",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
)

# 1. CORS Middleware (Supports local dev, explicit origins, and Vercel deployments)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# 2. Rate Limiting Middleware
@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    """Enforce request and scan creation rate limits per client IP."""
    denied = limiter.check(request)
    if denied:
        return denied
    return await call_next(request)


# 3. Security Headers Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Enforce production defense-in-depth HTTP security headers."""
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self' https:; "
        "frame-ancestors 'self'"
    )
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

    if settings.STRICT_TRANSPORT_SECURITY and settings.ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = f"max-age={settings.HSTS_MAX_AGE}; includeSubDomains"

    return response


# 4. Correlation ID & Observability Middleware
@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """Attach correlation ID to request and response for end-to-end traceability."""
    corr_id = request.headers.get("X-Correlation-ID") or uuid.uuid4().hex[:12]
    request.state.correlation_id = corr_id
    start_time = time.time()
    
    response = await call_next(request)
    
    duration = time.time() - start_time
    response.headers["X-Correlation-ID"] = corr_id
    response.headers["X-Response-Time"] = f"{duration:.3f}s"
    return response


# 5. Global Production Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch unhandled exceptions and format a safe error envelope without leaking tracebacks."""
    from starlette.exceptions import HTTPException as StarletteHTTPException
    if isinstance(exc, (StarletteHTTPException,)):
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail if isinstance(exc.detail, dict) else {"code": "HTTP_ERROR", "message": str(exc.detail)},
            headers=getattr(exc, "headers", None) or {},
        )

    corr_id = getattr(request.state, "correlation_id", "unknown")
    logger.error(f"[ERR-{corr_id}] Unhandled server exception on {request.method} {request.url.path}: {exc}", exc_info=True)

    # In production, mask internal details
    message = "An unexpected server error occurred."
    if settings.DEBUG or settings.ENVIRONMENT != "production":
        message = str(exc)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "code": "INTERNAL_SERVER_ERROR",
            "message": message,
            "correlation_id": corr_id,
        },
    )


# Mount API routes
app.include_router(api_router)


# ==================== Health & Readiness Probes ====================

@app.get("/")
def root():
    """Root welcome endpoint providing system metadata and docs links."""
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "online",
        "docs_url": "/docs",
        "health_url": "/health",
    }


@app.get("/health")
def health():
    """General system health and version metadata."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.get("/health/live")
def liveness():
    """Fast liveness probe for Render / cloud health monitoring."""
    return {"status": "alive", "timestamp": time.time()}


@app.get("/health/ready")
def readiness():
    """Deep readiness probe verifying database connectivity and runtime storage."""
    checks = {
        "database": False,
        "storage": False,
    }

    # Verify Database connectivity
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        checks["database"] = True
    except Exception as e:
        logger.error(f"Readiness DB probe failed: {e}")

    # Verify Data Directory writable
    try:
        data_dir = settings.DATA_DIR
        data_dir.mkdir(parents=True, exist_ok=True)
        test_file = data_dir / ".ready_probe"
        test_file.write_text("ok")
        test_file.unlink()
        checks["storage"] = True
    except Exception as e:
        logger.error(f"Readiness storage probe failed: {e}")

    all_ready = all(checks.values())
    status_code = status.HTTP_200_OK if all_ready else status.HTTP_503_SERVICE_UNAVAILABLE

    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ready" if all_ready else "not_ready",
            "checks": checks,
            "environment": settings.ENVIRONMENT,
            "version": settings.APP_VERSION,
        },
    )


if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=settings.DEBUG)
