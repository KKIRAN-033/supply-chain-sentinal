"""Production-grade in-memory sliding window rate limiter."""
import time
import threading
from typing import Dict, List, Optional
from collections import defaultdict
from fastapi import Request, status
from fastapi.responses import JSONResponse

from app.core.config import settings


class SlidingWindowRateLimiter:
    """Thread-safe sliding window rate limiter for FastAPI requests."""

    def __init__(self):
        self._lock = threading.Lock()
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._scan_requests: Dict[str, List[float]] = defaultdict(list)

    def _get_client_ip(self, request: Request) -> str:
        # Check standard reverse proxy headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        return request.client.host if request.client else "127.0.0.1"

    def check(self, request: Request) -> Optional[JSONResponse]:
        """Check if request is within allowed limits. Returns 429 JSONResponse if exceeded, else None."""
        if not settings.ENABLE_RATE_LIMITING:
            return None

        path = request.url.path
        # Whitelist health checks and root
        if path.startswith("/health") or path == "/":
            return None

        client_ip = self._get_client_ip(request)
        now = time.time()
        window_size = 60.0  # 60 seconds window

        with self._lock:
            # 1. Check general endpoint rate limit
            timestamps = self._requests[client_ip]
            cutoff = now - window_size
            self._requests[client_ip] = [t for t in timestamps if t > cutoff]

            if len(self._requests[client_ip]) >= settings.RATE_LIMIT_PER_MINUTE:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": f"Rate limit exceeded. Maximum {settings.RATE_LIMIT_PER_MINUTE} requests per minute.",
                    },
                    headers={"Retry-After": "60"},
                )

            self._requests[client_ip].append(now)

            # 2. Check strict scan submission rate limit
            if request.method == "POST" and "/scans" in path:
                scan_timestamps = self._scan_requests[client_ip]
                self._scan_requests[client_ip] = [t for t in scan_timestamps if t > cutoff]

                if len(self._scan_requests[client_ip]) >= settings.SCAN_RATE_LIMIT_PER_MINUTE:
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "code": "SCAN_RATE_LIMIT_EXCEEDED",
                            "message": f"Scan creation limit exceeded. Maximum {settings.SCAN_RATE_LIMIT_PER_MINUTE} scans per minute.",
                        },
                        headers={"Retry-After": "60"},
                    )

                self._scan_requests[client_ip].append(now)

        return None

    def reset(self) -> None:
        """Reset all rate limiter states (useful for testing)."""
        with self._lock:
            self._requests.clear()
            self._scan_requests.clear()


limiter = SlidingWindowRateLimiter()
