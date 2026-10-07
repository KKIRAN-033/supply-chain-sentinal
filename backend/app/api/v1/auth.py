"""Authentication & User Session API for Supply-Chain Sentinel.

Provides secure token-based authentication, brute-force defense,
timing-safe password verification, and session state inspection.
"""
import os
import time
import secrets
import hashlib
import threading
from typing import Optional, Dict
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Request, status, Header
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.db import repositories as repo
from app.core.config import settings
from app.core.security import utc_now

router = APIRouter(prefix="/auth", tags=["auth"])

# Thread-safe in-memory session store & brute-force rate limiter
_sessions_lock = threading.Lock()
_active_sessions: Dict[str, dict] = {}
_login_failures: Dict[str, list] = {}  # ip -> list of timestamps

# Default Users
DEFAULT_USERS = {
    "admin@sentinel.sec": {
        "id": "usr_sec_lead",
        "username": "admin@sentinel.sec",
        "name": "Security Lead Admin",
        "role": "admin",
        "organization": "Sentinel Cyber Defense",
        "password_hash": hashlib.sha256(
            os.environ.get("SCS_ADMIN_PASSWORD", "Sentinel@2026!").encode("utf-8")
        ).hexdigest(),
    },
    "analyst@sentinel.sec": {
        "id": "usr_analyst",
        "username": "analyst@sentinel.sec",
        "name": "Security Analyst",
        "role": "analyst",
        "organization": "Sentinel Cyber Defense",
        "password_hash": hashlib.sha256(
            os.environ.get("SCS_ANALYST_PASSWORD", "Sentinel@2026!").encode("utf-8")
        ).hexdigest(),
    },
}
# Alias 'admin' to 'admin@sentinel.sec'
DEFAULT_USERS["admin"] = DEFAULT_USERS["admin@sentinel.sec"]


class LoginRequest(BaseModel):
    username: str = Field(..., description="Email or username")
    password: str = Field(..., description="Account password")


class UserProfile(BaseModel):
    id: str
    username: str
    name: str
    role: str
    organization: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserProfile


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def _check_brute_force(ip: str):
    """Enforce brute force protection: max 10 failed logins per minute per IP."""
    now = time.time()
    with _sessions_lock:
        failures = _login_failures.get(ip, [])
        # Keep only failures in the last 60 seconds
        recent = [t for t in failures if now - t < 60.0]
        _login_failures[ip] = recent
        if len(recent) >= 10:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "code": "BRUTE_FORCE_LOCKOUT",
                    "message": "Too many failed login attempts. Please wait 60 seconds before retrying.",
                },
                headers={"Retry-After": "60"},
            )


def _record_login_failure(ip: str):
    with _sessions_lock:
        if ip not in _login_failures:
            _login_failures[ip] = []
        _login_failures[ip].append(time.time())


def get_current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
) -> dict:
    """Dependency to retrieve the currently authenticated user from Bearer token or API key."""
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    elif x_api_key:
        token = x_api_key.strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "Missing authentication credentials"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # API key bypass for CI/CD integrations
    if settings.API_KEY and token == settings.API_KEY:
        return {
            "id": "usr_system_api",
            "username": "api_client@sentinel.sec",
            "name": "System API Key Client",
            "role": "admin",
            "organization": "Sentinel Automation",
        }

    with _sessions_lock:
        session_data = _active_sessions.get(token)
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "INVALID_TOKEN", "message": "Session expired or invalid token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Check expiry
        if time.time() > session_data.get("expires_at", 0):
            _active_sessions.pop(token, None)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "TOKEN_EXPIRED", "message": "Session token has expired"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return session_data["user"]


@router.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate user with username and password and issue a bearer token."""
    ip = _get_client_ip(request)
    _check_brute_force(ip)

    username_clean = req.username.strip().lower()
    user_record = DEFAULT_USERS.get(username_clean)

    if not user_record:
        _record_login_failure(ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_CREDENTIALS", "message": "Invalid username or password"},
        )

    # Constant-time password verification against SHA-256 hash
    input_hash = hashlib.sha256(req.password.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(input_hash, user_record["password_hash"]):
        _record_login_failure(ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_CREDENTIALS", "message": "Invalid username or password"},
        )

    # Issue secure random token
    token = f"sct_{secrets.token_urlsafe(32)}"
    expires_in = 86400  # 24 hours
    user_profile = {
        "id": user_record["id"],
        "username": user_record["username"],
        "name": user_record["name"],
        "role": user_record["role"],
        "organization": user_record["organization"],
    }

    with _sessions_lock:
        _active_sessions[token] = {
            "user": user_profile,
            "created_at": time.time(),
            "expires_at": time.time() + expires_in,
            "ip": ip,
        }
        # Clear failure count on success
        _login_failures.pop(ip, None)

    repo.save_audit_event(db, "user_login", "auth", user_record["id"], {
        "username": user_record["username"],
        "ip": ip,
        "role": user_record["role"],
    })

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        user=UserProfile(**user_profile),
    )


@router.get("/me", response_model=UserProfile)
def get_current_user_profile(user: dict = Depends(get_current_user)):
    """Return currently authenticated user profile."""
    return UserProfile(**user)


@router.post("/logout")
def logout(authorization: Optional[str] = Header(None)):
    """Invalidate current session token."""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        with _sessions_lock:
            _active_sessions.pop(token, None)
    return {"status": "logged_out", "message": "Session terminated successfully"}
