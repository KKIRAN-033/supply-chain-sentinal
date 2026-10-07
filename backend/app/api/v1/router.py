"""API v1 router — aggregates all endpoint routers."""
from fastapi import APIRouter
from app.api.v1.projects import router as projects_router
from app.api.v1.scans import router as scans_router
from app.api.v1.policies import router as policies_router
from app.api.v1.webhooks import router as webhooks_router
from app.api.v1.ai import router as ai_router
from app.api.v1.auth import router as auth_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth_router)
api_router.include_router(projects_router)
api_router.include_router(scans_router)
api_router.include_router(policies_router)
api_router.include_router(webhooks_router)
api_router.include_router(ai_router)

