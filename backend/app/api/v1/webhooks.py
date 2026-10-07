"""GitHub Webhook API Endpoint.

Receives GitHub push/commit events, verifies signatures, and triggers scans.
"""
import hmac
import hashlib
import json
import logging
from fastapi import APIRouter, Header, Request, HTTPException, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.base import get_db
from app.db import repositories as repo
from app.engine.monitoring.service import MonitoringService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _verify_github_signature(payload_bytes: bytes, signature_header: str | None) -> bool:
    """Verify HMAC SHA-256 signature from GitHub webhook header."""
    if not settings.WEBHOOK_SECRET:
        # If no webhook secret configured, pass in dev/test mode
        return True
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(
        settings.WEBHOOK_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    provided = signature_header.split("sha256=")[-1]
    return hmac.compare_digest(expected, provided)


@router.post("/github", status_code=202)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str | None = Header(None),
    x_sentinel_project_id: str | None = Header(None),
    db: Session = Depends(get_db),
):
    """Handle incoming GitHub webhook push event."""
    body_bytes = await request.body()

    if not _verify_github_signature(body_bytes, x_hub_signature_256):
        raise HTTPException(status_code=403, detail={"code": "INVALID_SIGNATURE", "message": "Webhook signature mismatch"})

    try:
        payload = json.loads(body_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail={"code": "INVALID_PAYLOAD", "message": "Expected JSON payload"})

    # Determine project
    project_id = x_sentinel_project_id
    if not project_id:
        repo_data = payload.get("repository", {})
        repo_url = repo_data.get("clone_url") or repo_data.get("html_url")
        if repo_url:
            all_projects = repo.list_projects(db)
            for p in all_projects:
                if p.repo_url and p.repo_url in repo_url:
                    project_id = p.id
                    break

    if not project_id:
        # Fall back to first available project or raise 404
        all_projects = repo.list_projects(db)
        if all_projects:
            project_id = all_projects[0].id
        else:
            raise HTTPException(status_code=404, detail={"code": "NO_PROJECT", "message": "No matching project found for webhook repository"})

    commit_sha = payload.get("after", "")
    # Check if files changed contain manifests or package.json
    commits = payload.get("commits", [])
    changed_files = []
    for c in commits:
        changed_files.extend(c.get("added", []) + c.get("modified", []))

    # Attempt to fetch real repository manifest from project repo_url
    manifest_content = ""
    if project.repo_url:
        try:
            from app.api.v1.projects import _get_manifest_content, _probe_manifests
            manifests = _probe_manifests(project.repo_url)
            if manifests:
                content_res = _get_manifest_content(project.repo_url, manifests[0]["path"])
                manifest_content = content_res.get("content", "")
        except Exception as e:
            logger.warning(f"Failed to fetch live manifest on webhook: {e}")

    if not manifest_content:
        manifest_content = json.dumps({
            "name": payload.get("repository", {}).get("name", project.name),
            "version": "1.0.0",
        })


    result = MonitoringService.trigger_repo_change(
        project_id=project_id,
        commit_sha=commit_sha,
        raw_content=manifest_content,
        background_tasks=background_tasks,
        db=db,
        input_format="package_json",
    )

    return {
        "status": "ACCEPTED",
        "message": f"Webhook processed for project {project_id}",
        "scan_id": result["scan_id"],
        "commit": commit_sha[:8] if commit_sha else None,
    }
