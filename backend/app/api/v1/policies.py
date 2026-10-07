"""Policy API endpoints with AI-powered policy synthesis."""
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.base import get_db
from app.db import repositories as repo
from app.schemas.policies import PolicyCreateRequest
from app.engine.policy.ai_policy_generator import generate_ai_policy_for_project

logger = logging.getLogger(__name__)

router = APIRouter(tags=["policies"])


class AIPolicyGenerateRequest(BaseModel):
    environment: Optional[str] = None
    criticality: Optional[str] = None


def _detect_project_ecosystems(db: Session, project) -> list[str]:
    """Detect ecosystems associated with the project from its components or manifests."""
    ecosystems = set()
    
    # 1. From database scans & components if any
    try:
        scans = repo.get_scans_by_project(db, project.id)
        for s in scans:
            if s.input_ecosystem:
                ecosystems.add(s.input_ecosystem.lower())
    except Exception:
        pass

    # 2. Heuristics from project repo or name
    if project.repo_url:
        repo_lower = project.repo_url.lower()
        if "python" in repo_lower:
            ecosystems.add("pypi")
        if "node" in repo_lower or "react" in repo_lower or "vue" in repo_lower:
            ecosystems.add("npm")

    # Default to python + npm if empty as full-stack standard
    if not ecosystems:
        ecosystems = {"pypi", "npm"}

    return list(ecosystems)


@router.get("/projects/{project_id}/policies")
def get_policies(project_id: str, auto_generate: bool = True, db: Session = Depends(get_db)):
    """Retrieve policies for a project. Automatically synthesizes tailored AI policy if none exist."""
    project = repo.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail={
            "code": "PROJECT_NOT_FOUND",
            "message": f"Project {project_id} not found",
        })

    policies = repo.get_policies(db, project_id)

    # If no policies exist and auto_generate is enabled, synthesize an AI-tailored policy immediately!
    if not policies and auto_generate:
        ecosystems = _detect_project_ecosystems(db, project)
        ai_spec = generate_ai_policy_for_project(
            project_name=project.name,
            environment=project.environment,
            criticality=project.criticality,
            repo_url=project.repo_url,
            detected_ecosystems=ecosystems,
        )
        created = repo.create_policy(
            db,
            project_id=project.id,
            name=ai_spec["name"],
            environment=ai_spec["environment"],
            rules=ai_spec["rules"],
        )
        policies = [created]

    return [{
        "id": p.id,
        "project_id": p.project_id,
        "name": p.name,
        "environment": p.environment,
        "rules": p.rules,
        "is_active": p.is_active,
    } for p in policies]


@router.post("/projects/{project_id}/policies/ai-generate", status_code=201)
def generate_ai_policy(
    project_id: str,
    req: AIPolicyGenerateRequest = None,
    db: Session = Depends(get_db),
):
    """Generate and apply an AI-tailored security policy tailored specifically to the project."""
    project = repo.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail={
            "code": "PROJECT_NOT_FOUND",
            "message": f"Project {project_id} not found",
        })

    env = (req.environment if req and req.environment else project.environment) or "production"
    crit = (req.criticality if req and req.criticality else project.criticality) or "medium"
    ecosystems = _detect_project_ecosystems(db, project)

    ai_spec = generate_ai_policy_for_project(
        project_name=project.name,
        environment=env,
        criticality=crit,
        repo_url=project.repo_url,
        detected_ecosystems=ecosystems,
    )

    policy = repo.create_policy(
        db,
        project_id=project.id,
        name=ai_spec["name"],
        environment=ai_spec["environment"],
        rules=ai_spec["rules"],
    )

    return {
        "id": policy.id,
        "project_id": policy.project_id,
        "name": policy.name,
        "environment": policy.environment,
        "rules": policy.rules,
        "is_active": policy.is_active,
    }


@router.post("/projects/{project_id}/policies", status_code=201)
def create_policy(
    project_id: str,
    req: PolicyCreateRequest,
    db: Session = Depends(get_db),
):
    """Create a manual policy for a project."""
    project = repo.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail={
            "code": "PROJECT_NOT_FOUND",
            "message": f"Project {project_id} not found",
        })
    policy = repo.create_policy(db, project_id, req.name, req.environment, req.rules)
    return {
        "id": policy.id,
        "project_id": policy.project_id,
        "name": policy.name,
        "environment": policy.environment,
        "rules": policy.rules,
        "is_active": policy.is_active,
    }


@router.delete("/projects/{project_id}/policies/{policy_id}")
def delete_policy(
    project_id: str,
    policy_id: str,
    db: Session = Depends(get_db),
):
    """Delete a policy."""
    success = repo.delete_policy(db, policy_id)
    if not success:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"status": "deleted", "policy_id": policy_id}
