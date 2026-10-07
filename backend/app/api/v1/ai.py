"""AI Security Analyst API endpoints."""
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.base import get_db
from app.db import repositories as repo
from app.engine.ai.context import build_security_context
from app.engine.ai.analyst import AISecurityAnalyst

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai", tags=["ai"])


class AIAnalyzeRequest(BaseModel):
    project_id: str
    scan_id: Optional[str] = None
    finding_id: Optional[str] = None
    component_purl: Optional[str] = None
    question: Optional[str] = None
    mode: Optional[str] = "auto"


@router.post("/analyze")
def analyze_security_context(req: AIAnalyzeRequest, db: Session = Depends(get_db)):
    """Unified AI Security Analyst endpoint.
    
    Grounds all analysis, risk explanations, and remediation in authoritative backend data.
    """
    try:
        context = build_security_context(
            db,
            project_id=req.project_id,
            scan_id=req.scan_id,
            finding_id=req.finding_id,
            component_purl=req.component_purl,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail={"code": "PROJECT_NOT_FOUND", "message": str(e)})
    except Exception as e:
        logger.error(f"Error constructing security context: {e}")
        raise HTTPException(status_code=500, detail={"code": "CONTEXT_BUILD_ERROR", "message": str(e)})

    analyst = AISecurityAnalyst()
    result = analyst.analyze(context, question=req.question, mode=req.mode or "auto")

    # Record structured audit event for AI assistance
    try:
        repo.save_audit_event(
            db,
            action="ai_analyst_consulted",
            resource_type="finding" if req.finding_id else "project",
            resource_id=req.finding_id or req.project_id,
            details={
                "project_id": req.project_id,
                "finding_id": req.finding_id,
                "question": req.question or f"Mode: {req.mode}",
                "provider": result.get("provider"),
                "recommended_action": result.get("recommended_solution", {}).get("action"),
                "target_version": result.get("recommended_solution", {}).get("target_version"),
            },
        )
    except Exception as e:
        logger.warning(f"Failed to record AI audit event: {e}")

    return result


@router.get("/suggested-questions")
def get_suggested_questions(project_id: str, finding_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Return contextual, evidence-grounded questions tailored to active finding or project state."""
    if finding_id:
        return [
            {"id": "explain", "text": "Explain this finding simply.", "mode": "explain"},
            {"id": "solution", "text": "How do I fix this vulnerability?", "mode": "remediate"},
            {"id": "safe_upgrade", "text": "Can I safely upgrade this package?", "mode": "remediate"},
            {"id": "ignore", "text": "What happens if I ignore this finding?", "mode": "explain"},
            {"id": "exploitable", "text": "Is this vulnerability actually exploitable?", "mode": "explain"},
            {"id": "commands", "text": "What exact shell commands should I run?", "mode": "remediate"},
        ]

    # Project-level questions
    return [
        {"id": "why_score", "text": "Why is the risk score this high?", "mode": "risk"},
        {"id": "what_first", "text": "Which finding should I fix first?", "mode": "prioritize"},
        {"id": "why_policy", "text": "Why was the policy set to this decision?", "mode": "policy"},
        {"id": "blast_radius", "text": "Which dependency has the largest blast radius?", "mode": "risk"},
        {"id": "diff", "text": "What changed between the previous scan and current scan?", "mode": "diff"},
        {"id": "next_action", "text": "What should I do next?", "mode": "auto"},
    ]
