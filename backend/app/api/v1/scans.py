"""Scan API endpoints."""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from app.db.base import get_db, SessionLocal
from app.db import repositories as repo
from app.schemas.scans import ScanCreateRequest, ScanStatusResponse
from app.core.constants import ScanStatus, SCAN_PROGRESS, SCAN_MESSAGES
from app.core.security import compute_sha256, validate_api_key
from app.engine.orchestrator import run_scan
from app.engine.comparator import compare_scans
from app.engine.explainability.service import ExplainabilityService

router = APIRouter(tags=["scans"])


@router.post("/projects/{project_id}/scans", status_code=202)
def create_scan(
    project_id: str,
    req: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    auth: str = Depends(validate_api_key),
):
    """Create and start a new scan. Returns 202 immediately."""
    # Validate project exists
    project = repo.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail={
            "code": "PROJECT_NOT_FOUND",
            "message": f"Project {project_id} not found",
        })

    # Validate input
    if not req.raw_content or not req.raw_content.strip():
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_SBOM",
            "message": "raw_content is required",
        })

    # Check upload size (rough check)
    content_bytes = req.raw_content.encode("utf-8")
    max_bytes = 50 * 1024 * 1024  # 50MB
    if len(content_bytes) > max_bytes:
        raise HTTPException(status_code=400, detail={
            "code": "UPLOAD_TOO_LARGE",
            "message": f"Content exceeds {max_bytes // (1024*1024)}MB limit",
        })

    sbom_hash = compute_sha256(content_bytes)

    scan = repo.create_scan(
        db, project_id,
        input_format=req.input_type if req.input_type != "auto" else None,
        ecosystem=req.ecosystem,
        source=req.source,
        sbom_hash=sbom_hash,
    )

    repo.save_audit_event(db, "scan_started", "scan", scan.id, {
        "project_id": project_id,
        "input_type": req.input_type,
        "sbom_hash": sbom_hash,
    })

    # Schedule background scan — orchestrator gets its own DB session
    raw_content = req.raw_content
    scan_id = scan.id
    
    # Save raw_content for later retrieval
    try:
        import os
        from app.core.config import settings
        sbom_dir = os.path.join(settings.JSON_FALLBACK_DIR, "sboms")
        os.makedirs(sbom_dir, exist_ok=True)
        with open(os.path.join(sbom_dir, f"{scan_id}.txt"), "w", encoding="utf-8") as f:
            f.write(raw_content)
    except Exception as e:
        pass

    def _run_in_background():
        bg_db = SessionLocal()
        try:
            run_scan(scan_id, raw_content, bg_db)
        finally:
            bg_db.close()

    background_tasks.add_task(_run_in_background)

    return {
        "scan_id": scan.id,
        "status": "PENDING",
        "created_at": str(scan.created_at),
    }


@router.get("/scans/{scan_id}/status")
def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    scan = repo.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail={
            "code": "SCAN_NOT_FOUND",
            "message": f"Scan {scan_id} not found",
        })

    status = scan.status or "PENDING"
    try:
        progress = SCAN_PROGRESS.get(ScanStatus(status), 0)
        message = SCAN_MESSAGES.get(ScanStatus(status), "")
    except ValueError:
        progress = 0
        message = status

    result = {
        "scan_id": scan.id,
        "status": status,
        "progress": progress,
        "message": message,
        "created_at": str(scan.created_at),
    }

    if status == "FAILED":
        result["error"] = {
            "code": scan.error_code,
            "message": scan.error_message,
        }

    if status == "COMPLETED":
        result["overall_score"] = scan.overall_score
        result["risk_level"] = scan.risk_level
        result["policy_decision"] = scan.policy_decision

    return result


@router.get("/scans/{scan_id}/report")
def get_scan_report(scan_id: str, db: Session = Depends(get_db)):
    scan = repo.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail={
            "code": "SCAN_NOT_FOUND",
            "message": f"Scan {scan_id} not found",
        })

    if scan.status != "COMPLETED":
        raise HTTPException(status_code=400, detail={
            "code": "SCAN_NOT_COMPLETE",
            "message": f"Scan is still {scan.status}",
        })

    findings = repo.get_findings(db, scan_id)
    components = repo.get_components(db, scan_id)
    deps = repo.get_dependencies(db, scan_id)

    report_dict = {
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "summary": {
            "overall_score": scan.overall_score,
            "risk_level": scan.risk_level,
            "confidence": scan.confidence,
            "data_quality": scan.data_quality,
            "total_dependencies": scan.total_components,
            "vulnerable_count": scan.vulnerable_count,
            "suspicious_count": scan.suspicious_count,
            "outdated_count": scan.outdated_count,
        },
        "metrics_breakdown": scan.metrics_breakdown or {},
        "policy_decision": scan.policy_decision,
        "provenance": getattr(scan, "provenance", None) or {
            "format": scan.input_format,
            "sbom_hash": scan.sbom_hash,
            "spec_version": getattr(scan, "spec_version", None),
            "serial_number": getattr(scan, "serial_number", None),
        },
        "findings": [_finding_response(f) for f in findings],
        "components": [_component_response(c) for c in components],
        "dependencies": [{"parent": d.parent_purl, "child": d.child_purl} for d in deps],
    }
    report_dict["explainability"] = ExplainabilityService.generate_explanation(report_dict)
    return report_dict


@router.get("/scans/{scan_id}/findings")
def get_scan_findings(
    scan_id: str,
    category: str = None,
    severity: str = None,
    db: Session = Depends(get_db),
):
    scan = repo.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail={
            "code": "SCAN_NOT_FOUND",
            "message": f"Scan {scan_id} not found",
        })

    findings = repo.get_findings(db, scan_id, category=category, severity=severity)
    return [_finding_response(f) for f in findings]


@router.get("/projects/{project_id}/risk-history")
def get_risk_history(project_id: str, db: Session = Depends(get_db)):
    project = repo.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail={
            "code": "PROJECT_NOT_FOUND",
            "message": f"Project {project_id} not found",
        })

    history = repo.get_risk_history(db, project_id)
    return [{
        "scan_id": h.scan_id,
        "score": h.score,
        "risk_level": h.risk_level,
        "confidence": h.confidence,
        "total_findings": h.total_findings,
        "critical_count": h.critical_count,
        "high_count": h.high_count,
        "medium_count": h.medium_count,
        "low_count": h.low_count,
        "created_at": str(h.created_at),
    } for h in history]


@router.get("/projects/{project_id}/dependencies")
def get_project_dependencies(project_id: str, db: Session = Depends(get_db)):
    scans = repo.list_scans(db, project_id)
    if not scans:
        return {"nodes": [], "edges": [], "components": []}
    completed_scans = [s for s in scans if s.status == "COMPLETED"]
    latest = completed_scans[0] if completed_scans else scans[0]
    components = repo.get_components(db, latest.id)
    deps = repo.get_dependencies(db, latest.id)
    findings = repo.get_findings(db, latest.id)

    # Build vulnerability map for graph coloring
    vuln_map = {}
    for f in findings:
        purl = f.component_purl
        if purl not in vuln_map or f.severity in ("CRITICAL", "HIGH"):
            vuln_map[purl] = f.severity

    nodes = []
    for c in components:
        nodes.append({
            "data": {
                "id": c.purl,
                "label": f"{c.name}@{c.version}" if c.version else c.name,
                "name": c.name,
                "version": c.version,
                "ecosystem": c.ecosystem,
                "is_direct": c.is_direct,
                "scope": c.scope,
                "severity": vuln_map.get(c.purl),
            }
        })

    edges = []
    for i, d in enumerate(deps):
        edges.append({
            "data": {
                "id": f"e{i}",
                "source": d.parent_purl,
                "target": d.child_purl,
            }
        })

    return {"nodes": nodes, "edges": edges}


def _finding_response(f) -> dict:
    return {
        "id": f.id,
        "component_purl": f.component_purl,
        "component_name": f.component_name,
        "category": f.category,
        "severity": f.severity,
        "score": f.score,
        "confidence": f.confidence,
        "title": f.title,
        "description": f.description,
        "cve_id": f.cve_id,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "is_suppressed": f.is_suppressed,
    }


def _component_response(c) -> dict:
    return {
        "purl": c.purl,
        "name": c.name,
        "version": c.version,
        "ecosystem": c.ecosystem,
        "scope": c.scope,
        "is_direct": c.is_direct,
        "is_pinned": c.is_pinned,
    }


@router.get("/scans/{scan_id}/explain")
def get_scan_explanation(scan_id: str, db: Session = Depends(get_db)):
    """Fetch structured explainability for a completed scan."""
    scan = repo.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": f"Scan {scan_id} not found"})
    if scan.status != "COMPLETED":
        raise HTTPException(status_code=400, detail={"code": "SCAN_NOT_COMPLETE", "message": f"Scan is {scan.status}"})
    report = get_scan_report(scan_id, db)
    return ExplainabilityService.generate_explanation(report)


@router.get("/scans/{scan_id}/compare/{base_scan_id}")
def compare_scan_pair(scan_id: str, base_scan_id: str, db: Session = Depends(get_db)):
    """Compare scan with a specific base scan."""
    try:
        return compare_scans(db, base_scan_id, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": str(e)})


@router.get("/scans/{scan_id}/diff")
def get_scan_diff(scan_id: str, base_scan_id: str = None, db: Session = Depends(get_db)):
    """Compute fix verification diff against previous scan or specified base scan."""
    scan = repo.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": f"Scan {scan_id} not found"})

    if not base_scan_id:
        target_comps = repo.get_components(db, scan_id)
        target_ecosystems = {c.ecosystem.lower() for c in target_comps if c.ecosystem and c.scope != "root"}

        all_scans = repo.list_scans(db, scan.project_id)
        prev_scans = [s for s in all_scans if s.id != scan_id and s.status == "COMPLETED" and s.created_at <= scan.created_at]

        # Only pick a previous scan that shares the same ecosystem!
        for prev in prev_scans:
            prev_comps = repo.get_components(db, prev.id)
            prev_ecosystems = {c.ecosystem.lower() for c in prev_comps if c.ecosystem and c.scope != "root"}
            if target_ecosystems and prev_ecosystems and (target_ecosystems & prev_ecosystems):
                base_scan_id = prev.id
                break

    if not base_scan_id:
        findings = repo.get_findings(db, scan_id)
        return {
            "base_scan_id": None,
            "target_scan_id": scan_id,
            "base_score": 0.0,
            "target_score": scan.overall_score or 0.0,
            "risk_delta": 0.0,
            "counts": {"resolved": 0, "new": 0, "still_open": 0, "base_total": 0, "target_total": len(findings)},
            "resolved_findings": [],
            "new_findings": [],
            "still_open_findings": [],
        }

    try:
        return compare_scans(db, base_scan_id, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": str(e)})

@router.get("/scans/{scan_id}/raw")
def get_scan_raw(scan_id: str, db: Session = Depends(get_db)):
    """Fetch raw SBOM content for a scan."""
    scan = repo.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": f"Scan {scan_id} not found"})
    
    import os
    from app.core.config import settings
    path = os.path.join(settings.JSON_FALLBACK_DIR, "sboms", f"{scan_id}.txt")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return {"raw_content": f.read()}
    
    raise HTTPException(status_code=404, detail={"code": "CONTENT_NOT_FOUND", "message": "Raw content not available"})


# ==============================================================================
# AUDIT LOGS, WHAT-IF SIMULATOR, ATTACK PATHS & MONITORING ENDPOINTS
# ==============================================================================

from pydantic import BaseModel
from typing import Optional
from app.engine.scoring.risk_engine import calculate_risk
import networkx as nx


class SimulateRequest(BaseModel):
    action: str  # upgrade, remove, replace
    component_purl: str
    target_version: Optional[str] = None


@router.get("/audit-logs")
def list_audit_logs(
    org_id: Optional[str] = None,
    project_id: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Fetch structured audit evidence logs directly from the backend database."""
    logs = repo.get_audit_logs(db, org_id=org_id, project_id=project_id, limit=limit)
    return [
        {
            "id": l.id,
            "organization_id": l.organization_id or "org_default",
            "user_id": l.user_id or "system",
            "action": l.action,
            "resource_type": l.resource_type,
            "resource_id": l.resource_id,
            "details": l.details,
            "created_at": str(l.created_at),
        }
        for l in logs
    ]


@router.post("/scans/{scan_id}/simulate")
def simulate_remediation(scan_id: str, req: SimulateRequest, db: Session = Depends(get_db)):
    """Deterministic What-If simulator: calculates projected risk if a component is upgraded or removed."""
    scan = repo.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": f"Scan {scan_id} not found"})
    
    findings = repo.get_findings(db, scan_id)
    orig_score = scan.overall_score or 0.0
    
    # Identify findings on this component
    comp_findings = [
        f for f in findings 
        if f.component_purl == req.component_purl or (f.component_name and f.component_name.lower() in req.component_purl.lower())
    ]
    
    mitigated = []
    remaining = []
    
    if req.action == "remove":
        mitigated = comp_findings
        remaining = [f for f in findings if f not in comp_findings]
    elif req.action in ("upgrade", "replace"):
        for f in findings:
            if f in comp_findings:
                fixed_versions = (f.evidence or {}).get("fixed_versions", [])
                if req.target_version and fixed_versions:
                    mitigated.append(f)
                else:
                    mitigated.append(f)
            else:
                remaining.append(f)
    else:
        remaining = findings

    # Convert remaining findings to dicts for calculate_risk
    remaining_dicts = [
        {
            "category": f.category,
            "severity": f.severity,
            "score": f.score,
            "evidence": f.evidence or {},
            "component_purl": f.component_purl,
            "component_name": f.component_name,
        }
        for f in remaining
    ]
    
    sim_result = calculate_risk(remaining_dicts, blast_radius=None)
    proj_score = sim_result["risk_score"]
    delta = round(proj_score - orig_score, 1)

    return {
        "scan_id": scan_id,
        "action": req.action,
        "component_purl": req.component_purl,
        "target_version": req.target_version,
        "original_score": orig_score,
        "projected_score": proj_score,
        "risk_delta": delta,
        "mitigated_count": len(mitigated),
        "mitigated_findings": [f.title for f in mitigated],
        "remaining_count": len(remaining),
        "projected_risk_level": sim_result["risk_level"],
        "projected_metrics": sim_result["metrics_breakdown"],
        "explanation": f"Simulating {req.action} on {req.component_purl} resolves {len(mitigated)} finding(s), moving risk score from {orig_score} to {proj_score} ({delta:+0.1f} pts).",
    }


@router.get("/scans/{scan_id}/attack-paths")
def get_attack_paths(scan_id: str, db: Session = Depends(get_db)):
    """Compute deterministic graph attack paths from application entry down to vulnerable dependencies."""
    scan = repo.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": f"Scan {scan_id} not found"})
        
    components = repo.get_components(db, scan_id)
    dependencies = repo.get_dependencies(db, scan_id)
    findings = repo.get_findings(db, scan_id)
    
    if not components or not findings:
        return {"paths": [], "total_paths": 0}
        
    G = nx.DiGraph()
    comp_map = {c.purl: c for c in components}
    
    for c in components:
        G.add_node(c.purl, name=c.name, version=c.version, is_direct=c.is_direct, scope=c.scope)
        
    for d in dependencies:
        G.add_edge(d.parent_purl, d.child_purl)
        
    roots = [c.purl for c in components if c.is_direct or G.in_degree(c.purl) == 0]
    
    paths = []
    path_id = 1
    
    for f in findings:
        target = f.component_purl
        if target not in G:
            continue
            
        for root in roots:
            if root == target:
                c = comp_map.get(target)
                paths.append({
                    "id": f"path_{path_id}",
                    "target_component": c.name if c else target,
                    "target_purl": target,
                    "severity": f.severity,
                    "cve_id": f.cve_id or f.title,
                    "title": f.title,
                    "score": f.score,
                    "length": 1,
                    "chain": [
                        {"purl": target, "name": c.name if c else target, "version": c.version if c else "", "is_direct": True}
                    ],
                })
                path_id += 1
                break
            elif nx.has_path(G, root, target):
                p_nodes = nx.shortest_path(G, root, target)
                chain = []
                for node in p_nodes:
                    c = comp_map.get(node)
                    chain.append({
                        "purl": node,
                        "name": c.name if c else node,
                        "version": c.version if c else "",
                        "is_direct": c.is_direct if c else False,
                    })
                paths.append({
                    "id": f"path_{path_id}",
                    "target_component": comp_map[target].name if target in comp_map else target,
                    "target_purl": target,
                    "severity": f.severity,
                    "cve_id": f.cve_id or f.title,
                    "title": f.title,
                    "score": f.score,
                    "length": len(chain),
                    "chain": chain,
                })
                path_id += 1
                break

    paths.sort(key=lambda p: p["score"], reverse=True)
    return {"paths": paths, "total_paths": len(paths)}


@router.get("/monitoring/{project_id}/status")
def get_monitoring_status(project_id: str, db: Session = Depends(get_db)):
    """Retrieve continuous monitoring status for project."""
    project = repo.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail={"code": "PROJECT_NOT_FOUND", "message": f"Project {project_id} not found"})
        
    scans = repo.list_scans(db, project_id)
    policies = repo.get_policies(db, project_id)
    audit_logs = repo.get_audit_logs(db, limit=25)
    
    recent_events = [
        {
            "id": a.id,
            "action": a.action,
            "resource_type": a.resource_type,
            "created_at": str(a.created_at),
            "details": a.details,
        }
        for a in audit_logs if a.resource_id == project_id or (scans and a.resource_id in [s.id for s in scans])
    ]
    
    return {
        "project_id": project_id,
        "project_name": project.name,
        "is_active": len(scans) > 0,
        "status_label": "Continuous Monitoring Active" if scans else "Monitoring configured but not active",
        "last_scan_at": str(scans[0].created_at) if scans else None,
        "total_scans": len(scans),
        "active_policies": len([p for p in policies if p.is_active]),
        "monitored_ecosystems": list({s.input_format for s in scans if s.input_format}),
        "recent_events": recent_events,
    }

