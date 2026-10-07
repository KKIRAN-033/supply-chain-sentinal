"""Repository abstraction layer.

Business logic uses these functions instead of raw SQLAlchemy queries.
This allows swapping SQLite → PostgreSQL or JSON fallback without
touching engine/service code.
"""
import json
import logging
import os
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import generate_id, utc_now
from app.db.models import (
    Organization, Project, Scan, Component, Dependency,
    Finding, RiskHistory, Policy, AuditLog,
)

logger = logging.getLogger(__name__)


def _json_fallback_save(collection: str, record_id: str, data: dict):
    """Emergency JSON persistence when SQLite is unavailable."""
    try:
        fallback_dir = settings.JSON_FALLBACK_DIR
        os.makedirs(os.path.join(fallback_dir, collection), exist_ok=True)
        path = os.path.join(fallback_dir, collection, f"{record_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        logger.warning(f"JSON fallback write: {collection}/{record_id}")
    except Exception as e:
        logger.error(f"JSON fallback also failed: {e}")


def _json_fallback_read(collection: str, record_id: str) -> Optional[dict]:
    """Read record from emergency JSON persistence when DB read fails."""
    try:
        path = os.path.join(settings.JSON_FALLBACK_DIR, collection, f"{record_id}.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"JSON fallback read failed for {collection}/{record_id}: {e}")
    return None


def _json_fallback_list(collection: str) -> list[dict]:
    """List records from emergency JSON persistence collection."""
    results = []
    try:
        coll_dir = os.path.join(settings.JSON_FALLBACK_DIR, collection)
        if os.path.exists(coll_dir):
            for fname in os.listdir(coll_dir):
                if fname.endswith(".json"):
                    fpath = os.path.join(coll_dir, fname)
                    with open(fpath, "r", encoding="utf-8") as f:
                        results.append(json.load(f))
    except Exception as e:
        logger.error(f"JSON fallback list failed for {collection}: {e}")
    return results



# ---------- Organization ----------

def create_organization(db: Session, name: str, org_id: Optional[str] = None) -> Organization:
    org = Organization(id=org_id or generate_id("org"), name=name)
    db.add(org)
    db.commit()
    db.refresh(org)
    _audit(db, org.id, None, "organization_created", "organization", org.id)
    return org


def get_organization(db: Session, org_id: str) -> Optional[Organization]:
    return db.query(Organization).filter(Organization.id == org_id).first()


# ---------- Project ----------

def create_project(
    db: Session, org_id: str, name: str,
    repo_url: str = None, environment: str = "production",
    criticality: str = "medium"
) -> Project:
    project = Project(
        id=generate_id("prj"),
        organization_id=org_id,
        name=name,
        repo_url=repo_url,
        environment=environment,
        criticality=criticality,
    )
    try:
        db.add(project)
        db.commit()
        db.refresh(project)
    except Exception as e:
        db.rollback()
        logger.error(f"DB error creating project: {e}")
        _json_fallback_save("projects", project.id, {
            "id": project.id, "organization_id": org_id, "name": name,
            "repo_url": repo_url, "environment": environment, "criticality": criticality,
            "created_at": str(project.created_at or utc_now()),
        })
    _audit(db, org_id, None, "project_created", "project", project.id)
    return project


def get_project(db: Session, project_id: str) -> Optional[Project]:
    try:
        proj = db.query(Project).filter(Project.id == project_id).first()
        if proj:
            return proj
    except Exception as e:
        logger.warning(f"DB error in get_project({project_id}): {e}")
    data = _json_fallback_read("projects", project_id)
    if data:
        return Project(**{k: v for k, v in data.items() if hasattr(Project, k)})
    return None


def list_projects(db: Session, org_id: str = None) -> list[Project]:
    try:
        q = db.query(Project)
        if org_id:
            q = q.filter(Project.organization_id == org_id)
        return q.order_by(Project.created_at.desc()).all()
    except Exception as e:
        logger.warning(f"DB error listing projects: {e}")
    items = _json_fallback_list("projects")
    if org_id:
        items = [i for i in items if i.get("organization_id") == org_id]
    return [Project(**{k: v for k, v in item.items() if hasattr(Project, k)}) for item in items]


# ---------- Scan ----------

def create_scan(
    db: Session, project_id: str, input_format: str = None,
    ecosystem: str = None, source: str = "upload", sbom_hash: str = None
) -> Scan:
    scan = Scan(
        id=generate_id("scn"),
        project_id=project_id,
        input_format=input_format,
        input_ecosystem=ecosystem,
        source=source,
        sbom_hash=sbom_hash,
    )
    try:
        db.add(scan)
        db.commit()
        db.refresh(scan)
    except Exception as e:
        db.rollback()
        logger.error(f"DB error creating scan: {e}")
        # JSON fallback
        scan.id = scan.id or generate_id("scn")
        _json_fallback_save("scans", scan.id, {
            "id": scan.id, "project_id": project_id,
            "status": "PENDING", "source": source,
            "sbom_hash": sbom_hash, "input_format": input_format,
        })
    _audit(db, None, None, "scan_created", "scan", scan.id)
    return scan


def update_scan(db: Session, scan_id: str, **kwargs) -> Optional[Scan]:
    scan = None
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            for key, value in kwargs.items():
                if hasattr(scan, key):
                    setattr(scan, key, value)
            db.commit()
            db.refresh(scan)
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        logger.error(f"DB error updating scan {scan_id}: {e}")

    # Mirror to JSON fallback
    existing_fb = _json_fallback_read("scans", scan_id) or {"id": scan_id}
    existing_fb.update(kwargs)
    _json_fallback_save("scans", scan_id, existing_fb)

    if scan:
        return scan
    data = _json_fallback_read("scans", scan_id)
    if data:
        return Scan(**{k: v for k, v in data.items() if hasattr(Scan, k)})
    return None


def get_scan(db: Session, scan_id: str) -> Optional[Scan]:
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            return scan
    except Exception as e:
        logger.warning(f"DB error in get_scan({scan_id}): {e}")
    data = _json_fallback_read("scans", scan_id)
    if data:
        return Scan(**{k: v for k, v in data.items() if hasattr(Scan, k)})
    return None


def list_scans(db: Session, project_id: str) -> list[Scan]:
    try:
        return (db.query(Scan)
                .filter(Scan.project_id == project_id)
                .order_by(Scan.created_at.desc(), Scan.id.desc())
                .all())
    except Exception as e:
        logger.warning(f"DB error listing scans for project {project_id}: {e}")
    items = _json_fallback_list("scans")
    matched = [Scan(**{k: v for k, v in item.items() if hasattr(Scan, k)}) for item in items if item.get("project_id") == project_id]
    matched.sort(key=lambda s: str(getattr(s, "created_at", "") or ""), reverse=True)
    return matched


# ---------- Component ----------

def save_components(db: Session, scan_id: str, components: list[dict]):
    for comp_data in components:
        comp = Component(
            id=generate_id("cmp"),
            scan_id=scan_id,
            **comp_data,
        )
        db.add(comp)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"DB error saving components for scan {scan_id}: {e}")
        _json_fallback_save("components", scan_id, {"components": components})


def get_components(db: Session, scan_id: str) -> list[Component]:
    try:
        return db.query(Component).filter(Component.scan_id == scan_id).all()
    except Exception as e:
        logger.warning(f"DB error getting components for scan {scan_id}: {e}")
    data = _json_fallback_read("components", scan_id)
    if data and "components" in data:
        return [Component(**{k: v for k, v in c.items() if hasattr(Component, k)}) for c in data["components"]]
    return []


# ---------- Dependency ----------

def save_dependencies(db: Session, scan_id: str, edges: list[dict]):
    for edge in edges:
        dep = Dependency(
            id=generate_id("dep"),
            scan_id=scan_id,
            parent_purl=edge["parent_purl"],
            child_purl=edge["child_purl"],
        )
        db.add(dep)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"DB error saving dependencies for scan {scan_id}: {e}")
        _json_fallback_save("dependencies", scan_id, {"edges": edges})


def get_dependencies(db: Session, scan_id: str) -> list[Dependency]:
    try:
        return db.query(Dependency).filter(Dependency.scan_id == scan_id).all()
    except Exception as e:
        logger.warning(f"DB error getting dependencies for scan {scan_id}: {e}")
    data = _json_fallback_read("dependencies", scan_id)
    if data and "edges" in data:
        return [Dependency(parent_purl=e.get("parent_purl", e.get("parent")), child_purl=e.get("child_purl", e.get("child"))) for e in data["edges"]]
    return []


# ---------- Finding ----------

def save_findings(db: Session, scan_id: str, findings: list[dict]):
    for f_data in findings:
        finding = Finding(
            id=generate_id("fnd"),
            scan_id=scan_id,
            **f_data,
        )
        db.add(finding)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"DB error saving findings for scan {scan_id}: {e}")
        _json_fallback_save("findings", scan_id, {"findings": findings})


def get_findings(db: Session, scan_id: str, category: str = None, severity: str = None) -> list[Finding]:
    try:
        q = db.query(Finding).filter(Finding.scan_id == scan_id)
        if category:
            q = q.filter(Finding.category == category)
        if severity:
            q = q.filter(Finding.severity == severity)
        return q.order_by(Finding.score.desc()).all()
    except Exception as e:
        logger.warning(f"DB error getting findings for scan {scan_id}: {e}")
    data = _json_fallback_read("findings", scan_id)
    if data and "findings" in data:
        findings = [Finding(**{k: v for k, v in f.items() if hasattr(Finding, k)}) for f in data["findings"]]
        if category:
            findings = [f for f in findings if f.category == category]
        if severity:
            findings = [f for f in findings if f.severity == severity]
        return findings
    return []


# ---------- Risk History ----------

def save_risk_history(
    db: Session, project_id: str, scan_id: str,
    score: float, risk_level: str, confidence: float = None,
    total_findings: int = 0, critical_count: int = 0,
    high_count: int = 0, medium_count: int = 0, low_count: int = 0,
):
    rh = RiskHistory(
        id=generate_id("rh"),
        project_id=project_id,
        scan_id=scan_id,
        score=score,
        risk_level=risk_level,
        confidence=confidence,
        total_findings=total_findings,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
    )
    db.add(rh)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"DB error saving risk history: {e}")
        _json_fallback_save("risk_history", rh.id, {
            "id": rh.id,
            "project_id": project_id, "scan_id": scan_id,
            "score": score, "risk_level": risk_level,
            "confidence": confidence, "total_findings": total_findings,
            "critical_count": critical_count, "high_count": high_count,
            "medium_count": medium_count, "low_count": low_count,
            "created_at": str(rh.created_at or utc_now()),
        })


def get_risk_history(db: Session, project_id: str) -> list[RiskHistory]:
    try:
        return (db.query(RiskHistory)
                .filter(RiskHistory.project_id == project_id)
                .order_by(RiskHistory.created_at.asc())
                .all())
    except Exception as e:
        logger.warning(f"DB error getting risk history for project {project_id}: {e}")
    items = _json_fallback_list("risk_history")
    matched = [RiskHistory(**{k: v for k, v in item.items() if hasattr(RiskHistory, k)}) for item in items if item.get("project_id") == project_id]
    return matched



# ---------- Policy ----------

def create_policy(db: Session, project_id: str, name: str, environment: str, rules: dict) -> Policy:
    policy = Policy(
        id=generate_id("pol"),
        project_id=project_id,
        name=name,
        environment=environment,
        rules=rules,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


def get_policies(db: Session, project_id: str) -> list[Policy]:
    return db.query(Policy).filter(Policy.project_id == project_id, Policy.is_active == True).all()


def delete_policy(db: Session, policy_id: str) -> bool:
    pol = db.query(Policy).filter(Policy.id == policy_id).first()
    if pol:
        db.delete(pol)
        db.commit()
        return True
    return False



# ---------- Audit ----------

def _audit(db: Session, org_id: str, user_id: str, action: str,
           resource_type: str = None, resource_id: str = None, details: dict = None):
    """Internal audit log helper."""
    log = AuditLog(
        id=generate_id("aud"),
        organization_id=org_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
    )
    try:
        db.add(log)
        db.commit()
    except Exception:
        db.rollback()
        logger.warning(f"Audit log failed for action={action}")


def save_audit_event(db: Session, action: str, resource_type: str = None,
                     resource_id: str = None, details: dict = None,
                     org_id: str = None, user_id: str = None):
    _audit(db, org_id, user_id, action, resource_type, resource_id, details)


def get_audit_logs(db: Session, org_id: str = None, project_id: str = None, limit: int = 100) -> list[AuditLog]:
    q = db.query(AuditLog)
    if org_id:
        q = q.filter(AuditLog.organization_id == org_id)
    logs = q.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).all()
    if project_id:
        project_scans = {s.id for s in db.query(Scan.id).filter(Scan.project_id == project_id).all()}
        filtered = []
        for l in logs:
            if l.resource_id == project_id or l.resource_id in project_scans:
                filtered.append(l)
            elif l.details and isinstance(l.details, dict) and l.details.get("project_id") == project_id:
                filtered.append(l)
        return filtered[:limit]
    return logs[:limit]
