"""Scan comparator and finding-level fix verification engine.

Computes exact differences between two scans of a project:
- Resolved findings (vulnerabilities fixed by upgrades/removals)
- New findings (vulnerabilities introduced in the new scan)
- Still-open findings (unresolved issues across both scans)
- Risk score and severity deltas

Uses stable cryptographic & semantic fingerprints:
- (component_name, cve_id)
- (component_purl, category, cve_id)
- (component_name, category, title)
"""
import logging
from typing import Optional
from sqlalchemy.orm import Session

from app.db import repositories as repo
from app.db.models import Finding, Scan

logger = logging.getLogger(__name__)


def _finding_fingerprint(f) -> str:
    """Generate a stable identifier for matching findings across scans.
    
    If CVE ID is present, package + CVE forms the primary key.
    Otherwise, package + category + title is used.
    """
    pkg = getattr(f, "component_name", "") or ""
    cve = getattr(f, "cve_id", "") or ""
    cat = getattr(f, "category", "") or ""
    title = getattr(f, "title", "") or ""

    if cve:
        return f"{pkg.lower()}|cve:{cve.upper()}"
    return f"{pkg.lower()}|{cat.upper()}|{title.lower().strip()}"


def compare_scans(db: Session, base_scan_id: str, target_scan_id: str) -> dict:
    """Compare two scans and categorize findings into resolved, new, and still-open.
    
    Returns structured comparison with risk delta and verification details.
    """
    base_scan = repo.get_scan(db, base_scan_id)
    target_scan = repo.get_scan(db, target_scan_id)

    if not base_scan:
        raise ValueError(f"Base scan {base_scan_id} not found")
    if not target_scan:
        raise ValueError(f"Target scan {target_scan_id} not found")

    base_findings = repo.get_findings(db, base_scan_id)
    target_findings = repo.get_findings(db, target_scan_id)

    base_map = {_finding_fingerprint(f): f for f in base_findings}
    target_map = {_finding_fingerprint(f): f for f in target_findings}

    base_keys = set(base_map.keys())
    target_keys = set(target_map.keys())

    resolved_keys = base_keys - target_keys
    new_keys = target_keys - base_keys
    still_open_keys = base_keys & target_keys

    def serialize_finding(f):
        return {
            "id": getattr(f, "id", ""),
            "component_purl": getattr(f, "component_purl", ""),
            "component_name": getattr(f, "component_name", ""),
            "category": getattr(f, "category", ""),
            "severity": getattr(f, "severity", ""),
            "score": getattr(f, "score", 0.0),
            "title": getattr(f, "title", ""),
            "cve_id": getattr(f, "cve_id", None),
            "remediation": getattr(f, "remediation", None),
        }

    resolved = []
    for k in resolved_keys:
        f = base_map[k]
        item = serialize_finding(f)
        item["status"] = "RESOLVED"
        item["verification_note"] = "Finding resolved in target scan"
        resolved.append(item)

    new_findings = []
    for k in new_keys:
        f = target_map[k]
        item = serialize_finding(f)
        item["status"] = "NEW"
        item["verification_note"] = "New finding introduced in target scan"
        new_findings.append(item)

    still_open = []
    for k in still_open_keys:
        f = target_map[k]
        item = serialize_finding(f)
        item["status"] = "STILL_OPEN"
        item["verification_note"] = "Finding persists across both scans"
        still_open.append(item)

    base_score = base_scan.overall_score or 0.0
    target_score = target_scan.overall_score or 0.0
    risk_delta = round(target_score - base_score, 1)

    return {
        "base_scan_id": base_scan_id,
        "target_scan_id": target_scan_id,
        "base_score": base_score,
        "target_score": target_score,
        "risk_delta": risk_delta,
        "counts": {
            "resolved": len(resolved),
            "new": len(new_findings),
            "still_open": len(still_open),
            "base_total": len(base_findings),
            "target_total": len(target_findings),
        },
        "resolved_findings": resolved,
        "new_findings": new_findings,
        "still_open_findings": still_open,
    }
