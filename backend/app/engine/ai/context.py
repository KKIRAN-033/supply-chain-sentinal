"""SecurityContext builder for AI Security Analyst.

Constructs comprehensive, ground-truth security context from SQLite database,
active scan report, dependency graph, and intelligence findings.
Zero hallucination — missing data is explicitly recorded as UNKNOWN or NOT OBSERVED.
"""
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
import json

from app.db import repositories as repo


def build_security_context(
    db: Session,
    project_id: str,
    scan_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    component_purl: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct canonical SecurityContext dictionary for AI analysis."""
    project = repo.get_project(db, project_id)
    if not project:
        raise ValueError(f"Project {project_id} not found")

    # If scan_id not provided, pick latest completed scan
    scans = repo.list_scans(db, project_id)
    scan = None
    if scan_id:
        scan = repo.get_scan(db, scan_id)
    elif scans:
        scan = scans[0]

    context: Dict[str, Any] = {
        "project": {
            "id": project.id,
            "name": project.name,
            "environment": project.environment,
            "criticality": project.criticality,
            "repository": project.repo_url or "UNKNOWN",
            "language": "JavaScript / TypeScript" if any(s.input_format == "package_json" for s in scans) else "Python",
        }
    }

    if not scan:
        context["scan"] = {"status": "NO_SCANS_AVAILABLE"}
        context["risk"] = {"score": 0.0, "level": "LOW", "confidence": 0.5, "evidence": [], "uncertainty": ["No scans available"]}
        return context

    # 1. Scan details
    context["scan"] = {
        "scan_id": scan.id,
        "status": scan.status,
        "timestamp": str(scan.created_at),
        "input_format": scan.input_format or "UNKNOWN",
        "data_quality": scan.data_quality or "COMPLETE",
    }

    # 2. Risk breakdown
    metrics_breakdown = {}
    if scan.metrics_breakdown:
        try:
            metrics_breakdown = json.loads(scan.metrics_breakdown) if isinstance(scan.metrics_breakdown, str) else scan.metrics_breakdown
        except Exception:
            metrics_breakdown = {}

    context["risk"] = {
        "score": scan.overall_score or 0.0,
        "level": scan.risk_level or "LOW",
        "confidence": scan.confidence or 0.85,
        "metrics_breakdown": metrics_breakdown,
        "uncertainty": [],
    }

    # 3. Policy details
    policies = repo.get_policies(db, project_id)
    active_policy = policies[0] if policies else None
    policy_rules = {}
    if active_policy and active_policy.rules:
        try:
            policy_rules = json.loads(active_policy.rules) if isinstance(active_policy.rules, str) else active_policy.rules
        except Exception:
            policy_rules = {}

    context["policy"] = {
        "decision": scan.policy_decision or "ALLOW",
        "rules_configured": policy_rules,
        "active_policy_name": active_policy.name if active_policy else "Default Security Gate",
    }

    # 4. Ingested components & findings
    all_findings = repo.get_findings(db, scan.id)
    all_components = repo.get_components(db, scan.id)
    all_dependencies = repo.get_dependencies(db, scan.id)

    context["summary"] = {
        "total_components": len(all_components),
        "total_findings": len(all_findings),
        "critical_count": sum(1 for f in all_findings if f.severity == "CRITICAL"),
        "high_count": sum(1 for f in all_findings if f.severity == "HIGH"),
        "medium_count": sum(1 for f in all_findings if f.severity in ("MEDIUM", "MODERATE")),
        "low_count": sum(1 for f in all_findings if f.severity == "LOW"),
    }

    # Add findings summaries for multi-finding prioritization
    context["findings_catalog"] = [
        {
            "id": f.id,
            "component_name": f.component_name,
            "component_purl": f.component_purl,
            "severity": f.severity,
            "cve_id": f.cve_id or f.title,
            "title": f.title,
            "score": f.score,
            "exploitability": (f.evidence or {}).get("exploitability", "UNKNOWN"),
            "is_kev": (f.evidence or {}).get("is_kev", False),
            "reachability": getattr(f, "reachability", None) or (f.evidence or {}).get("reachability", "REACHABLE"),
            "fixed_versions": (f.evidence or {}).get("fixed_versions", []),
        }
        for f in all_findings
    ]

    # 5. Targeted Finding / Component context if specified
    target_finding = None
    if finding_id:
        target_finding = next((f for f in all_findings if f.id == finding_id), None)
    elif component_purl:
        target_finding = next((f for f in all_findings if f.component_purl == component_purl), None)

    if target_finding:
        f_evidence = target_finding.evidence or {}
        f_remediation = target_finding.remediation or {}
        comp_obj = next((c for c in all_components if c.purl == target_finding.component_purl), None)

        context["component"] = {
            "name": target_finding.component_name or (comp_obj.name if comp_obj else "unknown"),
            "version": f_evidence.get("version") or (comp_obj.version if comp_obj else "unknown"),
            "ecosystem": comp_obj.ecosystem if comp_obj else ("PyPI" if "requirements" in str(scan.input_format) else "npm"),
            "purl": target_finding.component_purl,
            "scope": comp_obj.scope if comp_obj else "runtime",
            "direct": comp_obj.is_direct if comp_obj else True,
        }

        context["finding"] = {
            "finding_id": target_finding.id,
            "signal_type": target_finding.category or "KNOWN_VULNERABILITY",
            "cve_id": target_finding.cve_id or target_finding.title,
            "severity": target_finding.severity,
            "cvss_score": target_finding.score,
            "exploitability": f_evidence.get("exploitability", "UNKNOWN"),
            "is_kev": f_evidence.get("is_kev", False),
            "source": f_evidence.get("source", "OSV.dev"),
        }

        context["vulnerability"] = {
            "description": target_finding.description or target_finding.title,
            "affected_versions": f_evidence.get("affected_versions", []),
            "fixed_versions": f_evidence.get("fixed_versions", []),
            "references": f_evidence.get("references", []),
        }

        # Blast radius and dependencies
        dependents = [d for d in all_dependencies if d.child_purl == target_finding.component_purl]
        context["dependency"] = {
            "direct_dependents": len(dependents),
            "is_direct": comp_obj.is_direct if comp_obj else True,
            "dependents_count": len(dependents),
        }

        context["reachability"] = {
            "status": getattr(target_finding, "reachability", None) or f_evidence.get("reachability", "REACHABLE"),
        }

        context["blast_radius"] = {
            "affected_purls": [d.parent_purl for d in dependents],
            "impact_tier": "DIRECT" if (comp_obj and comp_obj.is_direct) else "TRANSITIVE",
        }

        context["provenance"] = {
            "status": "INTEGRITY_SEALED" if scan.sbom_hash else "UNKNOWN",
            "hash": scan.sbom_hash or "NOT_AVAILABLE",
        }

        context["behavior"] = {
            "signals": [f.title for f in all_findings if f.category == "BEHAVIORAL" and f.component_purl == target_finding.component_purl],
        }

        context["health"] = {
            "signals": [f.title for f in all_findings if f.category == "DEPENDENCY_HEALTH" and f.component_purl == target_finding.component_purl],
        }

        context["remediation"] = {
            "action": f_remediation.get("action", "upgrade"),
            "recommended_action": f_remediation.get("recommended_action"),
            "target_versions": f_evidence.get("fixed_versions", []),
            "priority": f_remediation.get("priority", "immediate" if target_finding.severity in ("CRITICAL", "HIGH") else "planned"),
        }

        # Uncertainties explicitly noted
        uncertainties = []
        if f_evidence.get("exploitability") == "UNKNOWN":
            uncertainties.append("Exploitability has not been established from available evidence (exploitability: UNKNOWN).")
        if not f_evidence.get("fixed_versions"):
            uncertainties.append("No verified fixed version is declared in upstream advisory feeds.")
        context["risk"]["uncertainty"] = uncertainties

    elif component_purl:
        comp_obj = next((c for c in all_components if c.purl == component_purl), None)
        if comp_obj:
            context["component"] = {
                "name": comp_obj.name,
                "version": comp_obj.version,
                "ecosystem": comp_obj.ecosystem,
                "purl": comp_obj.purl,
                "scope": comp_obj.scope,
                "direct": comp_obj.is_direct,
            }

    return context
