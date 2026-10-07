"""Scan orchestrator — the core scan pipeline.

This function is the single entry point for scan execution.
It is deliberately decoupled from FastAPI so it can be moved to
Celery/Redis workers in the future.
"""
import logging
import traceback
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.constants import ScanStatus
from app.core.security import utc_now
from app.db import repositories as repo
from app.engine.parser import detect_format, parse, extract_provenance
from app.engine.normalizer import normalize
from app.engine.dependency_graph import DependencyGraph
from app.engine.intelligence.local import LocalProvider
from app.engine.intelligence.osv import OSVProvider
from app.engine.intelligence.nvd import NVDProvider
from app.engine.intelligence.ghsa import GHSAProvider
from app.engine.rules.vulnerability import analyze_vulnerabilities
from app.engine.rules.behavioral import analyze_behavioral
from app.engine.rules.typosquatting import analyze_typosquatting
from app.engine.rules.reputation import analyze_reputation
from app.engine.rules.health import analyze_health
from app.engine.signal_processor import process_signals
from app.engine.context_engine import apply_context
from app.engine.blast_radius import analyze_blast_radius
from app.engine.scoring.risk_engine import calculate_risk
from app.engine.policy.policy_engine import evaluate_policy
from app.engine.remediation.remediation_engine import generate_remediation

logger = logging.getLogger(__name__)


def run_scan(scan_id: str, raw_content: str, db: Session):
    """Execute the full scan pipeline.
    
    This function is portable — it only needs a scan_id, raw content,
    and a DB session. It does not import FastAPI.
    """
    try:
        scan = repo.get_scan(db, scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        project = repo.get_project(db, scan.project_id)
        environment = project.environment if project else "production"
        criticality = project.criticality if project else "medium"

        # ── STAGE 1: Parsing ──
        _update_status(db, scan_id, ScanStatus.PARSING)
        fmt = detect_format(raw_content, scan.input_format or "auto")
        if fmt.value in ("unknown", "unknown_json"):
            _fail_scan(db, scan_id, "UNSUPPORTED_FORMAT", "Unsupported input format: schema not recognized")
            return
        if fmt.value == "malformed_json":
            _fail_scan(db, scan_id, "INVALID_SBOM", "Malformed JSON syntax in input file")
            return

        try:
            components = parse(raw_content, fmt)
        except Exception as e:
            _fail_scan(db, scan_id, "INVALID_SBOM", f"Parse error: {str(e)}")
            return

        if not components:
            _fail_scan(db, scan_id, "INVALID_SBOM", "No components found in input")
            return

        provenance = extract_provenance(raw_content, fmt)
        repo.update_scan(
            db, scan_id,
            input_format=fmt.value,
            spec_version=provenance.get("spec_version"),
            serial_number=provenance.get("serial_number"),
            provenance=provenance,
        )

        # ── STAGE 2: Normalization ──
        _update_status(db, scan_id, ScanStatus.NORMALIZING)
        components = normalize(components, scan.input_ecosystem or "")

        # Persist components
        repo.save_components(db, scan_id, [c.to_db_dict() for c in components])
        repo.update_scan(db, scan_id, total_components=len(components))

        # ── STAGE 3: Dependency Graph ──
        _update_status(db, scan_id, ScanStatus.BUILDING_GRAPH)
        dep_graph = DependencyGraph()
        dep_graph.build_from_components(components)
        edges = dep_graph.get_all_edges()
        if edges:
            repo.save_dependencies(db, scan_id, edges)

        # ── STAGE 4: Intelligence Enrichment (Live Threat Intelligence) ──
        _update_status(db, scan_id, ScanStatus.ENRICHING)
        # Include local deterministic intelligence without network bottlenecks
        providers = [LocalProvider()]
        try:
            osv = OSVProvider()
            if osv.is_available():
                providers.append(osv)
        except Exception as e:
            logger.warning(f"OSV provider unavailable: {e}")
        try:
            nvd = NVDProvider()
            if nvd.is_available():
                providers.append(nvd)
        except Exception as e:
            logger.warning(f"NVD provider unavailable: {e}")
        try:
            ghsa = GHSAProvider()
            if ghsa.is_available():
                providers.append(ghsa)
        except Exception as e:
            logger.warning(f"GHSA provider unavailable: {e}")

        # ── STAGE 5: Security Analysis ──
        _update_status(db, scan_id, ScanStatus.ANALYZING)
        all_findings = []

        # Vulnerability engine
        vuln_findings = analyze_vulnerabilities(components, providers)
        all_findings.extend(vuln_findings)

        # Behavioral engine
        behavioral_findings = analyze_behavioral(components)
        all_findings.extend(behavioral_findings)

        # Typosquatting engine
        typo_findings = analyze_typosquatting(components)
        all_findings.extend(typo_findings)

        # Reputation engine
        rep_findings = analyze_reputation(components)
        all_findings.extend(rep_findings)

        # Health engine
        health_findings = analyze_health(components)
        all_findings.extend(health_findings)

        # ── STAGE 6: Signal Processing ──
        processed_findings = process_signals(all_findings)

        # ── STAGE 7: Context ──
        contextual_findings = apply_context(processed_findings, environment, criticality)

        # ── STAGE 8: Blast Radius ──
        blast_radius = analyze_blast_radius(contextual_findings, dep_graph)

        # ── STAGE 9: Remediation ──
        contextual_findings = generate_remediation(contextual_findings)

        # ── STAGE 10: Risk Scoring ──
        _update_status(db, scan_id, ScanStatus.SCORING)
        risk_result = calculate_risk(contextual_findings, blast_radius)

        # ── STAGE 11: Policy ──
        _update_status(db, scan_id, ScanStatus.APPLYING_POLICY)
        policies = repo.get_policies(db, scan.project_id)
        custom_rules = policies[0].rules if policies else None
        policy_result = evaluate_policy(
            risk_result["risk_level"],
            risk_result["risk_score"],
            environment,
            custom_rules,
        )

        # ── STAGE 12: Persist Results ──
        repo.save_findings(db, scan_id, contextual_findings)

        repo.update_scan(db, scan_id,
            status=ScanStatus.COMPLETED.value,
            overall_score=risk_result["risk_score"],
            risk_level=risk_result["risk_level"],
            confidence=risk_result["confidence"],
            data_quality=risk_result["data_quality"],
            policy_decision=policy_result["decision"],
            vulnerable_count=risk_result["vulnerable_count"],
            suspicious_count=risk_result["suspicious_count"],
            outdated_count=risk_result["outdated_count"],
            metrics_breakdown=risk_result["metrics_breakdown"],
            completed_at=utc_now(),
        )

        # Save risk history
        severity_counts = _count_severities(contextual_findings)
        repo.save_risk_history(
            db, scan.project_id, scan_id,
            score=risk_result["risk_score"],
            risk_level=risk_result["risk_level"],
            confidence=risk_result["confidence"],
            total_findings=len(contextual_findings),
            critical_count=severity_counts.get("CRITICAL", 0),
            high_count=severity_counts.get("HIGH", 0),
            medium_count=severity_counts.get("MEDIUM", 0),
            low_count=severity_counts.get("LOW", 0),
        )

        # Audit log
        repo.save_audit_event(db, "scan_completed", "scan", scan_id, {
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "findings_count": len(contextual_findings),
            "policy_decision": policy_result["decision"],
        })

        logger.info(
            f"Scan {scan_id} completed: score={risk_result['risk_score']}, "
            f"level={risk_result['risk_level']}, "
            f"decision={policy_result['decision']}, "
            f"findings={len(contextual_findings)}"
        )

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}\n{traceback.format_exc()}")
        _fail_scan(db, scan_id, "SCAN_ERROR", str(e))


def _update_status(db: Session, scan_id: str, status: ScanStatus):
    """Update scan status."""
    repo.update_scan(db, scan_id, status=status.value)
    logger.info(f"Scan {scan_id} -> {status.value}")


def _fail_scan(db: Session, scan_id: str, error_code: str, message: str):
    """Mark scan as failed with structured error."""
    repo.update_scan(db, scan_id,
        status=ScanStatus.FAILED.value,
        error_code=error_code,
        error_message=message,
        completed_at=utc_now(),
    )
    repo.save_audit_event(db, "scan_failed", "scan", scan_id, {
        "error_code": error_code,
        "error_message": message,
    })
    logger.error(f"Scan {scan_id} FAILED: [{error_code}] {message}")


def _count_severities(findings: list[dict]) -> dict:
    """Count findings by severity."""
    counts = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
