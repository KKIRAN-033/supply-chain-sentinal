"""Dependency health analysis engine.

Detects unpinned versions, wildcard ranges, and dependency hygiene concerns.
"""
import logging
from app.schemas.components import CanonicalComponent

logger = logging.getLogger(__name__)


def analyze_health(components: list[CanonicalComponent]) -> list[dict]:
    """Analyze dependency health/hygiene."""
    findings = []

    for comp in components:
        if comp.scope == "root" or comp.name in ("project-root", "app", ""):
            continue

        issues = []

        # Check pinning
        if comp.is_pinned is False:
            issues.append("unpinned_version")
        elif comp.is_pinned is None and not comp.version:
            issues.append("no_version_specified")

        # Check wildcard
        if comp.version in ("*", "latest"):
            issues.append("wildcard_version")

        if issues:
            severity = "MEDIUM" if "unpinned_version" in issues else "LOW"
            score = 25 + len(issues) * 10

            findings.append({
                "component_purl": comp.purl,
                "component_name": comp.name,
                "category": "DEPENDENCY_HEALTH",
                "severity": severity,
                "score": min(score, 60),
                "confidence": 0.9,
                "title": f"Dependency health concern: {comp.name}",
                "description": f"Found {len(issues)} health issue(s): {', '.join(issues)}",
                "cve_id": None,
                "evidence": {
                    "signal_type": "DEPENDENCY_HEALTH",
                    "component": comp.name,
                    "version": comp.version,
                    "is_pinned": comp.is_pinned,
                    "issues": issues,
                    "source": "health_analysis",
                    "confidence": 0.9,
                },
                "remediation": {
                    "action": "configuration_fix",
                    "reason": "Pin dependency versions for reproducible builds",
                    "verification": "Ensure all dependencies use exact version specifiers",
                },
            })

    return findings
