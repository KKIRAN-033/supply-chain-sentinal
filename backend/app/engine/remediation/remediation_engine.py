"""Remediation engine.

Generates structured remediation guidance for each finding.
"""
import logging

logger = logging.getLogger(__name__)


def generate_remediation(findings: list[dict]) -> list[dict]:
    """Enrich findings with detailed remediation guidance.
    
    Findings already have basic remediation from analysis engines.
    This engine adds more detailed, actionable guidance.
    """
    for finding in findings:
        existing = finding.get("remediation", {})
        if not existing:
            existing = {}

        category = finding.get("category", "")
        severity = finding.get("severity", "")
        evidence = finding.get("evidence", {})

        # Enhance remediation based on category
        if category == "VULNERABILITY":
            fixed = evidence.get("fixed_versions", [])
            if fixed:
                existing["recommended_action"] = f"Upgrade to version {fixed[0]} or later"
                existing["target_version"] = fixed[0]
            else:
                existing["recommended_action"] = "Check for available patches or consider alternatives"
            existing["priority"] = "immediate" if severity in ("CRITICAL", "HIGH") else "planned"
            existing["verification"] = "Re-scan after updating to confirm vulnerability is resolved"

        elif category == "BEHAVIORAL":
            existing["recommended_action"] = "Review install scripts for suspicious behavior"
            existing["priority"] = "immediate" if severity == "HIGH" else "soon"

        elif category == "TYPOSQUATTING":
            similar_to = evidence.get("similar_to", "")
            existing["recommended_action"] = f"Verify package identity. Did you mean '{similar_to}'?"
            existing["priority"] = "immediate"

        elif category == "REPUTATION":
            existing["recommended_action"] = "Replace with a trusted, maintained alternative"
            existing["priority"] = "immediate" if severity == "CRITICAL" else "planned"

        elif category == "DEPENDENCY_HEALTH":
            existing["recommended_action"] = "Pin dependency versions for reproducible builds"
            existing["priority"] = "planned"

        finding["remediation"] = existing

    return findings
