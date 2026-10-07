"""Behavioral analysis engine.

Static detection of suspicious patterns in package install scripts
and manifest metadata. Never executes arbitrary code.
"""
import re
import logging
from app.schemas.components import CanonicalComponent
from app.core.constants import SUSPICIOUS_PATTERNS

logger = logging.getLogger(__name__)


def analyze_behavioral(components: list[CanonicalComponent]) -> list[dict]:
    """Detect suspicious behavioral patterns in components."""
    findings = []

    for comp in components:
        matched_patterns = []

        # Check install scripts
        for script in comp.install_scripts:
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, script, re.IGNORECASE):
                    matched_patterns.append({
                        "pattern": pattern,
                        "context": script[:200],
                        "location": "install_script",
                    })

        if matched_patterns:
            severity = "HIGH" if len(matched_patterns) >= 3 else "MEDIUM"
            score = min(90, 40 + len(matched_patterns) * 15)

            findings.append({
                "component_purl": comp.purl,
                "component_name": comp.name,
                "category": "BEHAVIORAL",
                "severity": severity,
                "score": score,
                "confidence": 0.7,
                "title": f"Suspicious behavior detected in {comp.name}",
                "description": f"Found {len(matched_patterns)} suspicious pattern(s) in install scripts",
                "cve_id": None,
                "evidence": {
                    "signal_type": "SUSPICIOUS_BEHAVIOR",
                    "component": comp.name,
                    "patterns_matched": len(matched_patterns),
                    "details": matched_patterns[:10],  # Cap evidence size
                    "source": "static_analysis",
                    "confidence": 0.7,
                },
                "remediation": {
                    "action": "review",
                    "reason": "Package contains suspicious install-time behavior",
                    "verification": "Manually review the install scripts before using this package",
                },
            })

    return findings
