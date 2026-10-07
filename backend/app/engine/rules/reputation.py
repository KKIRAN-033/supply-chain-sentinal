"""Reputation analysis engine.

Checks packages against known reputation data.
Unknown reputation ≠ malicious — it means UNKNOWN.
"""
import json
import logging
from pathlib import Path

from app.schemas.components import CanonicalComponent
from app.core.config import settings

logger = logging.getLogger(__name__)


def _load_reputation_db() -> dict:
    path = settings.DATA_DIR / "reputation.json"
    try:
        if path.exists():
            with open(path, "r") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load reputation data: {e}")
    return {}


def analyze_reputation(components: list[CanonicalComponent]) -> list[dict]:
    """Check component reputation. Only flags known-bad packages."""
    reputation_db = _load_reputation_db()
    findings = []

    for comp in components:
        key = f"{comp.ecosystem.lower()}/{comp.name.lower()}"
        rep = reputation_db.get(key)

        if rep and rep.get("status") in ("malicious", "suspicious", "deprecated"):
            severity = "CRITICAL" if rep["status"] == "malicious" else "MEDIUM"
            score = 95 if rep["status"] == "malicious" else 45

            findings.append({
                "component_purl": comp.purl,
                "component_name": comp.name,
                "category": "REPUTATION",
                "severity": severity,
                "score": score,
                "confidence": rep.get("confidence", 0.8),
                "title": f"Reputation concern: {comp.name} ({rep['status']})",
                "description": rep.get("reason", f"Package has {rep['status']} reputation status"),
                "cve_id": None,
                "evidence": {
                    "signal_type": "REPUTATION",
                    "component": comp.name,
                    "status": rep["status"],
                    "reason": rep.get("reason", ""),
                    "source": "reputation_db",
                    "confidence": rep.get("confidence", 0.8),
                },
                "remediation": {
                    "action": "remove" if rep["status"] == "malicious" else "review",
                    "reason": rep.get("reason", "Package reputation concern"),
                    "verification": "Find an alternative maintained package",
                },
            })

    return findings
