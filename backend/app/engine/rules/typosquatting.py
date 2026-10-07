"""Typosquatting detection engine.

Uses Levenshtein distance against a dictionary of popular/protected packages.
Labels results as "suspicious typosquatting candidate", never "confirmed malicious".
"""
import json
import logging
import os
from pathlib import Path

from app.schemas.components import CanonicalComponent
from app.core.config import settings

logger = logging.getLogger(__name__)

# Try to import Levenshtein; fall back to manual implementation
try:
    from Levenshtein import distance as levenshtein_distance
    HAS_LEVENSHTEIN = True
except ImportError:
    HAS_LEVENSHTEIN = False
    logger.info("python-Levenshtein not installed, using built-in distance")


def _builtin_levenshtein(s1: str, s2: str) -> int:
    """Simple Levenshtein distance for fallback."""
    if len(s1) < len(s2):
        return _builtin_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _distance(s1: str, s2: str) -> int:
    if HAS_LEVENSHTEIN:
        return levenshtein_distance(s1, s2)
    return _builtin_levenshtein(s1, s2)


def _load_protected_packages() -> dict[str, list[str]]:
    """Load protected/popular package dictionary."""
    path = settings.DATA_DIR / "protected_packages.json"
    try:
        if path.exists():
            with open(path, "r") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load protected packages: {e}")
    # Fallback built-in list
    return {
        "npm": [
            "express", "react", "lodash", "axios", "webpack",
            "moment", "jquery", "typescript", "next", "vue",
            "angular", "babel", "eslint", "prettier", "mocha",
            "jest", "chalk", "commander", "inquirer", "debug",
            "underscore", "async", "request", "bluebird", "uuid",
            "vite", "tailwindcss", "postcss", "recharts", "cytoscape", "jsesc",
        ],
        "pypi": [
            "requests", "flask", "django", "numpy", "pandas",
            "scipy", "tensorflow", "torch", "boto3", "pillow",
            "cryptography", "sqlalchemy", "celery", "redis", "pytest",
            "setuptools", "pip", "wheel", "six", "urllib3",
            "pyyaml", "jinja2", "click", "httpx", "fastapi",
        ],
    }


def analyze_typosquatting(components: list[CanonicalComponent]) -> list[dict]:
    """Detect potential typosquatting candidates."""
    protected = _load_protected_packages()
    findings = []

    for comp in components:
        eco_packages = protected.get(comp.ecosystem.lower(), [])
        name_lower = comp.name.lower()

        # Skip if the package IS a protected package
        if name_lower in [p.lower() for p in eco_packages]:
            continue

        for protected_pkg in eco_packages:
            dist = _distance(name_lower, protected_pkg.lower())
            if 0 < dist <= 2 and len(name_lower) > 3:
                severity = "HIGH" if dist == 1 else "MEDIUM"
                score = 80 if dist == 1 else 55

                findings.append({
                    "component_purl": comp.purl,
                    "component_name": comp.name,
                    "category": "TYPOSQUATTING",
                    "severity": severity,
                    "score": score,
                    "confidence": 0.6 if dist == 2 else 0.75,
                    "title": f"Suspicious typosquatting candidate: {comp.name}",
                    "description": (
                        f"Package '{comp.name}' is {dist} edit distance(s) from "
                        f"popular package '{protected_pkg}'. This may indicate typosquatting."
                    ),
                    "cve_id": None,
                    "evidence": {
                        "signal_type": "TYPOSQUATTING_CANDIDATE",
                        "component": comp.name,
                        "similar_to": protected_pkg,
                        "edit_distance": dist,
                        "source": "typosquatting_analysis",
                        "confidence": 0.6 if dist == 2 else 0.75,
                    },
                    "remediation": {
                        "action": "replace",
                        "reason": f"Verify this is not a typosquat of '{protected_pkg}'",
                        "target_version": None,
                        "verification": f"Confirm you intended to use '{comp.name}' and not '{protected_pkg}'",
                    },
                })
                break  # One match per component is enough

    return findings
