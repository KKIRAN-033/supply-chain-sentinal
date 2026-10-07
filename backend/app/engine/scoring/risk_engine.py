"""Deterministic risk engine.

The authoritative security decision core.
Combines weighted signals from all analysis engines into a single
risk score with explicit confidence and data quality.

CRITICAL: LLM/AI never determines the final score.
"""
import logging
from collections import defaultdict
from app.core.constants import score_to_risk_level, DataQuality

logger = logging.getLogger(__name__)

# Category weights for final score calculation
CATEGORY_WEIGHTS = {
    "VULNERABILITY": 0.40,
    "BEHAVIORAL": 0.20,
    "TYPOSQUATTING": 0.20,
    "REPUTATION": 0.10,
    "DEPENDENCY_HEALTH": 0.10,
}


def calculate_risk(
    findings: list[dict],
    blast_radius: dict = None,
) -> dict:
    """Calculate deterministic risk score from processed findings.
    
    Returns:
        {
            "risk_score": float,
            "risk_level": str,
            "confidence": float,
            "data_quality": str,
            "risk_factors": list,
            "metrics_breakdown": dict,
            "vulnerable_count": int,
            "suspicious_count": int,
            "outdated_count": int,
        }
    """
    if not findings:
        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "confidence": 0.5,
            "data_quality": DataQuality.MINIMAL.value,
            "risk_factors": [],
            "metrics_breakdown": {cat: 0 for cat in CATEGORY_WEIGHTS},
            "vulnerable_count": 0,
            "suspicious_count": 0,
            "outdated_count": 0,
        }

    # Group findings by category
    by_category: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_category[f.get("category", "UNKNOWN")].append(f)

    # Calculate per-category scores (max score per category)
    category_scores = {}
    for category, weight in CATEGORY_WEIGHTS.items():
        cat_findings = by_category.get(category, [])
        if cat_findings:
            # Use weighted combination: max score dominates, with contribution from count
            max_score = max(f.get("score", 0) for f in cat_findings)
            count_factor = min(len(cat_findings) * 5, 20)  # More findings = more risk, capped
            category_scores[category] = min(max_score + count_factor, 100)
        else:
            category_scores[category] = 0

    # Calculate weighted risk score
    risk_score = sum(
        category_scores.get(cat, 0) * weight
        for cat, weight in CATEGORY_WEIGHTS.items()
    )

    # Apply blast radius boost
    if blast_radius and blast_radius.get("total_affected_components", 0) > 3:
        blast_boost = min(blast_radius["total_affected_components"] * 2, 15)
        risk_score = min(risk_score + blast_boost, 100)

    risk_score = round(risk_score, 1)

    # Calculate confidence (based on data quality signals)
    confidences = [f.get("confidence", 0.5) for f in findings]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5

    # Data quality assessment
    has_vuln_data = len(by_category.get("VULNERABILITY", [])) > 0 or True  # We always check
    has_behavioral = len(by_category.get("BEHAVIORAL", [])) >= 0
    has_health = len(by_category.get("DEPENDENCY_HEALTH", [])) >= 0
    source_diversity = len(set(
        f.get("evidence", {}).get("source", "") for f in findings if f.get("evidence")
    ))

    if source_diversity >= 2 and avg_confidence > 0.7:
        data_quality = DataQuality.COMPLETE.value
    elif avg_confidence > 0.5:
        data_quality = DataQuality.PARTIAL.value
    else:
        data_quality = DataQuality.MINIMAL.value

    # Build risk factors
    risk_factors = []
    for f in sorted(findings, key=lambda x: x.get("score", 0), reverse=True)[:5]:
        risk_factors.append({
            "category": f.get("category"),
            "component": f.get("component_name"),
            "severity": f.get("severity"),
            "score_contribution": f.get("score", 0),
            "title": f.get("title"),
        })

    # Count categories
    vuln_count = len(by_category.get("VULNERABILITY", []))
    suspicious_count = (
        len(by_category.get("BEHAVIORAL", [])) +
        len(by_category.get("TYPOSQUATTING", [])) +
        len(by_category.get("REPUTATION", []))
    )
    outdated_count = len(by_category.get("DEPENDENCY_HEALTH", []))

    return {
        "risk_score": risk_score,
        "risk_level": score_to_risk_level(risk_score).value,
        "confidence": round(avg_confidence, 2),
        "data_quality": data_quality,
        "risk_factors": risk_factors,
        "metrics_breakdown": {
            "vulnerability": category_scores.get("VULNERABILITY", 0),
            "behavioral": category_scores.get("BEHAVIORAL", 0),
            "typosquatting": category_scores.get("TYPOSQUATTING", 0),
            "reputation": category_scores.get("REPUTATION", 0),
            "health": category_scores.get("DEPENDENCY_HEALTH", 0),
        },
        "vulnerable_count": vuln_count,
        "suspicious_count": suspicious_count,
        "outdated_count": outdated_count,
    }
