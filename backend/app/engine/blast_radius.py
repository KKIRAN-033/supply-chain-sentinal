"""Blast radius analysis.

For each vulnerable component, calculates the scope of impact
through the dependency graph.
"""
import logging
from app.engine.dependency_graph import DependencyGraph

logger = logging.getLogger(__name__)


def analyze_blast_radius(
    findings: list[dict],
    dep_graph: DependencyGraph,
) -> dict:
    """Calculate blast radius for all vulnerable components.
    
    Returns a dict mapping component PURLs to their blast radius info.
    """
    blast_radius = {}
    vulnerable_purls = set()

    for finding in findings:
        purl = finding.get("component_purl", "")
        if purl and finding.get("category") == "VULNERABILITY":
            vulnerable_purls.add(purl)

    for purl in vulnerable_purls:
        radius = dep_graph.get_blast_radius(purl)
        blast_radius[purl] = radius

        # Attach blast radius to relevant findings
        for finding in findings:
            if finding.get("component_purl") == purl:
                evidence = finding.get("evidence", {})
                evidence["blast_radius"] = radius

    total_affected = len(set().union(
        *(set(br.get("affected_purls", [])) for br in blast_radius.values())
    )) if blast_radius else 0

    summary = {
        "vulnerable_components": len(vulnerable_purls),
        "total_affected_components": total_affected,
        "per_component": blast_radius,
    }

    logger.info(f"Blast radius: {len(vulnerable_purls)} vulnerable -> {total_affected} affected")
    return summary
