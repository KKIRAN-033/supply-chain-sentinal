"""Signal processor: normalizes, deduplicates, and correlates findings from all engines."""
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


def process_signals(all_findings: list[dict]) -> list[dict]:
    """Process raw findings into correlated, deduplicated signals.
    
    - Deduplicates by (component_purl, category, cve_id)
    - Sorts by score descending
    - Caps confidence at 1.0
    """
    seen = set()
    processed = []

    for finding in all_findings:
        dedup_key = (
            finding.get("component_purl", ""),
            finding.get("category", ""),
            finding.get("cve_id", ""),
            finding.get("title", ""),
        )
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # Normalize confidence
        finding["confidence"] = min(float(finding.get("confidence", 1.0)), 1.0)
        finding["score"] = min(float(finding.get("score", 0)), 100.0)

        processed.append(finding)

    # Sort by score descending
    processed.sort(key=lambda f: f.get("score", 0), reverse=True)

    logger.info(f"Signal processor: {len(all_findings)} raw -> {len(processed)} deduplicated findings")
    return processed
