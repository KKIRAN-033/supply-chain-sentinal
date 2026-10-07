"""Context engine: applies environmental and dependency context to findings."""
import logging

logger = logging.getLogger(__name__)

# Context multipliers for risk prioritization
ENVIRONMENT_MULTIPLIERS = {
    "production": 1.0,
    "staging": 0.7,
    "development": 0.4,
}

SCOPE_MULTIPLIERS = {
    "runtime": 1.0,
    "development": 0.5,
}

CRITICALITY_MULTIPLIERS = {
    "critical": 1.2,
    "high": 1.0,
    "medium": 0.8,
    "low": 0.6,
}


def apply_context(
    findings: list[dict],
    environment: str = "production",
    criticality: str = "medium",
) -> list[dict]:
    """Apply context-based score adjustments to findings.
    
    Context modifies prioritization — a dev-only vulnerability in a
    low-criticality staging app should not rank the same as a production
    runtime CRITICAL.
    """
    env_mult = ENVIRONMENT_MULTIPLIERS.get(environment.lower(), 1.0)
    crit_mult = CRITICALITY_MULTIPLIERS.get(criticality.lower(), 1.0)

    for finding in findings:
        original_score = finding.get("score", 0)
        evidence = finding.get("evidence", {})

        # Scope multiplier
        scope = "runtime"  # Default assumption
        scope_mult = SCOPE_MULTIPLIERS.get(scope, 1.0)

        # Apply context
        contextual_score = original_score * env_mult * crit_mult * scope_mult
        finding["score"] = min(round(contextual_score, 1), 100.0)

        # Record context in evidence
        if evidence:
            evidence["context"] = {
                "environment": environment,
                "criticality": criticality,
                "env_multiplier": env_mult,
                "criticality_multiplier": crit_mult,
                "original_score": original_score,
            }

    logger.info(f"Context applied: env={environment}, criticality={criticality}")
    return findings
