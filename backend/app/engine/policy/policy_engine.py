"""Policy engine.

Applies organization policies to risk results.
Risk and policy are separate layers — the policy engine
consumes risk output and produces ALLOW / REVIEW / BLOCK decisions.
"""
import logging
from app.core.constants import PolicyDecision, RiskLevel

logger = logging.getLogger(__name__)

# Default policy thresholds by environment
DEFAULT_POLICIES = {
    "production": {
        "CRITICAL": PolicyDecision.BLOCK,
        "HIGH": PolicyDecision.REVIEW,
        "MEDIUM": PolicyDecision.ALLOW,
        "LOW": PolicyDecision.ALLOW,
    },
    "staging": {
        "CRITICAL": PolicyDecision.REVIEW,
        "HIGH": PolicyDecision.REVIEW,
        "MEDIUM": PolicyDecision.ALLOW,
        "LOW": PolicyDecision.ALLOW,
    },
    "development": {
        "CRITICAL": PolicyDecision.REVIEW,
        "HIGH": PolicyDecision.ALLOW,
        "MEDIUM": PolicyDecision.ALLOW,
        "LOW": PolicyDecision.ALLOW,
    },
}


def evaluate_policy(
    risk_level: str,
    risk_score: float,
    environment: str = "production",
    custom_rules: dict = None,
    exceptions: list[dict] = None,
) -> dict:
    """Evaluate policy against risk result.
    
    Returns:
        {
            "decision": "ALLOW" | "REVIEW" | "BLOCK",
            "reason": str,
            "environment": str,
            "applied_rule": str,
        }
    """
    # Check custom rules first
    if custom_rules:
        policy_map = {}
        for level_str, decision_str in custom_rules.items():
            if not isinstance(decision_str, str):
                continue
            try:
                policy_map[level_str.upper()] = PolicyDecision(decision_str.upper())
            except (ValueError, KeyError, AttributeError):
                continue
        if policy_map and risk_level.upper() in policy_map:
            decision = policy_map[risk_level.upper()]
            return {
                "decision": decision.value,
                "reason": f"Custom policy: {risk_level} → {decision.value}",
                "environment": environment,
                "applied_rule": "custom",
            }

    # Use default policies
    env_policy = DEFAULT_POLICIES.get(environment.lower(), DEFAULT_POLICIES["production"])
    decision = env_policy.get(risk_level.upper(), PolicyDecision.REVIEW)

    return {
        "decision": decision.value,
        "reason": f"Default {environment} policy: {risk_level} → {decision.value}",
        "environment": environment,
        "applied_rule": "default",
    }
