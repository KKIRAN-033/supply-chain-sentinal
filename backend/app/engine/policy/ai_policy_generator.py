"""AI Policy Generator.

Synthesizes tailored, context-aware supply chain security policies
for a project based on its environment, criticality, tech stack,
and risk profile.
"""
import logging
import httpx
from typing import Optional, Dict, Any, List
from app.core.config import settings

logger = logging.getLogger(__name__)


def generate_ai_policy_for_project(
    project_name: str,
    environment: str = "production",
    criticality: str = "critical",
    repo_url: Optional[str] = None,
    detected_ecosystems: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Generate an AI-tailored security policy specification for a project."""
    env = (environment or "production").lower()
    crit = (criticality or "medium").lower()
    ecosystems = [e.lower() for e in (detected_ecosystems or [])]

    # 1. Base Decision Matrix Formulation based on Criticality & Environment
    rules = {
        "CRITICAL": "BLOCK",
        "HIGH": "REVIEW",
        "MEDIUM": "ALLOW",
        "LOW": "ALLOW",
    }

    if crit == "critical":
        if env == "production":
            rules = {"CRITICAL": "BLOCK", "HIGH": "BLOCK", "MEDIUM": "REVIEW", "LOW": "ALLOW"}
            max_cvss = 6.0
            sla_days = {"CRITICAL": 1, "HIGH": 7, "MEDIUM": 30, "LOW": 90}
        elif env == "staging":
            rules = {"CRITICAL": "BLOCK", "HIGH": "REVIEW", "MEDIUM": "REVIEW", "LOW": "ALLOW"}
            max_cvss = 7.0
            sla_days = {"CRITICAL": 2, "HIGH": 14, "MEDIUM": 45, "LOW": 120}
        else: # development
            rules = {"CRITICAL": "REVIEW", "HIGH": "REVIEW", "MEDIUM": "ALLOW", "LOW": "ALLOW"}
            max_cvss = 8.0
            sla_days = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 60, "LOW": 180}
    elif crit == "high":
        if env == "production":
            rules = {"CRITICAL": "BLOCK", "HIGH": "REVIEW", "MEDIUM": "REVIEW", "LOW": "ALLOW"}
            max_cvss = 7.0
            sla_days = {"CRITICAL": 2, "HIGH": 14, "MEDIUM": 45, "LOW": 120}
        elif env == "staging":
            rules = {"CRITICAL": "BLOCK", "HIGH": "REVIEW", "MEDIUM": "ALLOW", "LOW": "ALLOW"}
            max_cvss = 7.5
            sla_days = {"CRITICAL": 3, "HIGH": 21, "MEDIUM": 60, "LOW": 150}
        else:
            rules = {"CRITICAL": "REVIEW", "HIGH": "ALLOW", "MEDIUM": "ALLOW", "LOW": "ALLOW"}
            max_cvss = 8.5
            sla_days = {"CRITICAL": 14, "HIGH": 45, "MEDIUM": 90, "LOW": 180}
    elif crit == "medium":
        if env == "production":
            rules = {"CRITICAL": "BLOCK", "HIGH": "REVIEW", "MEDIUM": "ALLOW", "LOW": "ALLOW"}
            max_cvss = 7.5
            sla_days = {"CRITICAL": 3, "HIGH": 21, "MEDIUM": 60, "LOW": 150}
        elif env == "staging":
            rules = {"CRITICAL": "REVIEW", "HIGH": "REVIEW", "MEDIUM": "ALLOW", "LOW": "ALLOW"}
            max_cvss = 8.0
            sla_days = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180}
        else:
            rules = {"CRITICAL": "REVIEW", "HIGH": "ALLOW", "MEDIUM": "ALLOW", "LOW": "ALLOW"}
            max_cvss = 9.0
            sla_days = {"CRITICAL": 30, "HIGH": 60, "MEDIUM": 120, "LOW": 360}
    else: # low criticality
        if env == "production":
            rules = {"CRITICAL": "REVIEW", "HIGH": "ALLOW", "MEDIUM": "ALLOW", "LOW": "ALLOW"}
            max_cvss = 8.5
            sla_days = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180}
        else:
            rules = {"CRITICAL": "ALLOW", "HIGH": "ALLOW", "MEDIUM": "ALLOW", "LOW": "ALLOW"}
            max_cvss = 9.5
            sla_days = {"CRITICAL": 30, "HIGH": 90, "MEDIUM": 180, "LOW": 360}

    # 2. Ecosystem Specific Guardrails
    guardrails = [
        "Immediate BLOCK on packages present in CISA Known Exploited Vulnerabilities (KEV) catalog",
        "BLOCK any package flagged for typosquatting, dependency confusion, or name spoofing",
        "Require lockfile verification (sha512 / cryptographic hash integrity) in deployment pipelines",
    ]

    has_npm = any(e in ["npm", "javascript", "typescript", "node"] for e in ecosystems) or "package.json" in str(ecosystems)
    has_python = any(e in ["pypi", "python", "pip"] for e in ecosystems) or "requirements" in str(ecosystems)

    if has_npm or not ecosystems:
        guardrails.append("NPM Security Guard: Enforce strict check on prototype pollution gadgets and cross-site script leakages")
        guardrails.append("Strict block on packages with unverified maintainer turnover in the last 14 days")

    if has_python or not ecosystems:
        guardrails.append("PyPI Security Guard: Disallow unpinned wildcard versions in production requirements")
        guardrails.append("Block packages containing unverified post-install setup.py execution hooks")

    # 3. Compliance & Licenses
    compliance = [
        "NIST SP 800-218 (Secure Software Development Framework)",
        "OpenSSF Best Practices Scorecard",
        "SLSA Level 2 (Supply-chain Levels for Software Artifacts)",
    ]

    allowed_licenses = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Python-2.0"]

    # 4. Formulate AI Rationale (Deterministic Grounded Base)
    rationale_paragraphs = [
        f"**Project Profile Analysis**: Project **{project_name}** is designated as **{crit.upper()}** criticality running in a **{env.upper()}** environment.",
        f"**Risk Posture Rationale**: In a {env} tier, supply-chain vulnerabilities directly compromise user data, runtime integrity, and brand reputation. "
        f"Because criticality is rated as {crit}, the policy sets an automated gate: "
        f"**CRITICAL** issues are set to **{rules['CRITICAL']}**, and **HIGH** severity findings are mapped to **{rules['HIGH']}**. "
        f"Any package exceeding a CVSS base score of **{max_cvss}** will trigger automated build gating.",
    ]

    if ecosystems:
        rationale_paragraphs.append(
            f"**Stack-Specific Protections**: Detected active ecosystems ({', '.join(ecosystems).upper()}). "
            f"AI guards have injected targeted protections against transitive lockfile tampering and malicious lifecycle scripts."
        )

    ai_rationale = "\n\n".join(rationale_paragraphs)

    # 5. Optional LLM Enrichment (if enabled and key present)
    ai_model = "Supply-Chain Sentinel AI Synthesizer"
    if settings.ENABLE_LLM and settings.DEEPSEEK_API_KEY:
        try:
            prompt = (
                f"You are a principal application security architect. Write a 3-sentence executive security policy rationale "
                f"for project '{project_name}' (Criticality: {crit}, Environment: {env}, Ecosystems: {ecosystems}). "
                f"Explain why blocking critical CVEs and enforcing lockfile integrity is non-negotiable for this tier."
            )
            with httpx.Client(timeout=4.0) as client:
                resp = client.post(
                    settings.DEEPSEEK_API_URL,
                    headers={
                        "Authorization": f"Bearer {settings.DEEPSEEK_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": settings.DEEPSEEK_MODEL,
                        "messages": [
                            {"role": "system", "content": "You are a concise security architect."},
                            {"role": "user", "content": prompt}
                        ],
                        "stream": False,
                    }
                )
                if resp.status_code == 200:
                    llm_text = resp.json()["choices"][0]["message"]["content"].strip()
                    if llm_text:
                        ai_rationale += f"\n\n**AI Security Architect Note**: {llm_text}"
                        ai_model = f"DeepSeek {settings.DEEPSEEK_MODEL}"
        except Exception as e:
            logger.warning(f"LLM enrichment skipped: {e}")

    # Assemble complete policy dictionary
    policy_name = f"AI Tailored Security Policy — {project_name}"
    
    full_rules = {
        **rules,
        "ai_generated": True,
        "ai_model": ai_model,
        "ai_rationale": ai_rationale,
        "criticality": crit,
        "environment": env,
        "max_cvss": max_cvss,
        "sla_days": sla_days,
        "guardrails": guardrails,
        "allowed_licenses": allowed_licenses,
        "compliance": compliance,
    }

    return {
        "name": policy_name,
        "environment": env,
        "rules": full_rules,
    }
