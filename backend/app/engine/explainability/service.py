"""Explainability Service.

Provides evidence-grounded risk explainability and remediation synthesis.
Combines deterministic structured analysis with optional LLM narrative generation.

CRITICAL ARCHITECTURE INVARIANT:
The LLM/AI NEVER determines risk scores, severities, or policy decisions.
It only produces descriptive explanations based on deterministic evidence.
"""
import logging
import httpx
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


class ExplainabilityService:
    """Service generating explainability narratives for scans."""

    @staticmethod
    def generate_explanation(scan_report: dict) -> dict:
        """Synthesize explainability from canonical scan report data.
        
        Always produces deterministic explanation. Enriches with Ollama if enabled and reachable.
        """
        summary = scan_report.get("summary", {})
        findings = scan_report.get("findings", [])
        metrics = scan_report.get("metrics_breakdown", {})
        policy = scan_report.get("policy_decision", "ALLOW")

        score = summary.get("overall_score", 0.0)
        level = summary.get("risk_level", "LOW")
        confidence = summary.get("confidence", 0.5)
        quality = summary.get("data_quality", "UNKNOWN")

        # 1. Deterministic evidence analysis
        top_category = max(metrics.items(), key=lambda kv: kv[1])[0] if metrics else "none"
        critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")

        # Build grounded narrative
        lines = []
        lines.append(f"Scan evaluated an overall risk score of {score}/100 resulting in a {level} risk classification.")
        if critical_count > 0 or high_count > 0:
            lines.append(f"Identified {critical_count} critical and {high_count} high-severity risk factors primarily driven by {top_category.capitalize()} signals.")
        else:
            lines.append(f"No critical or high severity vulnerabilities detected across ingested components.")

        if policy == "BLOCK":
            lines.append("Deployment blocked by organizational security policy due to exceeding acceptable risk thresholds.")
        elif policy == "REVIEW":
            lines.append("Security team manual review requested before promoting to production.")
        else:
            lines.append("Security policy evaluation resulted in ALLOW.")

        deterministic_summary = " ".join(lines)

        # 2. Key recommended actions
        recommendations = []
        for f in findings[:3]:
            rem = f.get("remediation", {})
            action = rem.get("recommended_action") or rem.get("action")
            if action:
                recommendations.append(f"{f.get('component_name', 'Component')}: {action}")

        result = {
            "deterministic_summary": deterministic_summary,
            "primary_risk_driver": top_category,
            "confidence_assessment": f"{int(confidence * 100)}% confidence ({quality} data quality)",
            "policy_impact": f"Policy decision: {policy}",
            "recommendations": recommendations,
            "llm_summary": None,
            "llm_status": "disabled" if not settings.ENABLE_LLM else "offline",
        }

        # 3. Optional LLM narrative (strictly non-authoritative)
        if settings.ENABLE_LLM:
            try:
                if not settings.DEEPSEEK_API_KEY:
                    logger.warning("DEEPSEEK_API_KEY is not set. Cannot fetch explanation.")
                    result["llm_status"] = "offline"
                    return result

                prompt = (
                    f"You are a security explainability assistant. Summarize this deterministic security evidence in 2 sentences. "
                    f"DO NOT invent facts or change numbers. "
                    f"Score: {score}/100 ({level}). Primary driver: {top_category}. Policy: {policy}. Critical issues: {critical_count}."
                )
                payload = {
                    "model": settings.DEEPSEEK_MODEL,
                    "messages": [
                        {"role": "system", "content": "You are a helpful security assistant."},
                        {"role": "user", "content": prompt}
                    ],
                    "stream": False,
                }
                headers = {
                    "Authorization": f"Bearer {settings.DEEPSEEK_API_KEY}",
                    "Content-Type": "application/json"
                }
                with httpx.Client(timeout=5.0) as client:
                    resp = client.post(settings.DEEPSEEK_API_URL, json=payload, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        llm_resp = data.get("choices", [])[0].get("message", {}).get("content", "").strip() if data.get("choices") else ""
                        if llm_resp:
                            result["llm_summary"] = llm_resp
                            result["llm_status"] = "online"
                    else:
                        logger.error(f"DeepSeek API error: {resp.status_code} {resp.text}")
                        result["llm_status"] = "unavailable"
            except Exception as e:
                logger.error(f"DeepSeek unavailable or timed out: {e}")
                result["llm_status"] = "unavailable"

        return result
