"""Unified AI Security Analyst & Remediation Assistant.

Analyzes ground-truth SecurityContext and produces authoritative, evidence-grounded
remediation guidance and answers without hallucination.
"""
import json
import logging
from typing import Dict, Any, List, Optional

from app.engine.ai.providers import get_ai_provider, AIProvider

logger = logging.getLogger(__name__)


class AISecurityAnalyst:
    """Unified AI Security Analyst engine."""

    def __init__(self, provider: Optional[AIProvider] = None):
        self.provider = provider or get_ai_provider()

    def analyze(self, context: Dict[str, Any], question: Optional[str] = None, mode: str = "auto") -> Dict[str, Any]:
        """Perform unified security analysis given structured SecurityContext and optional question."""
        question_lower = (question or "").lower().strip()

        # Try LLM provider if it's an online LLM (e.g. Ollama)
        if self.provider and self.provider.is_available() and self.provider.name != "deterministic-security-analyst":
            try:
                llm_response = self._invoke_llm(context, question, mode)
                if llm_response:
                    return self._validate_and_sanitize(llm_response, context)
            except Exception as e:
                logger.warning(f"LLM generation failed: {e}. Falling back to deterministic analyst.")

        # Authoritative deterministic analyst fallback
        return self._deterministic_analyze(context, question_lower, mode)

    def _invoke_llm(self, context: Dict[str, Any], question: Optional[str], mode: str) -> Optional[Dict[str, Any]]:
        """Construct prompt and invoke external LLM."""
        system_prompt = (
            "You are the Supply-Chain Sentinel AI Security Analyst. "
            "You MUST base all answers strictly on the provided JSON SecurityContext. "
            "NEVER invent CVEs, package versions, exploits, or graph relationships. "
            "NEVER recalculate or modify risk scores or severities. "
            "If fixed_versions is empty, state 'No verified fixed version is available in the current intelligence data.' "
            "Return valid JSON matching the required schema."
        )

        user_prompt = f"""
SecurityContext:
{json.dumps(context, indent=2)}

User Question / Mode:
{question or f"Provide comprehensive security analysis and remediation plan (mode: {mode})."}

Return valid JSON with keys:
answer, what_happened, why_it_matters, evidence, risk_impact (score, level, contributors),
recommended_solution (action, target_version, files, commands, steps),
compatibility_risks, tests, verification, uncertainty, next_action, confidence.
"""
        raw = self.provider.generate(user_prompt, system_prompt)
        if raw:
            try:
                # Strip markdown code blocks if wrapped
                cleaned = raw.strip()
                if cleaned.startswith("```json"):
                    cleaned = cleaned[7:]
                if cleaned.startswith("```"):
                    cleaned = cleaned[3:]
                if cleaned.endswith("```"):
                    cleaned = cleaned[:-3]
                return json.loads(cleaned.strip())
            except Exception as e:
                logger.error(f"Failed to parse LLM JSON: {e}")
        return None

    def _validate_and_sanitize(self, response: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure LLM did not alter authoritative backend scores or invent versions."""
        # Force authoritative score and level from context
        risk_ctx = context.get("risk", {})
        response["risk_impact"] = {
            "score": risk_ctx.get("score", 0.0),
            "level": risk_ctx.get("level", "LOW"),
            "contributors": response.get("risk_impact", {}).get("contributors", []),
        }

        # Validate target version against verified versions
        sol = response.get("recommended_solution", {})
        fixed_versions = context.get("vulnerability", {}).get("fixed_versions", [])
        if not fixed_versions and sol.get("target_version"):
            sol["target_version"] = None
            sol["steps"].append("No verified fixed version exists in upstream intelligence.")
            response["answer"] += " (Note: No verified fixed version is available in current intelligence feeds)."

        response["provider"] = self.provider.name
        response["verification_status"] = "PENDING RE-SCAN"
        return response

    def _deterministic_analyze(self, context: Dict[str, Any], question_lower: str, mode: str) -> Dict[str, Any]:
        """Produce mathematically grounded, evidence-first security analysis."""
        project = context.get("project", {})
        scan = context.get("scan", {})
        risk = context.get("risk", {})
        policy = context.get("policy", {})
        finding = context.get("finding")
        component = context.get("component")
        vuln = context.get("vulnerability", {})
        remediation = context.get("remediation", {})
        summary = context.get("summary", {})
        catalog = context.get("findings_catalog") or context.get("findings", [])

        score = risk.get("score") or risk.get("overall_score", 0.0)
        level = risk.get("level") or risk.get("risk_level", "LOW")
        decision = (policy.get("decision") if isinstance(policy, dict) else None) or context.get("policy_decision") or "ALLOW"
        ecosystem = component.get("ecosystem", "npm" if "package_json" in scan.get("input_format", "") else "PyPI") if component else "PyPI"

        # -------------------------------------------------------------
        # CASE 1: PRIORITIZATION ("What should I fix first?")
        # -------------------------------------------------------------
        if "first" in question_lower or "priorit" in question_lower or mode == "prioritize":
            ranked = sorted(
                catalog,
                key=lambda x: (
                    1 if x.get("is_kev") else 0,
                    1 if x.get("severity") == "CRITICAL" else (0.8 if x.get("severity") == "HIGH" else 0.5),
                    float(x.get("score") or 0.0),
                ),
                reverse=True,
            )

            steps = []
            for idx, r in enumerate(ranked[:3], 1):
                fixed = r.get("fixed_versions") or []
                action = f"Upgrade to ≥ {fixed[0]}" if fixed else "Investigate mitigation or alternative"
                steps.append(f"Priority {idx}: {r.get('component_name')} ({r.get('severity')}) — {r.get('cve_id')}: {action}")

            first_fixed = (ranked[0].get("fixed_versions") or [None])[0] if ranked else None
            first_cmd = f"{'pip install' if ecosystem.lower() == 'pypi' else 'npm install'} {ranked[0].get('component_name')}=={first_fixed}" if ranked and first_fixed else "Review advisory patches"

            return {
                "answer": f"Based on deterministic risk contributions and severity, prioritize fixing {len(ranked)} active finding(s). The top priority is {ranked[0].get('component_name') if ranked else 'None'}.",
                "what_happened": f"Identified {summary.get('critical_count', 0)} critical, {summary.get('high_count', 0)} high, and {summary.get('medium_count', 0)} medium findings.",
                "why_it_matters": "Fixing the highest-ranked issue eliminates the greatest blast radius and provides immediate risk score reduction.",
                "evidence": [f"{r.get('component_name')}@{r.get('severity')} ({r.get('cve_id')})" for r in ranked[:4]],
                "risk_impact": {
                    "score": score,
                    "level": level,
                    "contributors": ["Critical/High severity vulnerabilities dominate overall score calculation."],
                },
                "recommended_solution": {
                    "action": "prioritized_remediation",
                    "target_version": first_fixed,
                    "files": ["requirements.txt" if ecosystem.lower() == "pypi" else "package.json"],
                    "commands": [first_cmd],
                    "steps": steps,
                },
                "compatibility_risks": ["Review breaking release notes between current version and target patch version."],
                "tests": ["Run unit test suite", "Verify integration API endpoints"],
                "verification": ["Re-scan repository manifest to verify finding resolution."],
                "uncertainty": ["Exploitability for unproven CVEs remains UNKNOWN until dynamic telemetry is observed."],
                "next_action": f"Apply fix for {ranked[0].get('component_name') if ranked else 'primary finding'} and trigger re-scan.",
                "confidence": "HIGH",
                "provider": "deterministic-security-analyst",
                "status_label": "DETERMINISTIC RESULT + AI REMEDIATION GUIDANCE",
                "verification_status": "PENDING RE-SCAN",
            }

        # -------------------------------------------------------------
        # CASE 2: POLICY EXPLANATION ("Why was the build blocked?")
        # -------------------------------------------------------------
        if "policy" in question_lower or "block" in question_lower or mode == "policy":
            reason = "Policy evaluated as ALLOW"
            if decision == "BLOCK":
                reason = f"BLOCK was triggered because project '{project.get('name')}' is {project.get('criticality', 'production')} criticality and contains {summary.get('critical_count', 0)} CRITICAL and {summary.get('high_count', 0)} HIGH severity findings exceeding the policy ceiling."
            elif decision == "REVIEW":
                reason = f"REVIEW was triggered because medium/moderate findings or unpinned dependency hygiene concerns require security team sign-off before production promotion."

            return {
                "answer": reason,
                "what_happened": f"Automated CI/CD policy gating returned {decision}.",
                "why_it_matters": "Enforcing automated build gates prevents unverified supply-chain tampering from reaching production infrastructure.",
                "evidence": [
                    f"Policy Decision: {decision}",
                    f"Environment: {project.get('environment')}",
                    f"Criticality: {project.get('criticality')}",
                    f"Active Score: {score} pts ({level})",
                ],
                "risk_impact": {"score": score, "level": level, "contributors": ["Policy threshold violation"]},
                "recommended_solution": {
                    "action": "remediate_policy_violations",
                    "target_version": None,
                    "files": ["package.json" if "package_json" in scan.get("input_format", "") else "requirements.txt"],
                    "commands": ["Run scan diff after resolving blocking findings"],
                    "steps": [
                        "Resolve all CRITICAL and HIGH severity findings",
                        "Verify lockfile cryptographic integrity",
                        "Re-run scan pipeline to clear policy gate",
                    ],
                },
                "compatibility_risks": [],
                "tests": ["Pipeline smoke tests"],
                "verification": ["Run re-scan to confirm policy transition to ALLOW."],
                "uncertainty": [],
                "next_action": "Remediate blocking vulnerabilities to permit deployment pipeline advancement.",
                "confidence": "HIGH",
                "provider": "deterministic-security-analyst",
                "status_label": "DETERMINISTIC RESULT + AI REMEDIATION GUIDANCE",
                "verification_status": "PENDING RE-SCAN",
            }

        # -------------------------------------------------------------
        # CASE 3: SPECIFIC FINDING EXPLANATION OR REMEDIATION
        # -------------------------------------------------------------
        if finding:
            cve_id = finding.get("cve_id", "Security Finding")
            comp_name = component.get("name", "Unknown") if component else finding.get("finding_id")
            comp_ver = component.get("version", "Unknown") if component else "Installed"
            fixed_versions = vuln.get("fixed_versions", [])
            target_version = fixed_versions[0] if fixed_versions else None
            affected = vuln.get("affected_versions", [])

            # Ecosystem command formatting
            cmd = ""
            files = []
            if "pypi" in str(ecosystem).lower() or "python" in str(project.get("language", "")).lower() or "requirements" in str(scan.get("input_format", "")):
                files = ["requirements.txt"]
                cmd = f"pip install {comp_name}=={target_version}" if target_version else f"pip install --upgrade {comp_name}"
            else:
                files = ["package.json", "package-lock.json"]
                cmd = f"npm install {comp_name}@{target_version}" if target_version else f"npm update {comp_name}"

            what = f"{comp_name} {comp_ver} is flagged for {cve_id}: {vuln.get('description', finding.get('title'))}"
            category = finding.get("category", "VULNERABILITY")
            if category == "VULNERABILITY":
                why = f"This vulnerability carries a CVSS/risk score of {finding.get('cvss_score', 0)} ({finding.get('severity')}). If left unpatched, attackers could exploit published vectors against runtime environments."
            elif category == "TYPOSQUATTING":
                why = f"This package is flagged for potential typosquatting ({comp_name}). Installing a lookalike package can lead to malicious code execution or credential theft during build/runtime."
            elif category == "BEHAVIORAL":
                why = f"This package exhibits suspicious install-time scripts or network telemetry. Malicious lifecycle hooks can compromise CI/CD runners or host machines."
            elif category == "DEPENDENCY_HEALTH":
                why = f"This dependency exhibits maintenance, abandonment, or unpinned versioning risks, impacting project supply-chain resilience."
            else:
                why = f"This issue contributes {finding.get('cvss_score', 0)} pts to overall risk and should be evaluated."
            if finding.get("is_kev"):
                why += " WARNING: CISA has cataloged active weaponized exploitation (KEV) in the wild."

            sol_steps = []
            if target_version:
                sol_steps.append(f"Update {comp_name} version specification in {files[0]} from {comp_ver} to {target_version}.")
                sol_steps.append(f"Execute ecosystem installation command: `{cmd}`.")
                sol_steps.append("Commit the updated manifest and regenerate cryptographic lockfile.")
                sol_steps.append("Re-scan the project to verify that the finding transitions to RESOLVED.")
            else:
                sol_steps.append(f"No verified fixed version is declared in current intelligence data for {cve_id}.")
                sol_steps.append("Inspect official vendor security advisories or evaluate dropping/replacing this dependency.")

            uncertainties = []
            if finding.get("exploitability") == "UNKNOWN":
                uncertainties.append("Exploitability has not been established from available evidence (exploitability: UNKNOWN).")
            if not fixed_versions:
                uncertainties.append("No verified fixed version is available in the current intelligence data.")

            return {
                "answer": f"{comp_name} @ {comp_ver} is affected by {cve_id} ({finding.get('severity')} severity). " + (f"A verified fix is available in version {target_version}." if target_version else "No verified fixed version is currently declared."),
                "what_happened": what,
                "why_it_matters": why,
                "evidence": [
                    f"Component PURL: {component.get('purl') if component else finding.get('finding_id')}",
                    f"Installed Version: {comp_ver}",
                    f"Affected Range: {', '.join(affected) if affected else 'All historical releases'}",
                    f"Verified Fixed Version: {target_version if target_version else 'None declared in upstream feed'}",
                    f"Intelligence Feed: {finding.get('source', 'OSV.dev')}",
                ],
                "risk_impact": {
                    "score": score,
                    "level": level,
                    "contributors": [f"{comp_name}: +{finding.get('cvss_score', 0)} pts ({finding.get('severity')})"],
                },
                "recommended_solution": {
                    "action": "upgrade" if target_version else "investigate_mitigation",
                    "target_version": target_version,
                    "files": files,
                    "commands": [cmd] if target_version else [],
                    "steps": sol_steps,
                },
                "compatibility_risks": [
                    f"Validate that upgrading {comp_name} does not introduce breaking API changes with adjacent packages."
                ],
                "tests": [
                    f"Run test suite covering {comp_name} import and runtime callers",
                    "Execute integration tests verifying end-to-end functionality",
                ],
                "verification": [
                    "Run new scan against updated manifest to confirm finding removal.",
                ],
                "uncertainty": uncertainties,
                "next_action": f"Upgrade {comp_name} to {target_version} and re-scan." if target_version else f"Review advisory for {comp_name}.",
                "confidence": "HIGH",
                "provider": "deterministic-security-analyst",
                "status_label": "DETERMINISTIC RESULT + AI REMEDIATION GUIDANCE",
                "verification_status": "PENDING RE-SCAN",
            }

        # -------------------------------------------------------------
        # CASE 4: PROJECT-LEVEL RISK OVERVIEW ("Why is the score high?")
        # -------------------------------------------------------------
        top_cats = risk.get("metrics_breakdown", {})
        top_driver = max(top_cats.items(), key=lambda kv: kv[1])[0] if top_cats else "vulnerabilities"

        return {
            "answer": f"Project '{project.get('name')}' assessed an overall deterministic risk score of {score}/100 resulting in a {level} risk posture. The primary driver is {top_driver}.",
            "what_happened": f"Analysis evaluated {summary.get('total_components', 0)} components and flagged {summary.get('total_findings', 0)} security findings ({summary.get('critical_count', 0)} critical, {summary.get('high_count', 0)} high).",
            "why_it_matters": f"In {project.get('environment', 'production')}, unresolved dependencies expose runtime APIs and lead to automated {decision} policy enforcement.",
            "evidence": [
                f"Deterministic Risk Score: {score}/100 ({level})",
                f"Confidence Index: {int(risk.get('confidence', 0.85) * 100)}%",
                f"Data Quality: {scan.get('data_quality', 'COMPLETE')}",
                f"Total Ingested Dependencies: {summary.get('total_components', 0)}",
            ],
            "risk_impact": {
                "score": score,
                "level": level,
                "contributors": [f"{cat.capitalize()}: {val} pts" for cat, val in top_cats.items() if val > 0],
            },
            "recommended_solution": {
                "action": "execute_remediation_plan",
                "target_version": None,
                "files": ["requirements.txt" if "requirements" in scan.get("input_format", "") else "package.json"],
                "commands": ["sentinel scan verify"],
                "steps": [
                    "Navigate to Remediation Center to review prioritized package upgrade targets.",
                    "Execute non-breaking patch updates in package manifests.",
                    "Run re-scan to verify risk score delta reduction.",
                ],
            },
            "compatibility_risks": ["Perform regression testing following major or minor version increments."],
            "tests": ["Comprehensive test suite execution"],
            "verification": ["Re-scan repository to verify risk score delta reduction."],
            "uncertainty": ["Dynamic behavioral runtime telemetry is NOT OBSERVED in static manifest scans."],
            "next_action": "Open Remediation Center to apply the top prioritized upgrade.",
            "confidence": "HIGH",
            "provider": "deterministic-security-analyst",
            "status_label": "DETERMINISTIC RESULT + AI REMEDIATION GUIDANCE",
            "verification_status": "PENDING RE-SCAN",
        }
