"""Comprehensive Tests for AI Security Analyst & Remediation Assistant.

Validates:
1. Deterministic authority & zero hallucinations (AI never invents versions or alters scores).
2. Ecosystem-specific remediation commands (pip vs npm).
3. PyMongo regression test (unfixed CVE handled safely with status PENDING RE-SCAN).
4. All finding categories (Vulnerability, Behavioral, Typosquatting, Health).
5. Multi-finding prioritization ("What should I fix first?").
6. Policy explanation & build block decisions.
7. Suggested questions API and audit log recording.
"""
import sys
import os
import pytest
from starlette.testclient import TestClient

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from app.engine.ai.providers import get_ai_provider, DeterministicAnalystProvider
from app.engine.ai.analyst import AISecurityAnalyst

SecurityContext = dict


# ==============================================================================
# UNIT TESTS: AI Providers & Analyst Invariants
# ==============================================================================

def test_ai_provider_fallback_to_deterministic(monkeypatch):
    """Verify that when local LLM is offline, system safely falls back to DeterministicAnalystProvider."""
    from app.engine.ai.providers import OllamaProvider
    monkeypatch.setattr(OllamaProvider, "is_available", lambda self: False)
    provider = get_ai_provider()
    assert isinstance(provider, DeterministicAnalystProvider)
    assert provider.name == "deterministic-security-analyst"


def test_multi_finding_prioritization_ranking():
    """Verify AI Security Analyst correctly prioritizes the most severe/impactful finding."""
    ctx = SecurityContext(
        project={"id": "prj_test", "name": "Test Service", "environment": "production", "criticality": "high"},
        scan={"id": "scn_test", "input_format": "requirements_txt", "data_quality": "COMPLETE"},
        risk={
            "overall_score": 75.5,
            "risk_level": "HIGH",
            "confidence": 0.90,
            "metrics_breakdown": {"vulnerability": 60, "behavioral": 15.5},
        },
        policy_decision="BLOCK",
        findings=[
            {
                "id": "fnd_med",
                "component_name": "urllib3",
                "severity": "MEDIUM",
                "score": 30.0,
                "cvss_score": 30.0,
                "title": "Moderate Denial of Service in urllib3",
                "cve_id": "CVE-2023-45803",
            },
            {
                "id": "fnd_crit",
                "component_name": "python-jose",
                "severity": "CRITICAL",
                "score": 95.0,
                "cvss_score": 95.0,
                "title": "Remote Algorithm Confusion in python-jose",
                "cve_id": "CVE-2024-33663",
                "is_kev": True,
            },
            {
                "id": "fnd_high",
                "component_name": "uvicorn",
                "severity": "HIGH",
                "score": 70.0,
                "cvss_score": 70.0,
                "title": "HTTP Response Splitting in uvicorn",
                "cve_id": "CVE-2020-7695",
            },
        ],
        components=[
            {"name": "python-jose", "version": "3.3.0", "purl": "pkg:pypi/python-jose@3.3.0"},
            {"name": "uvicorn", "version": "0.11.8", "purl": "pkg:pypi/uvicorn@0.11.8"},
            {"name": "urllib3", "version": "1.26.5", "purl": "pkg:pypi/urllib3@1.26.5"},
        ],
        summary={"total_components": 3, "total_findings": 3, "critical_count": 1, "high_count": 1},
    )

    analyst = AISecurityAnalyst()
    res = analyst.analyze(ctx, question="What should I fix first?", mode="prioritize")

    # Invariant: Must return all 15 structured schema keys
    expected_keys = [
        "answer", "what_happened", "why_it_matters", "evidence", "risk_impact",
        "recommended_solution", "compatibility_risks", "tests", "verification",
        "uncertainty", "next_action", "confidence", "provider", "status_label",
        "verification_status"
    ]
    for key in expected_keys:
        assert key in res, f"Missing key '{key}' in AI analyst response"

    # Must prioritize python-jose (CRITICAL, score 95.0)
    assert "python-jose" in res["answer"]
    assert res["status_label"] == "DETERMINISTIC RESULT + AI REMEDIATION GUIDANCE"
    assert res["verification_status"] == "PENDING RE-SCAN"
    assert res["risk_impact"]["score"] == 75.5


def test_pymongo_regression_and_fixed_version_integrity():
    """Verify PyMongo regression: When upstream feed has no fixed version, AI does NOT invent one."""
    ctx = SecurityContext(
        project={"id": "prj_py", "name": "PyApp", "environment": "production"},
        scan={"id": "scn_py", "input_format": "requirements_txt"},
        risk={"overall_score": 50.0, "risk_level": "MEDIUM", "metrics_breakdown": {"vulnerability": 50.0}},
        policy_decision="REVIEW",
        finding={
            "id": "fnd_pymongo",
            "component_name": "pymongo",
            "severity": "HIGH",
            "score": 85.0,
            "cvss_score": 85.0,
            "title": "Heap out-of-bounds write via signed size overflow in BSON document encoder",
            "cve_id": "CVE-2026-96749",
            "exploitability": "UNKNOWN",
            "evidence": {
                "version": "4.8.0",
                "affected_versions": ["<=4.8.0"],
                "fixed_versions": [],  # NO verified fixed version declared
            },
        },
        component={"name": "pymongo", "version": "4.8.0", "purl": "pkg:pypi/pymongo@4.8.0"},
        vulnerability={
            "id": "CVE-2026-96749",
            "fixed_versions": [],  # Empty
            "description": "Integer overflow in BSON document encoding",
        },
    )

    analyst = AISecurityAnalyst()
    res = analyst.analyze(ctx, question="How do I fix this pymongo vulnerability?", mode="remediate")

    sol = res["recommended_solution"]
    # Invariant: AI must NOT hallucinate or invent a fixed version
    assert sol["target_version"] is None
    assert sol["action"] == "investigate_mitigation"
    assert sol["commands"] == []  # No premature pip install command
    assert "No verified fixed version is declared" in sol["steps"][0]

    # Invariant: Status label and verification
    assert res["status_label"] == "DETERMINISTIC RESULT + AI REMEDIATION GUIDANCE"
    assert res["verification_status"] == "PENDING RE-SCAN"
    assert "No verified fixed version is available" in res["uncertainty"][1]


def test_npm_ecosystem_remediation_commands():
    """Verify npm projects emit npm commands and package.json manifest targets."""
    ctx = SecurityContext(
        project={"id": "prj_node", "name": "NodeApp", "environment": "production"},
        scan={"id": "scn_node", "input_format": "package_json"},
        risk={"overall_score": 35.0, "risk_level": "LOW", "metrics_breakdown": {"vulnerability": 35.0}},
        policy_decision="ALLOW",
        finding={
            "id": "fnd_express",
            "component_name": "express",
            "severity": "HIGH",
            "score": 75.0,
            "cvss_score": 75.0,
            "title": "Prototype Pollution in Express",
            "cve_id": "CVE-2024-9999",
            "evidence": {"version": "4.18.0", "fixed_versions": ["4.19.2"]},
        },
        component={"name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"},
        vulnerability={
            "id": "CVE-2024-9999",
            "fixed_versions": ["4.19.2"],
            "description": "Prototype Pollution in Express body parser",
        },
    )

    analyst = AISecurityAnalyst()
    res = analyst.analyze(ctx, question="How do I upgrade express?", mode="remediate")

    sol = res["recommended_solution"]
    assert sol["target_version"] == "4.19.2"
    assert sol["action"] == "upgrade"
    assert "package.json" in sol["files"]
    assert "package-lock.json" in sol["files"]
    # Invariant: Must use npm syntax, NOT pip
    assert sol["commands"] == ["npm install express@4.19.2"]


def test_behavioral_and_typosquatting_categories():
    """Verify non-CVE findings (behavioral, typosquatting) have category-aware explanations."""
    # 1. Typosquatting
    typo_ctx = SecurityContext(
        project={"id": "prj_1", "name": "Web", "environment": "staging"},
        scan={"id": "scn_1", "input_format": "package_json"},
        risk={"overall_score": 25.0, "risk_level": "LOW", "metrics_breakdown": {"typosquatting": 25.0}},
        policy_decision="ALLOW",
        finding={
            "id": "fnd_typo",
            "component_name": "lodsh",
            "category": "TYPOSQUATTING",
            "severity": "HIGH",
            "score": 70.0,
            "cvss_score": 70.0,
            "title": "Typosquatting detected: lodsh mimics lodash",
        },
        component={"name": "lodsh", "version": "1.0.0", "purl": "pkg:npm/lodsh@1.0.0"},
    )
    analyst = AISecurityAnalyst()
    res_typo = analyst.analyze(typo_ctx, mode="explain")
    assert "typosquatting" in res_typo["why_it_matters"].lower()

    # 2. Behavioral
    behav_ctx = SecurityContext(
        project={"id": "prj_2", "name": "Backend", "environment": "production"},
        scan={"id": "scn_2", "input_format": "package_json"},
        risk={"overall_score": 80.0, "risk_level": "HIGH", "metrics_breakdown": {"behavioral": 80.0}},
        policy_decision="BLOCK",
        finding={
            "id": "fnd_behav",
            "component_name": "malicious-pkg",
            "category": "BEHAVIORAL",
            "severity": "CRITICAL",
            "score": 90.0,
            "cvss_score": 90.0,
            "title": "Suspicious install script opens outbound socket",
        },
        component={"name": "malicious-pkg", "version": "1.0.0", "purl": "pkg:npm/malicious-pkg@1.0.0"},
    )
    res_behav = analyst.analyze(behav_ctx, mode="explain")
    assert "install-time scripts" in res_behav["why_it_matters"].lower()


def test_policy_build_block_explanation():
    """Verify AI answers 'Why was the build blocked?' using deterministic policy evaluations."""
    ctx = SecurityContext(
        project={"id": "prj_pol", "name": "Core Banking", "environment": "production", "criticality": "high"},
        scan={"id": "scn_pol", "input_format": "package_json"},
        risk={"overall_score": 88.0, "risk_level": "CRITICAL", "metrics_breakdown": {"vulnerability": 88.0}},
        policy_decision="BLOCK",
        summary={"total_components": 20, "critical_count": 2, "high_count": 4},
    )

    analyst = AISecurityAnalyst()
    res = analyst.analyze(ctx, question="Why was the build blocked?", mode="policy")

    assert "BLOCK was triggered" in res["answer"]
    assert "2 CRITICAL" in res["answer"]
    assert res["status_label"] == "DETERMINISTIC RESULT + AI REMEDIATION GUIDANCE"
    assert res["verification_status"] == "PENDING RE-SCAN"
    assert "remediate_policy_violations" in res["recommended_solution"]["action"]


# ==============================================================================
# INTEGRATION TESTS: HTTP API Endpoints
# ==============================================================================

def test_api_suggested_questions_endpoint():
    """Verify /api/v1/ai/suggested-questions returns contextual questions."""
    client = TestClient(app)

    # First fetch an existing project ID from the DB
    prjs_res = client.get("/api/v1/projects")
    assert prjs_res.status_code == 200
    prjs = prjs_res.json()
    if not prjs:
        pytest.skip("No projects available in database for API test")

    project_id = prjs[0]["id"]

    # 1. Project-level questions
    res = client.get(f"/api/v1/ai/suggested-questions?project_id={project_id}")
    assert res.status_code == 200
    questions = res.json()
    assert isinstance(questions, list)
    assert len(questions) >= 5
    ids = [q["id"] for q in questions]
    assert "why_score" in ids
    assert "what_first" in ids

    # 2. Finding-level questions
    res_fnd = client.get(f"/api/v1/ai/suggested-questions?project_id={project_id}&finding_id=fnd_fake")
    assert res_fnd.status_code == 200
    f_questions = res_fnd.json()
    f_ids = [q["id"] for q in f_questions]
    assert "explain" in f_ids
    assert "solution" in f_ids
    assert "safe_upgrade" in f_ids


def test_api_analyze_endpoint_and_audit_logging():
    """Verify POST /api/v1/ai/analyze returns grounded result and creates audit event."""
    client = TestClient(app)

    prjs_res = client.get("/api/v1/projects")
    prjs = prjs_res.json()
    if not prjs:
        pytest.skip("No projects available in database for API test")

    project_id = prjs[0]["id"]

    payload = {
        "project_id": project_id,
        "question": "What is the primary risk driver in this project?",
        "mode": "risk",
    }

    res = client.post("/api/v1/ai/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert "answer" in data
    assert "recommended_solution" in data
    assert data["status_label"] == "DETERMINISTIC RESULT + AI REMEDIATION GUIDANCE"
    assert data["verification_status"] == "PENDING RE-SCAN"

    # Verify audit log was recorded
    audit_res = client.get("/api/v1/audit-logs?limit=5")
    assert audit_res.status_code == 200
    logs = audit_res.json()
    ai_actions = [log for log in logs if log["action"] == "ai_analyst_consulted"]
    assert len(ai_actions) > 0, "Expected ai_analyst_consulted audit log entry"
