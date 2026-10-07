"""GitHub Advisory Database (GHSA) intelligence provider.

Enriches components with GitHub security advisories.
Fails safely without breaking the scan orchestrator.
"""
import logging
import httpx
from typing import Optional

from app.engine.intelligence.base import VulnerabilityProvider, VulnerabilityRecord
from app.core.config import settings

logger = logging.getLogger(__name__)


class GHSAProvider(VulnerabilityProvider):
    """GitHub Advisory Database provider via OSV GHSA query."""

    def __init__(self, api_url: str = "https://api.osv.dev/v1/query", timeout: float = 2.0):
        self.api_url = api_url
        self.timeout = timeout
        self.enabled = getattr(settings, "ENABLE_GHSA", False)

    @property
    def provider_name(self) -> str:
        return "ghsa"

    def is_available(self) -> bool:
        if not self.enabled:
            return False
        try:
            with httpx.Client(timeout=1.0) as client:
                r = client.post(self.api_url, json={"package": {"name": "test", "ecosystem": "npm"}})
                return r.status_code == 200
        except Exception:
            return False

    def get_vulnerabilities(self, ecosystem: str, name: str, version: str) -> list[VulnerabilityRecord]:
        """Query GHSA advisories for component."""
        if not self.enabled:
            return []

        eco_map = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go"}
        osv_eco = eco_map.get(ecosystem.lower(), ecosystem)

        payload = {"package": {"name": name, "ecosystem": osv_eco}}
        if version:
            payload["version"] = version

        records = []
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(self.api_url, json=payload)
                if resp.status_code != 200:
                    return []
                data = resp.json()

            for vuln in data.get("vulns", []):
                vid = vuln.get("id", "")
                # Prioritize GHSA IDs
                if not vid.startswith("GHSA-") and not any(a.startswith("GHSA-") for a in vuln.get("aliases", [])):
                    continue

                ghsa_id = vid if vid.startswith("GHSA-") else next(a for a in vuln.get("aliases", []) if a.startswith("GHSA-"))
                cve_id = next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), ghsa_id)

                summary = vuln.get("summary", "")
                details = vuln.get("details", "")

                severity = "UNKNOWN"
                cvss_score = None
                for s in vuln.get("severity", []):
                    if s.get("type") in ("CVSS_V3", "CVSS_V4"):
                        severity = "HIGH"

                records.append(VulnerabilityRecord(
                    cve_id=cve_id,
                    title=f"GHSA: {summary or ghsa_id}",
                    description=details[:300] if details else summary,
                    severity=severity,
                    cvss_score=cvss_score,
                    affected_versions=[version] if version else [],
                    fixed_versions=[],
                    references=[ref.get("url", "") for ref in vuln.get("references", [])][:3],
                    source="ghsa",
                    is_kev=False,
                    exploitability="HIGH" if severity in ("CRITICAL", "HIGH") else "MEDIUM",
                ))

        except httpx.TimeoutException:
            logger.warning(f"GHSA provider timed out for {name}@{version} (> {self.timeout}s)")
        except Exception as e:
            logger.warning(f"GHSA provider error for {name}@{version}: {e}")

        return records
