"""OSV.dev vulnerability provider — high-performance concurrent enrichment."""
import logging
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

import httpx
from app.engine.intelligence.base import VulnerabilityProvider, VulnerabilityRecord
from app.core.config import settings

logger = logging.getLogger(__name__)

# Shared high-throughput HTTP client with connection pooling
_client_pool = httpx.Client(
    timeout=httpx.Timeout(timeout=3.5, connect=2.0),
    limits=httpx.Limits(max_keepalive_connections=25, max_connections=50),
)


class OSVProvider(VulnerabilityProvider):
    """High-performance OSV.dev API provider with connection pooling & fast concurrency."""

    @property
    def provider_name(self) -> str:
        return "osv"

    def get_vulnerabilities(self, ecosystem: str, name: str, version: str) -> list[VulnerabilityRecord]:
        if not settings.ENABLE_OSV:
            return []

        eco_map = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go"}
        osv_ecosystem = eco_map.get(ecosystem.lower(), ecosystem)

        payload = {
            "package": {"name": name, "ecosystem": osv_ecosystem},
        }
        if version:
            payload["version"] = version

        try:
            resp = _client_pool.post(f"{settings.OSV_API_URL}/query", json=payload)
            if resp.status_code != 200:
                return []
            data = resp.json()
        except Exception as e:
            logger.debug(f"OSV lookup failed for {name}@{version}: {e}")
            return []

        results = []
        for vuln in data.get("vulns", []):
            severity = "UNKNOWN"
            cvss_score = None
            for s in vuln.get("severity", []):
                if s.get("type") == "CVSS_V3":
                    score_str = s.get("score", "")
                    try:
                        cvss_score = float(score_str) if score_str.replace(".", "").isdigit() else None
                    except ValueError:
                        pass

            # Map aliases to CVE ID
            cve_id = ""
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

            if not cve_id:
                cve_id = vuln.get("id", "")

            # Extract severity from database_specific if available
            db_specific = vuln.get("database_specific", {})
            if "severity" in db_specific:
                severity = str(db_specific["severity"]).upper()
            elif cvss_score:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            results.append(VulnerabilityRecord(
                cve_id=cve_id,
                title=vuln.get("summary", ""),
                description=vuln.get("details", ""),
                severity=severity,
                cvss_score=cvss_score,
                source="osv",
                references=[r.get("url", "") for r in vuln.get("references", [])],
            ))

        return results

    def is_available(self) -> bool:
        return settings.ENABLE_OSV
