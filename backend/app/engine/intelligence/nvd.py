"""NVD vulnerability intelligence provider.

Queries the National Vulnerability Database (NVD) API v2 or local cache.
Gracefully degrades upon timeout or network failure.
"""
import logging
import httpx
from typing import Optional

from app.engine.intelligence.base import VulnerabilityProvider, VulnerabilityRecord
from app.core.config import settings

logger = logging.getLogger(__name__)


class NVDProvider(VulnerabilityProvider):
    """NVD API v2 vulnerability provider."""

    def __init__(self, api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0", timeout: float = 2.0):
        self.api_url = api_url
        self.timeout = timeout
        self.enabled = getattr(settings, "ENABLE_NVD", False)

    @property
    def provider_name(self) -> str:
        return "nvd"

    def is_available(self) -> bool:
        if not self.enabled:
            return False
        try:
            with httpx.Client(timeout=1.0) as client:
                r = client.head(self.api_url)
                return r.status_code < 500
        except Exception:
            return False

    def get_vulnerabilities(self, ecosystem: str, name: str, version: str) -> list[VulnerabilityRecord]:
        """Query NVD for vulnerabilities. Never raises an unhandled exception."""
        if not self.enabled:
            return []

        records = []
        try:
            # Query by keyword
            keyword = f"{name} {version}".strip()
            params = {"keywordSearch": keyword, "resultsPerPage": 5}
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(self.api_url, params=params)
                if resp.status_code != 200:
                    logger.warning(f"NVD query returned HTTP {resp.status_code} for {name}")
                    return []
                data = resp.json()

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc_text = descriptions[0].get("value", "") if descriptions else ""

                # Extract CVSS
                cvss_score = None
                severity = "UNKNOWN"
                metrics = cve.get("metrics", {})
                for cvss_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if cvss_key in metrics and metrics[cvss_key]:
                        metric_data = metrics[cvss_key][0].get("cvssData", {})
                        cvss_score = metric_data.get("baseScore")
                        severity = metric_data.get("baseSeverity", "UNKNOWN").upper()
                        break

                records.append(VulnerabilityRecord(
                    cve_id=cve_id,
                    title=f"NVD: {cve_id} in {name}",
                    description=desc_text,
                    severity=severity,
                    cvss_score=cvss_score,
                    affected_versions=[version] if version else [],
                    fixed_versions=[],
                    references=[ref.get("url", "") for ref in cve.get("references", [])][:3],
                    source="nvd",
                    is_kev=False,
                    exploitability="UNKNOWN",
                ))

        except httpx.TimeoutException:
            logger.warning(f"NVD provider timed out for {name}@{version} (> {self.timeout}s)")
        except Exception as e:
            logger.warning(f"NVD provider error for {name}@{version}: {e}")

        return records
