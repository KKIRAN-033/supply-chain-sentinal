"""Local vulnerability intelligence provider.

Always available. Uses deterministic fixtures loaded from data/cve_fixtures.json.
"""
import json
import logging
import os
from pathlib import Path

from app.engine.intelligence.base import VulnerabilityProvider, VulnerabilityRecord
from app.core.config import settings

logger = logging.getLogger(__name__)


class LocalProvider(VulnerabilityProvider):
    """Local CVE fixture-based intelligence. Always available, no network required."""

    def __init__(self):
        self._db: dict = {}
        self._load_fixtures()

    @property
    def provider_name(self) -> str:
        return "local"

    def _load_fixtures(self):
        fixture_path = settings.DATA_DIR / "cve_fixtures.json"
        try:
            if fixture_path.exists():
                with open(fixture_path, "r") as f:
                    data = json.load(f)
                # Index by "ecosystem/name" for fast lookup
                for entry in data.get("vulnerabilities", []):
                    key = f"{entry.get('ecosystem', '').lower()}/{entry.get('package', '').lower()}"
                    if key not in self._db:
                        self._db[key] = []
                    self._db[key].append(entry)
                logger.info(f"Local intelligence loaded: {len(self._db)} packages, {sum(len(v) for v in self._db.values())} vulnerabilities")
            else:
                logger.warning(f"CVE fixtures not found at {fixture_path}")
        except Exception as e:
            logger.error(f"Failed to load CVE fixtures: {e}")

    def get_vulnerabilities(self, ecosystem: str, name: str, version: str) -> list[VulnerabilityRecord]:
        key = f"{ecosystem.lower()}/{name.lower()}"
        entries = self._db.get(key, [])
        results = []
        for entry in entries:
            # Check version match
            affected = entry.get("affected_versions", [])
            if affected and version:
                if not self._version_affected(version, affected):
                    continue
            results.append(VulnerabilityRecord(
                cve_id=entry.get("cve_id", ""),
                title=entry.get("title", ""),
                description=entry.get("description", ""),
                severity=entry.get("severity", "UNKNOWN"),
                cvss_score=entry.get("cvss_score"),
                affected_versions=affected,
                fixed_versions=entry.get("fixed_versions", []),
                references=entry.get("references", []),
                source="local",
                is_kev=entry.get("is_kev", False),
                exploitability=entry.get("exploitability", "UNKNOWN"),
            ))
        return results

    def _version_affected(self, version: str, affected_ranges: list[str]) -> bool:
        """Version-in-range check. Supports exact match, <, <=, >, >= and bounded ranges separated by comma."""
        if not affected_ranges:
            return True
        for aff in affected_ranges:
            aff = aff.strip()
            if not aff:
                continue
            if aff == version or aff == "*":
                return True
            
            # Check bounded range, e.g., ">= 4.0.0, < 4.19.2"
            conditions = [c.strip() for c in aff.split(",")]
            all_conditions_met = True
            for cond in conditions:
                try:
                    if cond.startswith("<="):
                        if self._compare_versions(version, cond[2:].strip()) > 0:
                            all_conditions_met = False
                            break
                    elif cond.startswith("<"):
                        if self._compare_versions(version, cond[1:].strip()) >= 0:
                            all_conditions_met = False
                            break
                    elif cond.startswith(">="):
                        if self._compare_versions(version, cond[2:].strip()) < 0:
                            all_conditions_met = False
                            break
                    elif cond.startswith(">"):
                        if self._compare_versions(version, cond[1:].strip()) <= 0:
                            all_conditions_met = False
                            break
                    elif cond == version:
                        pass
                    else:
                        if not any(cond.startswith(op) for op in ['<', '>', '=']):
                            if self._compare_versions(version, cond) != 0:
                                all_conditions_met = False
                                break
                except Exception:
                    all_conditions_met = False
                    break
            
            if all_conditions_met:
                return True
                
        return False

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Simple numeric version comparison. Strips non-digits from parts."""
        def extract_parts(v):
            parts = []
            for x in v.split("."):
                num_str = "".join(c for c in x if c.isdigit())
                if num_str:
                    parts.append(int(num_str))
                else:
                    parts.append(0)
            return parts

        parts1 = extract_parts(v1)
        parts2 = extract_parts(v2)
        for a, b in zip(parts1, parts2):
            if a < b:
                return -1
            if a > b:
                return 1
        return len(parts1) - len(parts2)

    def is_available(self) -> bool:
        return True

