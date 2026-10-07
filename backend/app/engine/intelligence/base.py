"""Base vulnerability provider interface."""
from abc import ABC, abstractmethod
from typing import Optional
from pydantic import BaseModel, Field


class VulnerabilityRecord(BaseModel):
    """Standard vulnerability record across all providers."""
    cve_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    source: str = ""
    is_kev: bool = False  # CISA Known Exploited Vulnerability
    exploitability: str = "UNKNOWN"


class VulnerabilityProvider(ABC):
    """Abstract interface for vulnerability intelligence providers."""

    @abstractmethod
    def get_vulnerabilities(self, ecosystem: str, name: str, version: str) -> list[VulnerabilityRecord]:
        """Query vulnerabilities for a specific package version."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is reachable."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass
