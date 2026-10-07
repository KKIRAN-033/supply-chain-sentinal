"""Scan request/response schemas."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ScanCreateRequest(BaseModel):
    input_type: str = "auto"  # cyclonedx, spdx, package_json, requirements_txt, auto
    ecosystem: str = ""
    raw_content: str = ""
    source: str = "upload"


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress: int = 0
    message: str = ""
    created_at: Optional[datetime] = None


class ScanSummary(BaseModel):
    overall_score: Optional[float] = None
    risk_level: Optional[str] = None
    confidence: Optional[float] = None
    data_quality: str = "UNKNOWN"
    total_dependencies: int = 0
    vulnerable_count: int = 0
    suspicious_count: int = 0
    outdated_count: int = 0


class MetricsBreakdown(BaseModel):
    vulnerability: float = 0
    behavioral: float = 0
    typosquatting: float = 0
    health: float = 0
    reputation: float = 0


class ProvenanceMetadata(BaseModel):
    format: Optional[str] = None
    sbom_hash: Optional[str] = None
    spec_version: Optional[str] = None
    serial_number: Optional[str] = None
    tools: list[str] = Field(default_factory=list)
    authors: list[str] = Field(default_factory=list)
    timestamp: Optional[str] = None


class ExplainabilityResponse(BaseModel):
    deterministic_summary: str
    primary_risk_driver: str
    confidence_assessment: str
    policy_impact: str
    recommendations: list[str] = Field(default_factory=list)
    llm_summary: Optional[str] = None
    llm_status: str = "disabled"

