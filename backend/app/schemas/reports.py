"""Report schemas."""
from typing import Optional
from pydantic import BaseModel
from app.schemas.scans import ScanSummary, MetricsBreakdown
from app.schemas.findings import FindingResponse


class ScanReport(BaseModel):
    scan_id: str
    project_id: str
    summary: ScanSummary
    metrics_breakdown: MetricsBreakdown
    policy_decision: Optional[str] = None
    findings: list[FindingResponse] = []
    blast_radius: Optional[dict] = None
    explanation: Optional[str] = None
