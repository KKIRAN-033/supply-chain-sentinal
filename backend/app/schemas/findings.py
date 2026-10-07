"""Finding schemas."""
from typing import Optional
from pydantic import BaseModel


class FindingResponse(BaseModel):
    id: str
    component_purl: str
    component_name: Optional[str] = None
    category: str
    severity: str
    score: float = 0.0
    confidence: float = 1.0
    title: Optional[str] = None
    description: Optional[str] = None
    cve_id: Optional[str] = None
    evidence: Optional[dict] = None
    remediation: Optional[dict] = None
    is_suppressed: bool = False
