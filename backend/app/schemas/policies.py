"""Policy schemas."""
from typing import Optional
from pydantic import BaseModel


class PolicyCreateRequest(BaseModel):
    name: str
    environment: str = "production"
    rules: dict = {}


class PolicyResponse(BaseModel):
    id: str
    project_id: str
    name: str
    environment: str
    rules: dict
    is_active: bool
