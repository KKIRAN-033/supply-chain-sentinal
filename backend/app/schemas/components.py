"""Canonical component schema — the PURL-first normalized representation."""
from pydantic import BaseModel, Field
from typing import Optional


class CanonicalComponent(BaseModel):
    """The single internal representation every parser must produce."""
    component_id: str = ""
    name: str
    version: str = ""
    ecosystem: str = ""
    purl: str = ""
    scope: str = "runtime"
    is_direct: bool = True
    is_pinned: Optional[bool] = None
    install_scripts: list[str] = Field(default_factory=list)
    licenses: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)

    def to_db_dict(self) -> dict:
        """Convert to dictionary suitable for repository save."""
        return {
            "purl": self.purl,
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "scope": self.scope,
            "is_direct": self.is_direct,
            "is_pinned": self.is_pinned,
            "licenses": self.licenses,
            "install_scripts": self.install_scripts,
        }
