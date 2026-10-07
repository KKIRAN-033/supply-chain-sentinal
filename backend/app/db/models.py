"""SQLAlchemy ORM models for Supply-Chain Sentinel."""
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Text, DateTime, Boolean, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from app.db.base import Base
from app.core.security import utc_now


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=utc_now)

    projects = relationship("Project", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization")


class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    name = Column(String, nullable=False)
    repo_url = Column(String, nullable=True)
    environment = Column(String, default="production")
    criticality = Column(String, default="medium")
    created_at = Column(DateTime, default=utc_now)

    organization = relationship("Organization", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    risk_history = relationship("RiskHistory", back_populates="project", cascade="all, delete-orphan")
    policies = relationship("Policy", back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    status = Column(String, default="PENDING")
    input_format = Column(String, nullable=True)
    input_ecosystem = Column(String, nullable=True)
    source = Column(String, default="upload")
    sbom_hash = Column(String, nullable=True)
    overall_score = Column(Float, nullable=True)
    risk_level = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)
    data_quality = Column(String, default="UNKNOWN")
    policy_decision = Column(String, nullable=True)
    total_components = Column(Integer, default=0)
    vulnerable_count = Column(Integer, default=0)
    suspicious_count = Column(Integer, default=0)
    outdated_count = Column(Integer, default=0)
    error_code = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    spec_version = Column(String, nullable=True)
    serial_number = Column(String, nullable=True)
    provenance = Column(JSON, nullable=True)
    metrics_breakdown = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, nullable=True)

    project = relationship("Project", back_populates="scans")
    components = relationship("Component", back_populates="scan", cascade="all, delete-orphan")
    dependencies = relationship("Dependency", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Component(Base):
    __tablename__ = "components"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    purl = Column(String, nullable=False)
    name = Column(String, nullable=False)
    version = Column(String, nullable=True)
    ecosystem = Column(String, nullable=True)
    scope = Column(String, default="runtime")
    is_direct = Column(Boolean, default=True)
    is_pinned = Column(Boolean, nullable=True)
    licenses = Column(JSON, default=list)
    install_scripts = Column(JSON, default=list)

    scan = relationship("Scan", back_populates="components")


class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    parent_purl = Column(String, nullable=False)
    child_purl = Column(String, nullable=False)

    scan = relationship("Scan", back_populates="dependencies")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    component_purl = Column(String, nullable=False)
    component_name = Column(String, nullable=True)
    category = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    score = Column(Float, default=0.0)
    confidence = Column(Float, default=1.0)
    title = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    cve_id = Column(String, nullable=True)
    evidence = Column(JSON, nullable=True)
    remediation = Column(JSON, nullable=True)
    is_suppressed = Column(Boolean, default=False)
    suppression_reason = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    scan = relationship("Scan", back_populates="findings")


class RiskHistory(Base):
    __tablename__ = "risk_history"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    score = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)
    confidence = Column(Float, nullable=True)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=utc_now)

    project = relationship("Project", back_populates="risk_history")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    name = Column(String, nullable=False)
    environment = Column(String, default="production")
    rules = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utc_now)

    project = relationship("Project", back_populates="policies")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=True)
    user_id = Column(String, nullable=True)
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    organization = relationship("Organization", back_populates="audit_logs")
