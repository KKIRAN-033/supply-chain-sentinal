"""Continuous Monitoring Service.

Provides lightweight trigger abstraction for:
- Scheduled re-scans
- Repository change / commit events
- Advisory-change checks

Decoupled from specific queue infrastructure (runs via BackgroundTasks or worker pool).
"""
import logging
from sqlalchemy.orm import Session
from fastapi import BackgroundTasks

from app.db import repositories as repo
from app.db.base import SessionLocal
from app.engine.orchestrator import run_scan

logger = logging.getLogger(__name__)


class MonitoringService:
    """Orchestrates continuous monitoring triggers to the scan pipeline."""

    @staticmethod
    def trigger_scheduled_scan(project_id: str, background_tasks: BackgroundTasks, db: Session) -> dict:
        """Trigger a scheduled scan for a project using its latest available manifest."""
        project = repo.get_project(db, project_id)
        if not project:
            raise ValueError(f"Project {project_id} not found")

        scans = repo.list_scans(db, project_id)
        if not scans:
            raise ValueError(f"No previous scans available to re-scan for project {project_id}")

        latest_scan = scans[0]
        # Create new scan
        new_scan = repo.create_scan(
            db, project_id,
            input_format=latest_scan.input_format,
            ecosystem=latest_scan.input_ecosystem,
            source="scheduled_monitoring",
            sbom_hash=latest_scan.sbom_hash,
        )

        scan_id = new_scan.id
        # We need raw content or rebuild from saved components
        components = repo.get_components(db, latest_scan.id)
        # Generate simple manifest or requirements
        req_lines = [f"{c.name}=={c.version}" for c in components if c.name and c.version]
        raw_content = "\n".join(req_lines) or "dependencies: []"

        def _run_bg():
            bg_db = SessionLocal()
            try:
                run_scan(scan_id, raw_content, bg_db)
            finally:
                bg_db.close()

        background_tasks.add_task(_run_bg)
        repo.save_audit_event(db, "monitoring_scheduled_scan_triggered", "scan", scan_id, {
            "project_id": project_id, "trigger": "schedule"
        })
        return {"scan_id": scan_id, "status": "PENDING", "trigger": "scheduled"}

    @staticmethod
    def trigger_repo_change(
        project_id: str,
        commit_sha: str,
        raw_content: str,
        background_tasks: BackgroundTasks,
        db: Session,
        input_format: str = "auto",
    ) -> dict:
        """Trigger scan upon receiving a repository commit/push event."""
        project = repo.get_project(db, project_id)
        if not project:
            raise ValueError(f"Project {project_id} not found")

        scan = repo.create_scan(
            db, project_id,
            input_format=input_format if input_format != "auto" else None,
            source=f"repo_push_{commit_sha[:8]}" if commit_sha else "repo_push",
        )

        scan_id = scan.id
        def _run_bg():
            bg_db = SessionLocal()
            try:
                run_scan(scan_id, raw_content, bg_db)
            finally:
                bg_db.close()

        background_tasks.add_task(_run_bg)
        repo.save_audit_event(db, "monitoring_repo_change_triggered", "scan", scan_id, {
            "project_id": project_id, "commit_sha": commit_sha, "trigger": "repository_change"
        })
        return {"scan_id": scan_id, "status": "PENDING", "commit_sha": commit_sha, "trigger": "repo_change"}
