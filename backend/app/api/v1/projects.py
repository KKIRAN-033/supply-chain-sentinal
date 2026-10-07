"""Project API endpoints."""
import re
import os
import logging
import httpx
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.base import get_db
from app.db import repositories as repo
from app.core.security import validate_api_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/projects", tags=["projects"])


from pydantic import BaseModel, field_validator


class ProjectCreateRequest(BaseModel):
    name: str = ""
    repo_url: Optional[str] = None
    environment: str = "production"
    criticality: str = "medium"

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return v
        val = v.strip()
        if not val:
            return None
        lower = val.lower()
        if lower.startswith(("javascript:", "data:", "file:", "vbscript:")):
            raise ValueError("Invalid URL scheme")
        if not (lower.startswith("http://") or lower.startswith("https://") or lower.startswith("git@")):
            raise ValueError("Repository URL must use https://, http://, or git@")
        return val


class ProjectResponse(BaseModel):
    id: str
    name: str
    repo_url: Optional[str] = None
    environment: str
    criticality: str
    created_at: str


def _project_response(project) -> dict:
    return {
        "id": project.id,
        "name": project.name,
        "repo_url": project.repo_url,
        "environment": project.environment,
        "criticality": project.criticality,
        "created_at": str(project.created_at),
    }


def _is_manifest_file(path: str) -> bool:
    base = path.split("/")[-1].lower()
    exact = {
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
        "poetry.lock", "pipfile", "pipfile.lock", "pyproject.toml",
        "pom.xml", "build.gradle", "build.gradle.kts",
        "go.mod", "go.sum", "cargo.toml", "cargo.lock",
        "composer.json", "composer.lock", "gemfile", "gemfile.lock"
    }
    if base in exact:
        return True
    if "requirements" in base and base.endswith(".txt"):
        return True
    if base.endswith(".lock") or base.endswith(".lockb"):
        return True
    if any(p in base for p in ["sbom", "cyclonedx", "spdx", "bom."]):
        return True
    return False


def _detect_format_from_path(path: str) -> str:
    lower = path.lower()
    if lower.endswith("package.json"):
        return "package_json"
    if lower.endswith("package-lock.json") or lower.endswith("yarn.lock") or lower.endswith("pnpm-lock.yaml"):
        return "package_lock"
    if "requirements" in lower and lower.endswith(".txt"):
        return "requirements_txt"
    if lower.endswith("poetry.lock"):
        return "poetry_lock"
    if "cyclonedx" in lower or lower.endswith("bom.json"):
        return "cyclonedx"
    if "spdx" in lower:
        return "spdx"
    return "auto"


def _fetch_manifests_for_repo_url(repo_url: str) -> list[dict]:
    if not repo_url or "github.com" not in repo_url:
        return []

    match = re.search(r"github\.com[:/]([^/]+)/([^/\.]+)", repo_url.strip())
    if not match:
        return []

    owner, repo_name = match.group(1), match.group(2)

    headers = {"Accept": "application/vnd.github.v3+json"}
    gh_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    with httpx.Client(timeout=10.0) as client:
        # 1. Fetch default branch
        default_branch = "main"
        repo_resp = client.get(f"https://api.github.com/repos/{owner}/{repo_name}", headers=headers)
        if repo_resp.status_code == 200:
            default_branch = repo_resp.json().get("default_branch", "main")

        # 2. Fetch git tree recursively
        tree_resp = client.get(
            f"https://api.github.com/repos/{owner}/{repo_name}/git/trees/{default_branch}?recursive=1",
            headers=headers
        )

        manifests = []
        if tree_resp.status_code == 200:
            tree = tree_resp.json().get("tree", [])
            for item in tree:
                if item.get("type") == "blob":
                    path = item.get("path", "")
                    if any(ignored in path.lower() for ignored in ["node_modules/", "venv/", ".venv/", ".git/", "dist/", "build/"]):
                        continue
                    if _is_manifest_file(path):
                        download_url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/{default_branch}/{path}"
                        manifests.append({
                            "name": path,
                            "path": path,
                            "format": _detect_format_from_path(path),
                            "download_url": download_url
                        })
        else:
            # High-performance fallback when GitHub API is rate-limited (403) or tree API fails
            try:
                # 1. Quick scrape of main repository HTML
                html_resp = client.get(f"https://github.com/{owner}/{repo_name}", headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True, timeout=3.0)
                if html_resp.status_code == 200:
                    pattern = rf"/{re.escape(owner)}/{re.escape(repo_name)}/blob/[^/]+/([^\"#\?]+)"
                    for path in set(re.findall(pattern, html_resp.text)):
                        if _is_manifest_file(path):
                            manifests.append({
                                "name": path,
                                "path": path,
                                "format": _detect_format_from_path(path),
                                "download_url": f"https://raw.githubusercontent.com/{owner}/{repo_name}/{default_branch}/{path}"
                            })
            except Exception as e:
                logger.warning(f"HTML fallback failed: {e}")

            # 2. Fast concurrent probes for standard and monorepo locations
            from concurrent.futures import ThreadPoolExecutor
            probes = [
                "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                "requirements.txt", "poetry.lock", "pyproject.toml", "uv.lock",
                "frontend/package.json", "frontend/package-lock.json",
                "backend/requirements.txt", "client/package.json", "server/package.json",
                "Cargo.toml", "go.mod", "pom.xml"
            ]
            existing_paths = {m["path"] for m in manifests}

            def check_probe(probe):
                if probe in existing_paths:
                    return None
                for b in [default_branch, "main", "master"]:
                    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/{b}/{probe}"
                    try:
                        r = client.head(raw_url, timeout=2.5)
                        if r.status_code == 200:
                            return {
                                "name": probe,
                                "path": probe,
                                "format": _detect_format_from_path(probe),
                                "download_url": raw_url
                            }
                    except Exception:
                        pass
                return None

            with ThreadPoolExecutor(max_workers=10) as ex:
                probed_results = list(filter(None, ex.map(check_probe, probes)))
                manifests.extend(probed_results)

        return manifests


def _fetch_manifest_content_for_repo_url(repo_url: str, path: str) -> dict:
    if not repo_url or "github.com" not in repo_url:
        raise HTTPException(status_code=400, detail="Invalid repository URL")

    match = re.search(r"github\.com[:/]([^/]+)/([^/\.]+)", repo_url.strip())
    if not match:
        raise HTTPException(status_code=400, detail="Invalid GitHub repo URL")

    owner, repo_name = match.group(1), match.group(2)

    headers = {"Accept": "application/vnd.github.v3+json"}
    gh_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    with httpx.Client(timeout=10.0) as client:
        default_branch = "main"
        repo_resp = client.get(f"https://api.github.com/repos/{owner}/{repo_name}", headers=headers)
        if repo_resp.status_code == 200:
            default_branch = repo_resp.json().get("default_branch", "main")

        # Try raw usercontent across potential branch names (main, master, default_branch)
        candidate_branches = list(dict.fromkeys([default_branch, "main", "master"]))
        for b in candidate_branches:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/{b}/{path}"
            try:
                raw_resp = client.get(raw_url)
                if raw_resp.status_code == 200:
                    return {
                        "path": path,
                        "format": _detect_format_from_path(path),
                        "content": raw_resp.text
                    }
            except Exception:
                pass

        # Fallback to contents API
        api_url = f"https://api.github.com/repos/{owner}/{repo_name}/contents/{path}"
        api_resp = client.get(api_url, headers=headers)
        if api_resp.status_code == 200:
            import base64
            data = api_resp.json()
            raw_b64 = data.get("content", "")
            decoded = base64.b64decode(raw_b64).decode("utf-8", errors="replace")
            return {
                "path": path,
                "format": _detect_format_from_path(path),
                "content": decoded
            }

        raise HTTPException(status_code=404, detail=f"File {path} not found in repository")


# ==================== Endpoints ====================

@router.post("", status_code=201)
def create_project(
    req: ProjectCreateRequest,
    db: Session = Depends(get_db),
):
    org = repo.get_organization(db, "org_default")
    if not org:
        org = repo.create_organization(db, "Default Organization", org_id="org_default")

    name = req.name.strip() if req.name else "Project"
    project = repo.create_project(
        db, org.id, name, req.repo_url.strip() if req.repo_url else None, req.environment, req.criticality
    )
    return _project_response(project)


@router.post("/by-repo")
def get_or_create_project_by_repo(req: ProjectCreateRequest, db: Session = Depends(get_db)):
    """Find existing project by repo_url or create a new one automatically."""
    clean_repo = req.repo_url.strip() if req.repo_url else ""
    if clean_repo:
        projects = repo.list_projects(db)
        for p in projects:
            if p.repo_url and p.repo_url.strip().rstrip("/").lower() == clean_repo.rstrip("/").lower():
                return _project_response(p)

    org = repo.get_organization(db, "org_default")
    if not org:
        org = repo.create_organization(db, "Default Organization")
        org.id = "org_default"
        db.commit()

    name = req.name
    if not name or name == "New Project":
        name = clean_repo.strip("/").split("/")[-1].replace(".git", "") if clean_repo else "Project"

    project = repo.create_project(
        db, org.id, name, clean_repo or None, req.environment, req.criticality
    )
    return _project_response(project)


@router.get("")
def list_projects(db: Session = Depends(get_db)):
    projects = repo.list_projects(db)
    results = []
    for p in projects:
        p_dict = _project_response(p)
        scans = repo.list_scans(db, p.id)
        p_dict["total_scans"] = len(scans)
        p_dict["scans"] = [
            {
                "id": s.id,
                "status": s.status,
                "overall_score": s.overall_score,
                "risk_level": s.risk_level,
                "confidence": s.confidence,
                "data_quality": s.data_quality,
                "policy_decision": s.policy_decision,
                "total_components": s.total_components,
                "vulnerable_count": s.vulnerable_count,
                "suspicious_count": s.suspicious_count,
                "outdated_count": s.outdated_count,
                "input_format": s.input_format,
                "created_at": str(s.created_at),
            }
            for s in scans
        ]
        if scans:
            p_dict["latest_scan"] = p_dict["scans"][0]
        results.append(p_dict)
    return results


@router.get("/manifests-from-url")
def get_manifests_from_url(repo_url: str):
    """Dynamically fetch all manifest/SBOM files for ANY GitHub repository URL."""
    try:
        manifests = _fetch_manifests_for_repo_url(repo_url)
        return {"repo_url": repo_url, "manifests": manifests}
    except Exception as e:
        logger.error(f"Error fetching manifests for URL {repo_url}: {e}")
        return {"repo_url": repo_url, "manifests": []}


@router.get("/manifest-content-from-url")
def get_manifest_content_from_url(repo_url: str, path: str):
    """Fetch raw file content for ANY manifest from ANY repository URL."""
    return _fetch_manifest_content_for_repo_url(repo_url, path)


@router.get("/{project_id}")
def get_project(project_id: str, db: Session = Depends(get_db)):
    project = repo.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail={
            "code": "PROJECT_NOT_FOUND",
            "message": f"Project {project_id} not found",
        })
    scans = repo.list_scans(db, project_id)
    result = _project_response(project)
    result["total_scans"] = len(scans)
    result["scans"] = [
        {
            "id": s.id,
            "status": s.status,
            "overall_score": s.overall_score,
            "risk_level": s.risk_level,
            "confidence": s.confidence,
            "data_quality": s.data_quality,
            "policy_decision": s.policy_decision,
            "total_components": s.total_components,
            "vulnerable_count": s.vulnerable_count,
            "suspicious_count": s.suspicious_count,
            "outdated_count": s.outdated_count,
            "input_format": s.input_format,
            "created_at": str(s.created_at),
        }
        for s in scans
    ]
    if scans:
        result["latest_scan"] = result["scans"][0]
    return result


def _find_local_repo_dir(project_name: str, repo_url: Optional[str] = None) -> Optional[str]:
    scratch_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".."))
    names_to_try = [project_name]
    if repo_url:
        match = re.search(r"github\.com[:/]([^/]+)/([^/\.]+)", repo_url.strip())
        if match:
            names_to_try.append(match.group(2))
        clean_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        names_to_try.append(clean_name)
    for n in names_to_try:
        if n:
            candidate = os.path.join(scratch_dir, n)
            if os.path.isdir(candidate):
                return candidate
    return None


def _scan_local_manifests(local_dir: str) -> list[dict]:
    manifests = []
    ignored_dirs = {".git", "node_modules", "venv", ".venv", "dist", "build", ".kilo", ".cursor", ".agent", ".agents", "__pycache__"}
    for root, dirs, files in os.walk(local_dir):
        dirs[:] = [d for d in dirs if d.lower() not in ignored_dirs and not d.startswith(".")]
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), local_dir).replace("\\", "/")
            if _is_manifest_file(rel):
                manifests.append({
                    "name": rel,
                    "path": rel,
                    "format": _detect_format_from_path(rel),
                    "download_url": ""
                })
    return manifests


@router.get("/{project_id}/manifests")
def get_project_manifests(project_id: str, db: Session = Depends(get_db)):
    """Fetch available manifest files from the project's repository."""
    project = repo.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    manifests = []
    # 1. Local scratch repository check
    local_dir = _find_local_repo_dir(project.name, project.repo_url)
    if local_dir:
        manifests.extend(_scan_local_manifests(local_dir))

    # 2. Remote GitHub repository check (if repo_url exists and not found locally or complementing)
    if project.repo_url and not manifests:
        try:
            gh_manifests = _fetch_manifests_for_repo_url(project.repo_url)
            manifests.extend(gh_manifests)
        except Exception as e:
            logger.error(f"Error fetching manifests for project {project_id}: {e}")

    # Deduplicate by path
    seen = set()
    deduped = []
    for m in manifests:
        if m["path"] not in seen:
            seen.add(m["path"])
            deduped.append(m)

    return {"manifests": deduped}


@router.get("/{project_id}/manifest-content")
def get_manifest_content(project_id: str, path: str, db: Session = Depends(get_db)):
    """Fetch raw content of a manifest file for the project."""
    project = repo.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # 1. Check local scratch repository
    local_dir = _find_local_repo_dir(project.name, project.repo_url)
    if local_dir:
        real_local = os.path.realpath(local_dir)
        real_target = os.path.realpath(os.path.join(local_dir, path))
        try:
            is_inside = (os.path.commonpath([real_local, real_target]) == real_local)
        except ValueError:
            is_inside = False

        if is_inside and os.path.isfile(real_target) and _is_manifest_file(real_target):
            try:
                with open(real_target, "r", encoding="utf-8", errors="replace") as f:
                    return {
                        "path": path,
                        "format": _detect_format_from_path(path),
                        "content": f.read()
                    }
            except Exception as e:
                logger.warning(f"Failed to read local manifest {real_target}: {e}")

    # 3. Check remote GitHub repo
    if project.repo_url:
        return _fetch_manifest_content_for_repo_url(project.repo_url, path)

    raise HTTPException(status_code=404, detail=f"Manifest file {path} not found")

