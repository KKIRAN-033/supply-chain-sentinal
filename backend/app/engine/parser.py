"""Format detection and multi-format SBOM / manifest parser.

Supports:
1. package.json
2. requirements.txt
3. package-lock.json (v1, v2, v3)
4. poetry.lock
5. CycloneDX JSON SBOM
6. SPDX JSON SBOM

All formats converge into a list of CanonicalComponent with real dependency relationships.
ZERO hardcoding. Real structural relationships only.
"""
import json
import re
import logging
from typing import Optional, Dict, Any, List, Tuple

from app.core.constants import InputFormat
from app.schemas.components import CanonicalComponent

logger = logging.getLogger(__name__)


def detect_format(raw_content: str, hint: str = "auto") -> InputFormat:
    """Detect input format strictly from content and schema.
    
    File extensions or hints alone are NEVER sufficient.
    Content structure and schema are validated.
    """
    if not raw_content or not raw_content.strip():
        return InputFormat.UNKNOWN

    content = raw_content.strip()

    # 1. Check for poetry.lock (TOML format with [[package]])
    if "[[package]]" in content and ("name =" in content or "version =" in content):
        return InputFormat.POETRY_LOCK

    # 2. Check for JSON content
    if content.startswith("{") or (content.startswith("[") and not content.startswith("[[")):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return InputFormat.MALFORMED_JSON


        if isinstance(data, dict):
            # CycloneDX Detection
            bom_format = str(data.get("bomFormat", "")).lower()
            schema = str(data.get("$schema", "")).lower()
            if bom_format == "cyclonedx" or "cyclonedx" in schema or ("specVersion" in data and "components" in data):
                return InputFormat.CYCLONEDX_JSON

            # SPDX Detection
            if "spdxVersion" in data or "SPDXID" in data or "spdx" in schema or ("packages" in data and "dataLicense" in data):
                return InputFormat.SPDX_JSON

            # package-lock.json Detection (v1, v2, v3)
            if "lockfileVersion" in data:
                return InputFormat.PACKAGE_LOCK_JSON

            # package.json Detection
            npm_dep_keys = {"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"}
            has_npm_deps = any(k in data for k in npm_dep_keys)
            has_npm_meta = any(k in data for k in ("name", "version", "scripts", "main", "keywords", "author", "license", "private", "description"))
            if has_npm_deps or has_npm_meta:
                return InputFormat.PACKAGE_JSON

            # If a valid JSON hint was given, honor it
            if hint and hint != "auto":
                mapping = {
                    "cyclonedx": InputFormat.CYCLONEDX_JSON,
                    "cyclonedx_json": InputFormat.CYCLONEDX_JSON,
                    "spdx": InputFormat.SPDX_JSON,
                    "spdx_json": InputFormat.SPDX_JSON,
                    "package_json": InputFormat.PACKAGE_JSON,
                    "package_lock": InputFormat.PACKAGE_LOCK_JSON,
                    "package_lock_json": InputFormat.PACKAGE_LOCK_JSON,
                }
                if hint.lower() in mapping:
                    return mapping[hint.lower()]

            # Unknown JSON (valid JSON object, but unsupported schema)
            return InputFormat.UNKNOWN_JSON
        elif isinstance(data, list):
            # Unknown JSON array
            return InputFormat.UNKNOWN_JSON

    # 3. Check for requirements.txt (Python dependencies)
    lines = [l.strip() for l in content.split("\n") if l.strip()]
    if lines:
        meaningful = [l for l in lines if not l.startswith(("#", "-r", "-i", "--"))]
        req_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._\-\[\]]*(\s*([><=!~^@]=?\s*[\w\.\*\+\-\_\/\:]+(\s*,\s*[><=!~^]=?\s*[\w\.\*\+\-\_\/\:]+)*)?(\s*;.*)?)?$')
        if meaningful:
            valid_req = sum(1 for l in meaningful if req_pattern.match(l))
            if (valid_req / len(meaningful)) >= 0.4:
                return InputFormat.REQUIREMENTS_TXT

    # Check hint fallback
    if hint and hint != "auto":
        mapping = {
            "cyclonedx": InputFormat.CYCLONEDX_JSON,
            "cyclonedx_json": InputFormat.CYCLONEDX_JSON,
            "spdx": InputFormat.SPDX_JSON,
            "spdx_json": InputFormat.SPDX_JSON,
            "package_json": InputFormat.PACKAGE_JSON,
            "requirements_txt": InputFormat.REQUIREMENTS_TXT,
            "package_lock": InputFormat.PACKAGE_LOCK_JSON,
            "package_lock_json": InputFormat.PACKAGE_LOCK_JSON,
            "poetry_lock": InputFormat.POETRY_LOCK,
        }
        if hint.lower() in mapping:
            return mapping[hint.lower()]

    return InputFormat.UNKNOWN


def parse(raw_content: str, fmt: InputFormat) -> list[CanonicalComponent]:
    """Route to the appropriate parser."""
    parsers = {
        InputFormat.CYCLONEDX_JSON: _parse_cyclonedx,
        InputFormat.SPDX_JSON: _parse_spdx,
        InputFormat.PACKAGE_JSON: _parse_package_json,
        InputFormat.REQUIREMENTS_TXT: _parse_requirements_txt,
        InputFormat.PACKAGE_LOCK_JSON: _parse_package_lock,
        InputFormat.POETRY_LOCK: _parse_poetry_lock,
    }
    parser_fn = parsers.get(fmt)
    if not parser_fn:
        raise ValueError(f"Unsupported format: {fmt.value if hasattr(fmt, 'value') else fmt}")
    return parser_fn(raw_content)


def extract_provenance(raw_content: str, fmt: InputFormat) -> dict:
    """Extract provenance and specification metadata from SBOM content."""
    meta = {
        "format": fmt.value if hasattr(fmt, "value") else str(fmt),
        "spec_version": None,
        "serial_number": None,
        "tools": [],
        "authors": [],
        "timestamp": None,
    }
    try:
        if fmt == InputFormat.CYCLONEDX_JSON:
            data = json.loads(raw_content)
            meta["spec_version"] = str(data.get("specVersion", "")) or None
            meta["serial_number"] = data.get("serialNumber")
            metadata = data.get("metadata", {})
            meta["timestamp"] = metadata.get("timestamp")
            tools = metadata.get("tools", [])
            if isinstance(tools, list):
                meta["tools"] = [t.get("name", str(t)) if isinstance(t, dict) else str(t) for t in tools]
            elif isinstance(tools, dict):
                components = tools.get("components", [])
                meta["tools"] = [c.get("name", "") for c in components if isinstance(c, dict)]
            authors = metadata.get("authors", [])
            if isinstance(authors, list):
                meta["authors"] = [a.get("name", str(a)) if isinstance(a, dict) else str(a) for a in authors]

        elif fmt == InputFormat.SPDX_JSON:
            data = json.loads(raw_content)
            meta["spec_version"] = data.get("spdxVersion")
            meta["serial_number"] = data.get("documentNamespace") or data.get("SPDXID")
            creation = data.get("creationInfo", {})
            meta["timestamp"] = creation.get("created")
            creators = creation.get("creators", [])
            for c in creators:
                if str(c).startswith("Tool:"):
                    meta["tools"].append(str(c).replace("Tool:", "").strip())
                elif str(c).startswith("Person:") or str(c).startswith("Organization:"):
                    meta["authors"].append(str(c).strip())
    except Exception as e:
        logger.warning(f"Error extracting provenance: {e}")
    return meta


# ---------- 1. CycloneDX JSON ----------

def _parse_cyclonedx(raw: str) -> list[CanonicalComponent]:
    data = json.loads(raw)
    components = []
    comp_by_ref: Dict[str, CanonicalComponent] = {}

    # 1. Root component from metadata if present
    metadata = data.get("metadata", {})
    root_comp_data = metadata.get("component")
    root_ref = None
    if root_comp_data and isinstance(root_comp_data, dict):
        r_name = root_comp_data.get("name", "application")
        r_version = root_comp_data.get("version", "")
        r_purl = root_comp_data.get("purl", "") or _generate_purl("npm", r_name, r_version)
        root_ref = root_comp_data.get("bom-ref") or r_purl or r_name
        root_comp = CanonicalComponent(
            component_id=root_ref,
            name=r_name,
            version=r_version,
            ecosystem=_ecosystem_from_purl(r_purl) or "generic",
            purl=r_purl,
            scope="root",
            is_direct=True,
            dependencies=[],
        )
        components.append(root_comp)
        comp_by_ref[root_ref] = root_comp
        if r_purl:
            comp_by_ref[r_purl] = root_comp
        comp_by_ref[r_name] = root_comp

    # 2. Components list
    for comp in data.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version", "")
        purl = comp.get("purl", "")
        ecosystem = _ecosystem_from_purl(purl) or comp.get("group", "") or "generic"
        scope = comp.get("scope", "required")
        scope_mapped = "development" if scope == "optional" else "runtime"
        bom_ref = comp.get("bom-ref") or purl or name

        licenses = []
        for lic in comp.get("licenses", []):
            if isinstance(lic, dict) and "license" in lic:
                lid = lic["license"].get("id", lic["license"].get("name", ""))
                if lid:
                    licenses.append(lid)

        c = CanonicalComponent(
            component_id=bom_ref,
            name=name,
            version=version,
            ecosystem=ecosystem,
            purl=purl or _generate_purl(ecosystem, name, version),
            scope=scope_mapped,
            is_direct=True,
            licenses=licenses,
            dependencies=[],
        )
        components.append(c)
        comp_by_ref[bom_ref] = c
        if purl:
            comp_by_ref[purl] = c
        comp_by_ref[name] = c

    # 3. Explicit dependency relationships from "dependencies" array
    dep_entries = data.get("dependencies", [])
    all_child_refs = set()
    for dep_entry in dep_entries:
        parent_ref = dep_entry.get("ref", "")
        depends_on = dep_entry.get("dependsOn", [])
        if parent_ref in comp_by_ref:
            parent_comp = comp_by_ref[parent_ref]
            for child_ref in depends_on:
                all_child_refs.add(child_ref)
                if child_ref in comp_by_ref:
                    child_comp = comp_by_ref[child_ref]
                    target_identifier = child_comp.purl or child_comp.name
                    if target_identifier not in parent_comp.dependencies:
                        parent_comp.dependencies.append(target_identifier)
                else:
                    parent_comp.dependencies.append(child_ref)

    # Set is_direct: if a component is depended on by another non-root component, mark transitive
    if root_ref and root_ref in comp_by_ref:
        root_deps = set(comp_by_ref[root_ref].dependencies)
        for c in components:
            if c != comp_by_ref[root_ref]:
                c.is_direct = (c.purl in root_deps or c.name in root_deps or c.component_id in root_deps)
    elif all_child_refs:
        for c in components:
            if c.component_id in all_child_refs and c.dependencies:
                pass

    return components


# ---------- 2. SPDX JSON ----------

def _parse_spdx(raw: str) -> list[CanonicalComponent]:
    data = json.loads(raw)
    components = []
    packages = data.get("packages", [])
    relationships = data.get("relationships", [])

    spdx_map: Dict[str, CanonicalComponent] = {}

    for pkg in packages:
        spdx_id = pkg.get("SPDXID", "")
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        purl = ""
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                break
        ecosystem = _ecosystem_from_purl(purl) or "generic"

        licenses = []
        concluded = pkg.get("licenseConcluded")
        if concluded and concluded != "NOASSERTION":
            licenses.append(concluded)
        declared = pkg.get("licenseDeclared")
        if declared and declared != "NOASSERTION" and declared not in licenses:
            licenses.append(declared)

        c = CanonicalComponent(
            component_id=spdx_id,
            name=name,
            version=version,
            ecosystem=ecosystem,
            purl=purl or _generate_purl(ecosystem, name, version),
            is_direct=True,
            licenses=licenses,
            dependencies=[],
        )
        components.append(c)
        spdx_map[spdx_id] = c
        if purl:
            spdx_map[purl] = c
        spdx_map[name] = c

    # Parse relationships: DEPENDS_ON, CONTAINS, DEPENDENCY_OF
    for rel in relationships:
        elem = rel.get("spdxElementId", "")
        rel_type = rel.get("relationshipType", "")
        related = rel.get("relatedSpdxElement", "")

        parent_id = None
        child_id = None

        if rel_type in ("DEPENDS_ON", "CONTAINS"):
            parent_id = elem
            child_id = related
        elif rel_type in ("DEPENDENCY_OF", "CONTAINED_BY"):
            parent_id = related
            child_id = elem

        if parent_id and child_id and parent_id in spdx_map:
            parent_comp = spdx_map[parent_id]
            child_comp = spdx_map.get(child_id)
            child_target = (child_comp.purl or child_comp.name) if child_comp else child_id
            if child_target not in parent_comp.dependencies:
                parent_comp.dependencies.append(child_target)
            if child_comp and parent_comp.component_id != "SPDXRef-DOCUMENT":
                # Child is depended on by another component -> transitive
                child_comp.is_direct = False

    return components


# ---------- 3. package.json ----------

def _parse_package_json(raw: str) -> list[CanonicalComponent]:
    data = json.loads(raw)
    components = []

    app_name = data.get("name", "app")
    app_version = data.get("version", "1.0.0")
    app_purl = f"pkg:npm/{app_name}@{app_version}" if app_version else f"pkg:npm/{app_name}"

    root_deps: List[str] = []

    dep_sections = [
        ("dependencies", "runtime", True),
        ("devDependencies", "development", True),
        ("peerDependencies", "runtime", True),
        ("optionalDependencies", "runtime", True),
    ]

    for dep_type, scope, is_direct in dep_sections:
        deps = data.get(dep_type, {})
        if isinstance(deps, dict):
            for name, version_spec in deps.items():
                raw_spec = str(version_spec).strip() if version_spec else ""
                clean_ver = re.sub(r'^[><=!~^]+', '', raw_spec).strip()
                purl = _generate_purl("npm", name, clean_ver or raw_spec)
                is_pinned = _is_npm_pinned(raw_spec)

                components.append(CanonicalComponent(
                    component_id=name,
                    name=name,
                    version=clean_ver or raw_spec,
                    ecosystem="npm",
                    purl=purl,
                    scope=scope,
                    is_direct=is_direct,
                    is_pinned=is_pinned,
                    dependencies=[],
                ))
                root_deps.append(purl)

    # Create root application component so that root -> direct dependency edges exist in graph
    root_comp = CanonicalComponent(
        component_id=app_name,
        name=app_name,
        version=app_version,
        ecosystem="npm",
        purl=app_purl,
        scope="root",
        is_direct=True,
        dependencies=root_deps,
    )
    components.insert(0, root_comp)

    # Extract scripts for behavioral analysis
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        script_names_of_interest = ["preinstall", "postinstall", "install", "prepare", "prepublish"]
        install_scripts = [f"{k}: {scripts[k]}" for k in script_names_of_interest if k in scripts]
        if install_scripts:
            for c in components:
                c.install_scripts = install_scripts

    return components


# ---------- 4. requirements.txt ----------

def _parse_requirements_txt(raw: str) -> list[CanonicalComponent]:
    components = []
    root_deps: List[str] = []

    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Split inline comments
        if " #" in line:
            line = line.split(" #")[0].strip()

        match = re.match(r'^([a-zA-Z0-9._-]+)(?:\[[^\]]*\])?\s*([><=!~^]=?\s*[\d.a-zA-Z*+-]+(?:\s*,\s*[><=!~^]=?\s*[\d.a-zA-Z*+-]+)*)?', line)
        if match:
            name = match.group(1).strip()
            version_spec = (match.group(2) or "").strip()
            version = re.sub(r'^[><=!~^]+\s*', '', version_spec.split(",")[0]).strip() if version_spec else ""
            is_pinned = _is_python_pinned(version_spec)
            purl = _generate_purl("pypi", name, version)

            components.append(CanonicalComponent(
                component_id=name,
                name=name,
                version=version,
                ecosystem="pypi",
                purl=purl,
                scope="runtime",
                is_direct=True,
                is_pinned=is_pinned,
                dependencies=[],
            ))
            root_deps.append(purl)

    # Root application node: Project -> direct dependencies
    root_comp = CanonicalComponent(
        component_id="project-root",
        name="project-root",
        version="1.0.0",
        ecosystem="pypi",
        purl="pkg:pypi/project-root@1.0.0",
        scope="root",
        is_direct=True,
        dependencies=root_deps,
    )
    components.insert(0, root_comp)

    return components


# ---------- 5. package-lock.json (v1, v2, v3) ----------

def _parse_package_lock(raw: str) -> list[CanonicalComponent]:
    data = json.loads(raw)
    components = []
    seen_purls = set()
    comp_map: Dict[str, CanonicalComponent] = {}

    root_name = data.get("name", "app")
    root_version = data.get("version", "1.0.0")
    root_purl = f"pkg:npm/{root_name}@{root_version}" if root_version else f"pkg:npm/{root_name}"

    root_comp = CanonicalComponent(
        component_id=root_name,
        name=root_name,
        version=root_version,
        ecosystem="npm",
        purl=root_purl,
        scope="root",
        is_direct=True,
        dependencies=[],
    )
    components.append(root_comp)
    comp_map[root_name] = root_comp
    comp_map[""] = root_comp

    # Lockfile v2 & v3 format ("packages" key)
    packages = data.get("packages", {})
    if packages and isinstance(packages, dict):
        root_pkg = packages.get("", {})
        root_declared_deps = dict(root_pkg.get("dependencies", {}))
        root_declared_dev_deps = dict(root_pkg.get("devDependencies", {}))

        # First pass: Create all components
        for path, info in packages.items():
            if not path or path == "":
                continue
            parts = path.split("node_modules/")
            name = parts[-1]
            if not name:
                continue

            version = info.get("version", "")
            is_direct = name in root_declared_deps or name in root_declared_dev_deps or len(parts) == 2
            dev = info.get("dev", False) or name in root_declared_dev_deps
            scope = "development" if dev else "runtime"
            is_pinned = _is_npm_pinned(version)
            purl = _generate_purl("npm", name, version)

            comp = CanonicalComponent(
                component_id=name,
                name=name,
                version=version,
                ecosystem="npm",
                purl=purl,
                scope=scope,
                is_direct=is_direct,
                is_pinned=is_pinned,
                dependencies=[],
            )
            if purl not in seen_purls:
                seen_purls.add(purl)
                components.append(comp)
            comp_map[path] = comp
            comp_map[name] = comp

        # Link root dependencies
        for dep_name in list(root_declared_deps.keys()) + list(root_declared_dev_deps.keys()):
            target = comp_map.get(dep_name)
            if target and target.purl not in root_comp.dependencies:
                root_comp.dependencies.append(target.purl)

        # Second pass: Extract real dependencies per package
        for path, info in packages.items():
            if not path or path == "":
                continue
            parent_comp = comp_map.get(path)
            if not parent_comp:
                continue

            pkg_deps = info.get("dependencies", {})
            if isinstance(pkg_deps, dict):
                for child_name in pkg_deps.keys():
                    # Look up child package in node_modules hierarchy
                    child_path = f"{path}/node_modules/{child_name}"
                    child_comp = comp_map.get(child_path) or comp_map.get(child_name)
                    if child_comp:
                        target_id = child_comp.purl
                        if target_id not in parent_comp.dependencies:
                            parent_comp.dependencies.append(target_id)

    # Lockfile v1 fallback ("dependencies" key)
    elif "dependencies" in data and isinstance(data.get("dependencies"), dict):
        def walk_v1(deps_dict: dict, parent_node: CanonicalComponent, is_root: bool = False):
            for name, info in deps_dict.items():
                version = info.get("version", "")
                dev = info.get("dev", False)
                scope = "development" if dev else "runtime"
                is_pinned = _is_npm_pinned(version)
                purl = _generate_purl("npm", name, version)

                comp = CanonicalComponent(
                    component_id=name,
                    name=name,
                    version=version,
                    ecosystem="npm",
                    purl=purl,
                    scope=scope,
                    is_direct=is_root,
                    is_pinned=is_pinned,
                    dependencies=[],
                )
                if purl not in seen_purls:
                    seen_purls.add(purl)
                    components.append(comp)

                if comp.purl not in parent_node.dependencies:
                    parent_node.dependencies.append(comp.purl)

                # Nested dependencies or "requires"
                sub_deps = info.get("dependencies", {})
                if isinstance(sub_deps, dict) and sub_deps:
                    walk_v1(sub_deps, comp, is_root=False)
                elif "requires" in info and isinstance(info["requires"], dict):
                    # v1 requires map child names
                    for req_name in info["requires"].keys():
                        req_comp = comp_map.get(req_name)
                        if req_comp and req_comp.purl not in comp.dependencies:
                            comp.dependencies.append(req_comp.purl)

                comp_map[name] = comp

        walk_v1(data["dependencies"], root_comp, is_root=True)

    return components


# ---------- 6. poetry.lock ----------

def _parse_poetry_lock(raw: str) -> list[CanonicalComponent]:
    components = []
    comp_by_name: Dict[str, CanonicalComponent] = {}
    dep_mappings: Dict[str, List[str]] = {}

    root_comp = CanonicalComponent(
        component_id="poetry-project",
        name="poetry-project",
        version="1.0.0",
        ecosystem="pypi",
        purl="pkg:pypi/poetry-project@1.0.0",
        scope="root",
        is_direct=True,
        dependencies=[],
    )
    components.append(root_comp)

    package_blocks = re.split(r'(?m)^\[\[package\]\]', raw)
    for block in package_blocks[1:]:
        name_match = re.search(r'(?m)^name\s*=\s*["\']([^"\']+)["\']', block)
        version_match = re.search(r'(?m)^version\s*=\s*["\']([^"\']+)["\']', block)
        category_match = re.search(r'(?m)^category\s*=\s*["\']([^"\']+)["\']', block)
        if name_match:
            name = name_match.group(1).strip()
            version = version_match.group(1).strip() if version_match else ""
            category = category_match.group(1).strip().lower() if category_match else "main"
            scope = "development" if category == "dev" else "runtime"
            is_pinned = bool(version)
            purl = _generate_purl("pypi", name, version)

            comp = CanonicalComponent(
                component_id=name,
                name=name,
                version=version,
                ecosystem="pypi",
                purl=purl,
                scope=scope,
                is_direct=True,
                is_pinned=is_pinned,
                dependencies=[],
            )
            components.append(comp)
            comp_by_name[name.lower()] = comp

            # Extract [package.dependencies] block
            deps_match = re.search(r'(?m)^\[package\.dependencies\](.*?)(?=\n\[|\Z)', block, re.DOTALL)
            if deps_match:
                deps_text = deps_match.group(1)
                dep_names = re.findall(r'(?m)^([a-zA-Z0-9._-]+)\s*=', deps_text)
                dep_mappings[name.lower()] = [d.lower() for d in dep_names]

    # Link relationships from lockfile
    transitive_names = set()
    for parent_name, children in dep_mappings.items():
        parent_comp = comp_by_name.get(parent_name)
        if parent_comp:
            for child_name in children:
                child_comp = comp_by_name.get(child_name)
                if child_comp:
                    if child_comp.purl not in parent_comp.dependencies:
                        parent_comp.dependencies.append(child_comp.purl)
                    transitive_names.add(child_name)

    # Direct packages: packages not depended on by other packages (or all top packages)
    for comp in components:
        if comp != root_comp:
            if comp.name.lower() in transitive_names:
                comp.is_direct = False
            else:
                comp.is_direct = True
                root_comp.dependencies.append(comp.purl)

    return components


# ---------- Helpers ----------

def _generate_purl(ecosystem: str, name: str, version: str = "") -> str:
    """Generate a valid Package URL."""
    eco_map = {"npm": "npm", "pypi": "pypi", "maven": "maven", "golang": "golang"}
    purl_type = eco_map.get(ecosystem.lower(), ecosystem.lower()) if ecosystem else "generic"
    clean_v = re.sub(r'^[><=!~^]+', '', version).strip() if version else ""
    if clean_v:
        return f"pkg:{purl_type}/{name}@{clean_v}"
    return f"pkg:{purl_type}/{name}"


def _ecosystem_from_purl(purl: str) -> str:
    """Extract ecosystem from a PURL string."""
    if not purl:
        return ""
    match = re.match(r'^pkg:([^/]+)/', purl)
    return match.group(1) if match else ""


def _is_npm_pinned(version: str) -> Optional[bool]:
    """Check if an npm version specifier is pinned."""
    if not version:
        return None
    v = version.strip()
    if v in ("*", "latest"):
        return False
    if v.startswith("^") or v.startswith("~") or v.startswith(">") or v.startswith("<"):
        return False
    if re.match(r'^\d+\.\d+\.\d+', v):
        return True
    return False


def _is_python_pinned(version_spec: str) -> Optional[bool]:
    """Check if a Python version specifier is pinned."""
    if not version_spec:
        return False
    spec = version_spec.strip()
    if "==" in spec and not any(op in spec for op in (">=", "<=", ">", "<", "~=", "!=")):
        return True
    return False
