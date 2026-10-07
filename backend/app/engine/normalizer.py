"""Normalizer: assigns PURLs, deduplicates, and ensures canonical form."""
import logging
import re
from app.schemas.components import CanonicalComponent

logger = logging.getLogger(__name__)


def normalize(components: list[CanonicalComponent], ecosystem_hint: str = "") -> list[CanonicalComponent]:
    """Normalize a list of parsed components.
    
    - Ensures every component has a PURL
    - Deduplicates by PURL
    - Applies ecosystem hint if missing
    - Strips leading/trailing whitespace from names/versions
    """
    seen_purls = {}
    normalized = []

    for comp in components:
        # Clean up
        comp.name = comp.name.strip()
        comp.version = comp.version.strip()

        # Apply ecosystem hint
        if not comp.ecosystem and ecosystem_hint:
            comp.ecosystem = ecosystem_hint

        # Generate PURL if missing
        if not comp.purl:
            comp.purl = _generate_purl(comp.ecosystem, comp.name, comp.version)

        # Deduplicate by PURL
        if comp.purl in seen_purls:
            existing = seen_purls[comp.purl]
            # Merge: keep direct if either is direct, keep runtime if either is runtime
            if comp.is_direct:
                existing.is_direct = True
            if comp.scope == "runtime":
                existing.scope = "runtime"
            existing.licenses = list(set(existing.licenses + comp.licenses))
            existing.install_scripts = list(set(existing.install_scripts + comp.install_scripts))
            continue

        # Assign component_id
        comp.component_id = comp.purl

        seen_purls[comp.purl] = comp
        normalized.append(comp)

    logger.info(f"Normalized {len(components)} -> {len(normalized)} unique components")
    return normalized


def _generate_purl(ecosystem: str, name: str, version: str = "") -> str:
    eco_map = {"npm": "npm", "pypi": "pypi", "maven": "maven", "golang": "golang", "": "generic"}
    purl_type = eco_map.get(ecosystem, ecosystem or "generic")
    name_clean = name.lower().replace(" ", "-")
    if version:
        return f"pkg:{purl_type}/{name_clean}@{version}"
    return f"pkg:{purl_type}/{name_clean}"
