"""Dependency graph engine using NetworkX.

Builds directed graph of component relationships,
computes reachability, and calculates blast radius.
Supports querying edges by both PURL and package name.
ZERO hardcoded relationships — strictly driven by canonical component data.
"""
import logging
from typing import Optional, Dict, Set, List
from app.schemas.components import CanonicalComponent

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    logger.warning("NetworkX not available; using fallback graph")


class DependencyGraph:
    """Directed graph of package dependencies."""

    def __init__(self):
        if HAS_NETWORKX:
            self.graph = nx.DiGraph()
        else:
            self.graph = None
            self._adj: Dict[str, List[str]] = {}
            self._nodes: Dict[str, dict] = {}

        # Lookups for resolving name <-> PURL <-> component_id
        self._name_to_purls: Dict[str, Set[str]] = {}
        self._id_to_purl: Dict[str, str] = {}
        self._purl_to_node: Dict[str, dict] = {}

    def add_component(self, component: CanonicalComponent):
        """Add a component node."""
        attrs = {
            "name": component.name,
            "version": component.version,
            "ecosystem": component.ecosystem,
            "is_direct": component.is_direct,
            "scope": component.scope,
            "purl": component.purl,
            "component_id": component.component_id,
        }
        node_id = component.purl or component.name

        # Track name & ID aliases for lookup
        if component.name:
            self._name_to_purls.setdefault(component.name.lower(), set()).add(node_id)
        if component.component_id:
            self._id_to_purl[component.component_id] = node_id
        self._purl_to_node[node_id] = attrs

        if self.graph is not None:
            self.graph.add_node(node_id, **attrs)
        else:
            self._nodes[node_id] = attrs
            if node_id not in self._adj:
                self._adj[node_id] = []

    def add_edge(self, parent: str, child: str):
        """Add a dependency edge (parent depends on child)."""
        if self.graph is not None:
            # Ensure nodes exist
            if not self.graph.has_node(parent):
                self.graph.add_node(parent, name=parent, purl=parent)
            if not self.graph.has_node(child):
                self.graph.add_node(child, name=child, purl=child)
            self.graph.add_edge(parent, child)
        else:
            if parent not in self._adj:
                self._adj[parent] = []
            if child not in self._adj[parent]:
                self._adj[parent].append(child)

    def build_from_components(self, components: list[CanonicalComponent]):
        """Build graph from canonical components and their declared dependencies."""
        # 1. Register all nodes
        for comp in components:
            self.add_component(comp)

        # 2. Add all declared dependency edges
        for comp in components:
            parent_id = comp.purl or comp.name
            for dep_ref in comp.dependencies:
                # Resolve dep_ref to a known node ID
                target_id = self._resolve_node_id(dep_ref)
                if target_id and target_id != parent_id:
                    self.add_edge(parent_id, target_id)

    def _resolve_node_id(self, ref: str) -> str:
        """Resolve a PURL, component_id, or package name to the actual node ID."""
        if not ref:
            return ""
        # 1. Exact node match
        if self.graph is not None and self.graph.has_node(ref):
            return ref
        elif self.graph is None and ref in self._nodes:
            return ref

        # 2. ID match
        if ref in self._id_to_purl:
            return self._id_to_purl[ref]

        # 3. Name match (case-insensitive)
        purls = self._name_to_purls.get(ref.lower())
        if purls:
            return next(iter(purls))

        # Return as-is if no resolution
        return ref

    def has_edge(self, u: str, v: str) -> bool:
        """Check if an edge exists between u and v, supporting both PURL and name lookups."""
        if self.graph is not None:
            if self.graph.has_edge(u, v):
                return True

            # Try resolving u and v from names/aliases
            u_candidates = {u} | self._name_to_purls.get(u.lower(), set())
            if u in self._id_to_purl:
                u_candidates.add(self._id_to_purl[u])

            v_candidates = {v} | self._name_to_purls.get(v.lower(), set())
            if v in self._id_to_purl:
                v_candidates.add(self._id_to_purl[v])

            for u_node in u_candidates:
                for v_node in v_candidates:
                    if self.graph.has_edge(u_node, v_node):
                        return True
            return False
        else:
            # Fallback
            u_candidates = {u} | self._name_to_purls.get(u.lower(), set())
            v_candidates = {v} | self._name_to_purls.get(v.lower(), set())
            for u_node in u_candidates:
                for v_node in v_candidates:
                    if u_node in self._adj and v_node in self._adj[u_node]:
                        return True
            return False

    def number_of_nodes(self) -> int:
        """Return total number of nodes in graph."""
        if self.graph is not None:
            return self.graph.number_of_nodes()
        return len(self._nodes)

    def number_of_edges(self) -> int:
        """Return total number of edges in graph."""
        if self.graph is not None:
            return self.graph.number_of_edges()
        return sum(len(c) for c in self._adj.values())

    def get_dependents(self, purl: str) -> list[str]:
        """Get all packages that depend on the given package (predecessors)."""
        node_id = self._resolve_node_id(purl)
        if self.graph is not None:
            if self.graph.has_node(node_id):
                return list(self.graph.predecessors(node_id))
            return []
        # Fallback
        return [p for p, children in self._adj.items() if node_id in children]

    def get_dependencies_of(self, purl: str) -> list[str]:
        """Get direct dependencies of a package (successors)."""
        node_id = self._resolve_node_id(purl)
        if self.graph is not None:
            if self.graph.has_node(node_id):
                return list(self.graph.successors(node_id))
            return []
        return self._adj.get(node_id, [])

    def get_transitive_dependents(self, purl: str) -> set[str]:
        """Get all transitive dependents (ancestors in dependency tree)."""
        node_id = self._resolve_node_id(purl)
        if self.graph is not None:
            if self.graph.has_node(node_id):
                try:
                    return set(nx.ancestors(self.graph, node_id))
                except nx.NetworkXError:
                    return set()
            return set()
        # Fallback BFS
        visited = set()
        queue = [node_id]
        while queue:
            current = queue.pop(0)
            for parent in self.get_dependents(current):
                if parent not in visited:
                    visited.add(parent)
                    queue.append(parent)
        return visited

    def get_blast_radius(self, purl: str) -> dict:
        """Calculate blast radius for a vulnerable component."""
        dependents = self.get_transitive_dependents(purl)
        direct_dependents = self.get_dependents(purl)

        return {
            "component": purl,
            "direct_dependents": len(direct_dependents),
            "transitive_dependents": len(dependents),
            "affected_dependents": len(dependents),
            "affected_purls": list(dependents),
        }

    def get_all_edges(self) -> list[dict]:
        """Get all dependency edges for persistence and frontend visualization."""
        if self.graph is not None:
            return [{"parent_purl": u, "child_purl": v} for u, v in self.graph.edges()]
        edges = []
        for parent, children in self._adj.items():
            for child in children:
                edges.append({"parent_purl": parent, "child_purl": child})
        return edges
