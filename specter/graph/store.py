"""NetworkX-backed entity graph with optional SQLite persistence."""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import networkx as nx

from specter.models.person import PersonProfile

logger = logging.getLogger(__name__)

NODE_TYPES = frozenset({
    "Person", "Email", "Username", "Phone", "Platform",
    "Domain", "IP", "Location", "Organization", "Image",
})

EDGE_TYPES = frozenset({
    "HAS_EMAIL", "HAS_USERNAME", "HAS_PHONE",
    "PRESENT_ON", "LINKED_TO", "CIRCLE_MEMBER",
    "TARGETING", "EXPOSED_IN", "LOCATED_AT",
})


class GraphStore:
    """In-memory NetworkX MultiDiGraph with optional SQLite persistence.

    Nodes are identified by ``<NodeType>:<normalised_value>`` keys.
    Adding a node that already exists merges attributes rather than replacing.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._db_path = Path(db_path) if db_path else None
        if self._db_path:
            self._init_db()

    # ------------------------------------------------------------------
    # Node / edge operations
    # ------------------------------------------------------------------

    def _nid(self, node_type: str, value: str) -> str:
        return f"{node_type}:{value.lower().strip()}"

    def add_node(self, node_type: str, value: str, **attrs) -> str:
        """Add or merge a node. Returns the node ID."""
        if node_type not in NODE_TYPES:
            raise ValueError(f"Unknown node type '{node_type}'. Valid: {sorted(NODE_TYPES)}")
        nid = self._nid(node_type, value)
        if nid in self._graph:
            self._graph.nodes[nid].update(attrs)  # merge
        else:
            self._graph.add_node(nid, node_type=node_type, value=value, **attrs)
        return nid

    def add_edge(self, src: str, dst: str, edge_type: str, **attrs) -> None:
        """Add a directed edge between two node IDs."""
        if edge_type not in EDGE_TYPES:
            raise ValueError(f"Unknown edge type '{edge_type}'. Valid: {sorted(EDGE_TYPES)}")
        self._graph.add_edge(src, dst, edge_type=edge_type, **attrs)

    def get_node(self, node_id: str) -> dict | None:
        """Return node attributes or None if not present."""
        if node_id not in self._graph:
            return None
        return dict(self._graph.nodes[node_id])

    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def graph(self) -> nx.MultiDiGraph:
        """Direct access to the underlying NetworkX graph."""
        return self._graph

    # ------------------------------------------------------------------
    # Profile ingestion
    # ------------------------------------------------------------------

    def merge_profile(self, target_id: str, profile: PersonProfile) -> str:
        """Populate the graph from a PersonProfile. Returns the person node ID."""
        person_id = self.add_node("Person", target_id, target_id=target_id)

        for email in profile.emails:
            email_id = self.add_node("Email", email)
            self.add_edge(person_id, email_id, "HAS_EMAIL")

        for pi in profile.phone_intel:
            phone_id = self.add_node(
                "Phone", pi.number,
                carrier=pi.carrier or "",
                region=pi.region or "",
            )
            self.add_edge(person_id, phone_id, "HAS_PHONE")

        for sp in profile.social_presence:
            uname_id = self.add_node("Username", sp.username, platform=sp.platform)
            plat_id = self.add_node("Platform", sp.platform)
            self.add_edge(person_id, uname_id, "HAS_USERNAME")
            self.add_edge(uname_id, plat_id, "PRESENT_ON")

        for loc in profile.locations:
            loc_id = self.add_node("Location", loc)
            self.add_edge(person_id, loc_id, "LOCATED_AT")

        for emp in profile.employers:
            org_id = self.add_node("Organization", emp)
            self.add_edge(person_id, org_id, "LINKED_TO")

        return person_id

    def subgraph_for_target(self, target_id: str) -> nx.MultiDiGraph:
        """Return all nodes reachable from the target's Person node."""
        person_id = self._nid("Person", target_id)
        if person_id not in self._graph:
            return nx.MultiDiGraph()
        reachable = nx.single_source_shortest_path_length(
            self._graph.to_undirected(as_view=True), person_id
        )
        return self._graph.subgraph(reachable.keys()).copy()

    # ------------------------------------------------------------------
    # SQLite persistence
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        assert self._db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_state (
                    target_id TEXT PRIMARY KEY,
                    graph_json TEXT NOT NULL,
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        assert self._db_path
        conn = sqlite3.connect(self._db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def save(self, target_id: str) -> None:
        """Serialise current graph to SQLite (node-link format)."""
        if not self._db_path:
            return
        data = nx.node_link_data(self._graph)
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO graph_state (target_id, graph_json) VALUES (?, ?)",
                (target_id, json.dumps(data, default=str)),
            )

    def load(self, target_id: str) -> bool:
        """Load graph state for a target from SQLite. Returns True if found."""
        if not self._db_path:
            return False
        with self._conn() as conn:
            row = conn.execute(
                "SELECT graph_json FROM graph_state WHERE target_id = ?", (target_id,)
            ).fetchone()
        if not row:
            return False
        self._graph = nx.node_link_graph(json.loads(row[0]))
        return True
