"""Agent 5 TDD contract: graph store and exporters."""

from __future__ import annotations

from pathlib import Path

import pytest

from specter.graph.exporter import MALTEGO_MAP, GraphExporter
from specter.graph.store import EDGE_TYPES, NODE_TYPES, GraphStore
from specter.models.person import PersonProfile, PhoneIntel, SocialPresence


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store() -> GraphStore:
    return GraphStore()


@pytest.fixture
def persistent_store(tmp_path: Path) -> GraphStore:
    return GraphStore(db_path=tmp_path / "graph.db")


@pytest.fixture
def exporter() -> GraphExporter:
    return GraphExporter()


def make_profile(**kwargs) -> PersonProfile:
    return PersonProfile(**kwargs)


# ===========================================================================
# GraphStore — nodes
# ===========================================================================


class TestGraphStoreNodes:
    def test_add_person_node(self, store: GraphStore):
        nid = store.add_node("Person", "target-001")
        assert store.get_node(nid) is not None
        assert store.get_node(nid)["node_type"] == "Person"

    def test_add_email_node(self, store: GraphStore):
        nid = store.add_node("Email", "jane@example.com")
        data = store.get_node(nid)
        assert data is not None
        assert data["value"] == "jane@example.com"

    def test_unknown_node_type_raises(self, store: GraphStore):
        with pytest.raises(ValueError):
            store.add_node("Wallet", "0xABCD")

    def test_duplicate_node_merged_not_duplicated(self, store: GraphStore):
        store.add_node("Email", "jane@example.com", source="hibp")
        store.add_node("Email", "jane@example.com", source="intelx")
        assert store.node_count() == 1
        data = store.get_node(store._nid("Email", "jane@example.com"))
        assert data is not None
        assert data["source"] == "intelx"  # updated

    def test_case_insensitive_deduplication(self, store: GraphStore):
        store.add_node("Email", "Jane@Example.COM")
        store.add_node("Email", "jane@example.com")
        assert store.node_count() == 1

    def test_all_node_types_accepted(self, store: GraphStore):
        for ntype in NODE_TYPES:
            store.add_node(ntype, f"test-{ntype}")
        assert store.node_count() == len(NODE_TYPES)


# ===========================================================================
# GraphStore — edges
# ===========================================================================


class TestGraphStoreEdges:
    def test_add_edge(self, store: GraphStore):
        p = store.add_node("Person", "t1")
        e = store.add_node("Email", "a@b.com")
        store.add_edge(p, e, "HAS_EMAIL")
        assert store.edge_count() == 1

    def test_unknown_edge_type_raises(self, store: GraphStore):
        p = store.add_node("Person", "t1")
        e = store.add_node("Email", "a@b.com")
        with pytest.raises(ValueError):
            store.add_edge(p, e, "KNOWS")

    def test_all_edge_types_accepted(self, store: GraphStore):
        nodes = [store.add_node("Person", f"n{i}") for i in range(len(EDGE_TYPES))]
        for i, etype in enumerate(EDGE_TYPES):
            store.add_edge(nodes[i], nodes[(i + 1) % len(nodes)], etype)
        assert store.edge_count() == len(EDGE_TYPES)


# ===========================================================================
# GraphStore — profile ingestion
# ===========================================================================


class TestGraphStoreMergeProfile:
    def test_merge_profile_creates_nodes(self, store: GraphStore):
        profile = make_profile(
            emails=["jane@example.com"],
            locations=["Miami, FL"],
            social_presence=[SocialPresence(platform="twitter", username="jdoe")],
        )
        store.merge_profile("target-001", profile)
        # Person + Email + Location + Username + Platform = 5 nodes
        assert store.node_count() == 5

    def test_merge_profile_creates_edges(self, store: GraphStore):
        profile = make_profile(
            emails=["jane@example.com"],
            phone_intel=[PhoneIntel(number="+15550001111")],
        )
        store.merge_profile("target-001", profile)
        assert store.edge_count() >= 2

    def test_store_retrieves_by_target_id(self, store: GraphStore):
        profile = make_profile(emails=["x@example.com"])
        store.merge_profile("target-002", profile)
        sub = store.subgraph_for_target("target-002")
        node_types = {d["node_type"] for _, d in sub.nodes(data=True)}
        assert "Person" in node_types
        assert "Email" in node_types

    def test_unknown_target_returns_empty_subgraph(self, store: GraphStore):
        sub = store.subgraph_for_target("nonexistent")
        assert sub.number_of_nodes() == 0

    def test_graph_merges_duplicate_nodes_across_profiles(self, store: GraphStore):
        """Two profiles sharing an email should produce only one Email node."""
        p1 = make_profile(emails=["shared@example.com"])
        p2 = make_profile(emails=["shared@example.com"])
        store.merge_profile("target-A", p1)
        store.merge_profile("target-B", p2)
        email_nodes = [
            nid for nid, d in store.graph().nodes(data=True)
            if d.get("node_type") == "Email"
        ]
        assert len(email_nodes) == 1


# ===========================================================================
# GraphStore — SQLite persistence
# ===========================================================================


class TestGraphStorePersistence:
    def test_save_and_load(self, persistent_store: GraphStore, tmp_path: Path):
        profile = make_profile(emails=["persist@example.com"])
        persistent_store.merge_profile("t1", profile)
        persistent_store.save("t1")

        store2 = GraphStore(db_path=tmp_path / "graph.db")
        assert store2.load("t1") is True
        assert store2.node_count() >= 2

    def test_load_nonexistent_returns_false(self, persistent_store: GraphStore):
        assert persistent_store.load("no-such-target") is False


# ===========================================================================
# GraphExporter
# ===========================================================================


class TestGraphExporter:
    def _populated_store(self) -> GraphStore:
        store = GraphStore()
        profile = make_profile(
            emails=["jane@example.com"],
            locations=["Miami, FL"],
            social_presence=[SocialPresence(platform="twitter", username="jdoe")],
        )
        store.merge_profile("target-001", profile)
        return store

    def test_exporter_produces_valid_graphml(self, exporter: GraphExporter):
        store = self._populated_store()
        graphml = exporter.export_graphml(store.graph())
        assert "<?xml" in graphml or "<graphml" in graphml
        assert "node" in graphml

    def test_graphml_contains_node_types(self, exporter: GraphExporter):
        store = self._populated_store()
        graphml = exporter.export_graphml(store.graph())
        assert "Person" in graphml
        assert "Email" in graphml

    def test_exporter_maltego_format_valid(self, exporter: GraphExporter):
        store = self._populated_store()
        xml = exporter.export_maltego(store.graph())
        assert "MaltegoMessage" in xml
        assert "maltego.Person" in xml
        assert "maltego.EmailAddress" in xml

    def test_exporter_maps_all_entity_types(self, exporter: GraphExporter):
        store = GraphStore()
        for ntype in MALTEGO_MAP:
            store.add_node(ntype, f"test-{ntype}")
        xml = exporter.export_maltego(store.graph())
        for maltego_type in MALTEGO_MAP.values():
            assert maltego_type in xml, f"{maltego_type} missing from Maltego export"

    def test_maltego_map_covers_all_node_types(self):
        """Every node type in the store has a Maltego mapping."""
        missing = NODE_TYPES - set(MALTEGO_MAP.keys())
        assert not missing, f"Node types without Maltego mapping: {missing}"
