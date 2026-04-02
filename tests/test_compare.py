"""
Tests for POST /api/diff/compare — entity graph comparison endpoint.

Covers:
  - All 5 entity types (package, threatactor, ip, domain, cve)
  - Full overlap (same entity both sides)
  - Zero overlap (completely disjoint graphs)
  - Partial overlap (shared nodes + exclusive nodes)
  - Link overlap and exclusive links
  - overlap_score arithmetic
  - Summary counts consistency
  - Validation: empty entity, whitespace, invalid type
  - Both graphs empty
  - One graph empty, one populated
  - Case: node present in both (deduplicated correctly in returned lists)
  - Parallel execution: get_graph called exactly twice
"""

import sys
import os
import types
import unittest
from unittest.mock import MagicMock, patch

# ── Stubs (mirror test_api_routes.py setup) ───────────────────────────────────
config_stub = types.ModuleType("config")
config_stub.NEO4J_URI      = "neo4j+s://test.databases.neo4j.io"
config_stub.NEO4J_USERNAME = "neo4j"
config_stub.NEO4J_PASSWORD = "testpass"
config_stub.ANTHROPIC_KEY  = "sk-ant-test"
config_stub.NEO4J_MCP_URL  = "http://127.0.0.1:8787"
config_stub.ROCKETRIDE_URL = "http://127.0.0.1:3000"
config_stub.require = lambda key: getattr(
    config_stub,
    "ANTHROPIC_KEY" if key == "ANTHROPIC_API_KEY" else key,
)
sys.modules["config"] = config_stub

neo4j_stub = types.ModuleType("neo4j")
mock_driver = MagicMock()
neo4j_stub.GraphDatabase = MagicMock()
neo4j_stub.GraphDatabase.driver = MagicMock(return_value=mock_driver)
neo4j_stub.ManagedTransaction = MagicMock()
sys.modules["neo4j"] = neo4j_stub

anthropic_stub = types.ModuleType("anthropic")
mock_anthropic_client = MagicMock()
anthropic_stub.Anthropic = MagicMock(return_value=mock_anthropic_client)
sys.modules["anthropic"] = anthropic_stub

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient  # noqa: E402
from main import app  # noqa: E402

CLIENT = TestClient(app)
COMPARE_URL = "/api/diff/compare"
GET_GRAPH = "neo4j_client.get_graph"

# ── Reusable graph fixtures ───────────────────────────────────────────────────

def _node(id_, type_="Package", val=5):
    return {"id": id_, "label": id_, "type": type_, "val": val}

def _link(src, tgt, rel="OPERATES"):
    return {"source": src, "target": tgt, "type": rel, "dashed": False,
            "confidence": 0.7, "source_reliability": None, "last_seen": None}

# APT41 graph: 3 IPs + actor node
GRAPH_APT41 = {
    "nodes": [
        _node("APT41", "ThreatActor", 8),
        _node("45.142.212.100", "IP"),
        _node("103.43.12.105", "IP"),
        _node("SHARED-IP", "IP"),           # shared with FIN7
    ],
    "links": [
        _link("APT41", "45.142.212.100"),
        _link("APT41", "103.43.12.105"),
        _link("APT41", "SHARED-IP"),
    ],
}

# FIN7 graph: 2 unique IPs + same SHARED-IP + actor node
GRAPH_FIN7 = {
    "nodes": [
        _node("FIN7", "ThreatActor", 8),
        _node("203.0.113.99", "IP"),
        _node("SHARED-IP", "IP"),           # shared with APT41
    ],
    "links": [
        _link("FIN7", "203.0.113.99"),
        _link("FIN7", "SHARED-IP"),
    ],
}

GRAPH_EMPTY = {"nodes": [], "links": []}


def _post(entity_a, type_a, entity_b, type_b, graph_a=GRAPH_EMPTY, graph_b=GRAPH_EMPTY):
    """Helper: post a compare request with mocked get_graph returning graph_a / graph_b."""
    def _side_effect(entity, etype):
        if entity == entity_a:
            return graph_a
        return graph_b

    with patch(GET_GRAPH, side_effect=_side_effect):
        return CLIENT.post(COMPARE_URL, json={
            "entity_a": entity_a, "type_a": type_a,
            "entity_b": entity_b, "type_b": type_b,
        })


# ── Validation tests ──────────────────────────────────────────────────────────

class TestCompareValidation(unittest.TestCase):
    """Pydantic validation and empty-input guards."""

    def test_missing_entity_a_returns_422(self):
        resp = CLIENT.post(COMPARE_URL, json={"type_a": "package", "entity_b": "b", "type_b": "package"})
        self.assertEqual(resp.status_code, 422)

    def test_missing_entity_b_returns_422(self):
        resp = CLIENT.post(COMPARE_URL, json={"entity_a": "a", "type_a": "package", "type_b": "package"})
        self.assertEqual(resp.status_code, 422)

    def test_invalid_type_a_returns_422(self):
        resp = CLIENT.post(COMPARE_URL, json={
            "entity_a": "a", "type_a": "notatype",
            "entity_b": "b", "type_b": "package",
        })
        self.assertEqual(resp.status_code, 422)

    def test_invalid_type_b_returns_422(self):
        resp = CLIENT.post(COMPARE_URL, json={
            "entity_a": "a", "type_a": "package",
            "entity_b": "b", "type_b": "notatype",
        })
        self.assertEqual(resp.status_code, 422)

    def test_empty_body_returns_422(self):
        resp = CLIENT.post(COMPARE_URL, json={})
        self.assertEqual(resp.status_code, 422)


# ── Both graphs empty ─────────────────────────────────────────────────────────

class TestCompareBothEmpty(unittest.TestCase):
    """When both entities return empty graphs, overlap = 0 and all lists empty."""

    def setUp(self):
        self.resp = _post("unknown-a", "package", "unknown-b", "package")
        self.body = self.resp.json()

    def test_status_200(self):
        self.assertEqual(self.resp.status_code, 200)

    def test_overlap_score_is_zero(self):
        self.assertEqual(self.body["overlap_score"], 0.0)

    def test_all_lists_empty(self):
        self.assertEqual(self.body["shared_nodes"], [])
        self.assertEqual(self.body["only_a"], [])
        self.assertEqual(self.body["only_b"], [])

    def test_summary_all_zeros(self):
        s = self.body["summary"]
        self.assertEqual(s["total_unique_nodes"], 0)
        self.assertEqual(s["shared_count"], 0)
        self.assertEqual(s["only_a_count"], 0)
        self.assertEqual(s["only_b_count"], 0)


# ── One-sided graph ───────────────────────────────────────────────────────────

class TestCompareOneSided(unittest.TestCase):
    """Graph A has nodes; Graph B is empty. All nodes land in only_a."""

    def setUp(self):
        g = {"nodes": [_node("APT41", "ThreatActor"), _node("1.2.3.4", "IP")],
             "links": [_link("APT41", "1.2.3.4")]}
        self.resp = _post("APT41", "threatactor", "nobody", "threatactor", graph_a=g, graph_b=GRAPH_EMPTY)
        self.body = self.resp.json()

    def test_status_200(self):
        self.assertEqual(self.resp.status_code, 200)

    def test_only_a_has_all_nodes(self):
        self.assertEqual(len(self.body["only_a"]), 2)
        self.assertEqual(self.body["only_b"], [])
        self.assertEqual(self.body["shared_nodes"], [])

    def test_overlap_score_zero(self):
        self.assertEqual(self.body["overlap_score"], 0.0)

    def test_summary_counts(self):
        s = self.body["summary"]
        self.assertEqual(s["only_a_count"], 2)
        self.assertEqual(s["only_b_count"], 0)
        self.assertEqual(s["shared_count"], 0)
        self.assertEqual(s["total_unique_nodes"], 2)


# ── Full overlap (same entity both sides) ─────────────────────────────────────

class TestCompareFullOverlap(unittest.TestCase):
    """Comparing an entity against itself → 100 % overlap."""

    def setUp(self):
        g = {"nodes": [_node("openclaw", "Package"), _node("APT41", "ThreatActor")],
             "links": [_link("openclaw", "APT41", "HAS_VULNERABILITY")]}
        self.resp = _post("openclaw", "package", "openclaw", "package", graph_a=g, graph_b=g)
        self.body = self.resp.json()

    def test_status_200(self):
        self.assertEqual(self.resp.status_code, 200)

    def test_overlap_score_is_one(self):
        self.assertEqual(self.body["overlap_score"], 1.0)

    def test_all_nodes_shared(self):
        self.assertEqual(len(self.body["shared_nodes"]), 2)
        self.assertEqual(self.body["only_a"], [])
        self.assertEqual(self.body["only_b"], [])

    def test_summary_shared_equals_total(self):
        s = self.body["summary"]
        self.assertEqual(s["shared_count"], s["total_unique_nodes"])
        self.assertEqual(s["only_a_count"], 0)
        self.assertEqual(s["only_b_count"], 0)


# ── Partial overlap ───────────────────────────────────────────────────────────

class TestComparePartialOverlap(unittest.TestCase):
    """APT41 vs FIN7 — one shared IP, rest exclusive."""

    def setUp(self):
        self.resp = _post("APT41", "threatactor", "FIN7", "threatactor",
                          graph_a=GRAPH_APT41, graph_b=GRAPH_FIN7)
        self.body = self.resp.json()

    def test_status_200(self):
        self.assertEqual(self.resp.status_code, 200)

    def test_shared_node_is_shared_ip(self):
        shared_ids = {n["id"] for n in self.body["shared_nodes"]}
        self.assertIn("SHARED-IP", shared_ids)

    def test_apt41_exclusive_nodes(self):
        only_a_ids = {n["id"] for n in self.body["only_a"]}
        self.assertIn("APT41", only_a_ids)
        self.assertIn("45.142.212.100", only_a_ids)
        self.assertIn("103.43.12.105", only_a_ids)
        self.assertNotIn("SHARED-IP", only_a_ids)

    def test_fin7_exclusive_nodes(self):
        only_b_ids = {n["id"] for n in self.body["only_b"]}
        self.assertIn("FIN7", only_b_ids)
        self.assertIn("203.0.113.99", only_b_ids)
        self.assertNotIn("SHARED-IP", only_b_ids)

    def test_overlap_score_in_range(self):
        score = self.body["overlap_score"]
        self.assertGreater(score, 0.0)
        self.assertLess(score, 1.0)

    def test_overlap_score_arithmetic(self):
        # GRAPH_APT41 has 4 nodes, GRAPH_FIN7 has 3, SHARED-IP is common
        # → 6 unique nodes, 1 shared → 1/6 ≈ 0.1667
        self.assertAlmostEqual(self.body["overlap_score"], round(1 / 6, 4), places=4)

    def test_summary_counts_add_up(self):
        s = self.body["summary"]
        self.assertEqual(
            s["shared_count"] + s["only_a_count"] + s["only_b_count"],
            s["total_unique_nodes"],
        )

    def test_shared_nodes_not_in_exclusive_lists(self):
        shared_ids = {n["id"] for n in self.body["shared_nodes"]}
        only_a_ids = {n["id"] for n in self.body["only_a"]}
        only_b_ids = {n["id"] for n in self.body["only_b"]}
        self.assertEqual(shared_ids & only_a_ids, set())
        self.assertEqual(shared_ids & only_b_ids, set())

    def test_partition_covers_all_nodes(self):
        shared_ids = {n["id"] for n in self.body["shared_nodes"]}
        only_a_ids = {n["id"] for n in self.body["only_a"]}
        only_b_ids = {n["id"] for n in self.body["only_b"]}
        all_returned = shared_ids | only_a_ids | only_b_ids
        self.assertEqual(len(all_returned), self.body["summary"]["total_unique_nodes"])


# ── Link overlap ──────────────────────────────────────────────────────────────

class TestCompareLinkOverlap(unittest.TestCase):
    """Graphs sharing a link → that link appears in shared_links."""

    SHARED_LINK_GRAPH_A = {
        "nodes": [_node("A"), _node("B"), _node("C")],
        "links": [_link("A", "B"), _link("B", "C")],
    }
    SHARED_LINK_GRAPH_B = {
        "nodes": [_node("B"), _node("C"), _node("D")],
        "links": [_link("B", "C"), _link("C", "D")],  # B-C is shared
    }

    def setUp(self):
        self.resp = _post("pkg-a", "package", "pkg-b", "package",
                          graph_a=self.SHARED_LINK_GRAPH_A,
                          graph_b=self.SHARED_LINK_GRAPH_B)
        self.body = self.resp.json()

    def test_shared_links_present(self):
        self.assertEqual(self.body["summary"]["shared_links_count"], 1)

    def test_shared_link_endpoints(self):
        link = self.body["shared_links"][0]
        endpoints = {link["source"], link["target"]}
        self.assertEqual(endpoints, {"B", "C"})

    def test_only_a_link_present(self):
        self.assertEqual(self.body["summary"]["only_a_links_count"], 1)

    def test_only_b_link_present(self):
        self.assertEqual(self.body["summary"]["only_b_links_count"], 1)

    def test_total_unique_links(self):
        # A-B, B-C (shared), C-D → 3 unique
        self.assertEqual(self.body["summary"]["total_unique_links"], 3)


# ── All entity types accepted ─────────────────────────────────────────────────

class TestCompareAllEntityTypes(unittest.TestCase):
    """Endpoint must accept every valid EntityType enum value."""

    CASES = [
        ("openclaw", "package", "event-stream", "package"),
        ("APT41", "threatactor", "FIN7", "threatactor"),
        ("45.142.212.100", "ip", "203.0.113.42", "ip"),
        ("malware.ru", "domain", "update-service.net", "domain"),
        ("CVE-2021-44228", "cve", "CVE-2019-11340", "cve"),
        ("juspay-001", "fraudsignal", "juspay-002", "fraudsignal"),
    ]

    def test_all_types_return_200(self):
        for entity_a, type_a, entity_b, type_b in self.CASES:
            with self.subTest(type=type_a):
                resp = _post(entity_a, type_a, entity_b, type_b)
                self.assertEqual(resp.status_code, 200,
                                 f"Expected 200 for type={type_a}, got {resp.status_code}")

    def test_all_types_have_expected_keys(self):
        required_keys = {
            "shared_nodes", "only_a", "only_b",
            "shared_links", "only_a_links", "only_b_links",
            "overlap_score", "summary",
        }
        for entity_a, type_a, entity_b, type_b in self.CASES:
            with self.subTest(type=type_a):
                body = _post(entity_a, type_a, entity_b, type_b).json()
                self.assertTrue(required_keys.issubset(body.keys()),
                                f"Missing keys for type={type_a}: {required_keys - body.keys()}")


# ── get_graph called twice ────────────────────────────────────────────────────

class TestCompareCallsGetGraphTwice(unittest.TestCase):
    """The route must call get_graph exactly once per entity."""

    def test_get_graph_called_twice(self):
        with patch(GET_GRAPH, return_value=GRAPH_EMPTY) as mock_gg:
            CLIENT.post(COMPARE_URL, json={
                "entity_a": "APT41", "type_a": "threatactor",
                "entity_b": "FIN7",  "type_b": "threatactor",
            })
        self.assertEqual(mock_gg.call_count, 2)

    def test_get_graph_called_with_correct_entities(self):
        calls = []
        def _side(entity, etype):
            calls.append((entity, etype))
            return GRAPH_EMPTY

        with patch(GET_GRAPH, side_effect=_side):
            CLIENT.post(COMPARE_URL, json={
                "entity_a": "APT41", "type_a": "threatactor",
                "entity_b": "FIN7",  "type_b": "threatactor",
            })
        entities = {c[0] for c in calls}
        self.assertIn("APT41", entities)
        self.assertIn("FIN7", entities)

    def test_get_graph_called_with_correct_type(self):
        types_seen = []
        def _side(entity, etype):
            types_seen.append(etype)
            return GRAPH_EMPTY

        with patch(GET_GRAPH, side_effect=_side):
            CLIENT.post(COMPARE_URL, json={
                "entity_a": "openclaw", "type_a": "package",
                "entity_b": "event-stream", "type_b": "package",
            })
        self.assertTrue(all(t == "package" for t in types_seen),
                        f"Unexpected types: {types_seen}")


# ── Response shape ────────────────────────────────────────────────────────────

class TestCompareResponseShape(unittest.TestCase):
    """Each returned node must have id/label/type; summary must have all keys."""

    SUMMARY_KEYS = {
        "total_unique_nodes", "shared_count", "only_a_count", "only_b_count",
        "total_unique_links", "shared_links_count", "only_a_links_count", "only_b_links_count",
    }

    def setUp(self):
        self.resp = _post("APT41", "threatactor", "FIN7", "threatactor",
                          graph_a=GRAPH_APT41, graph_b=GRAPH_FIN7)
        self.body = self.resp.json()

    def test_summary_has_all_keys(self):
        self.assertTrue(self.SUMMARY_KEYS.issubset(self.body["summary"].keys()))

    def test_nodes_have_id_label_type(self):
        all_nodes = (
            self.body["shared_nodes"]
            + self.body["only_a"]
            + self.body["only_b"]
        )
        for node in all_nodes:
            with self.subTest(node=node.get("id")):
                self.assertIn("id", node)
                self.assertIn("label", node)
                self.assertIn("type", node)

    def test_overlap_score_between_0_and_1(self):
        score = self.body["overlap_score"]
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_links_have_source_and_target(self):
        all_links = (
            self.body["shared_links"]
            + self.body["only_a_links"]
            + self.body["only_b_links"]
        )
        for link in all_links:
            with self.subTest(link=link):
                self.assertIn("source", link)
                self.assertIn("target", link)


# ── Cross-type comparison (valid but unusual) ─────────────────────────────────

class TestCompareCrossType(unittest.TestCase):
    """
    The API accepts mismatched types if the caller explicitly sets both.
    This isn't blocked server-side; the frontend prevents it, but the backend
    should still return 200 without crashing.
    """

    def test_package_vs_ip_returns_200(self):
        resp = _post("openclaw", "package", "45.142.212.100", "ip")
        self.assertEqual(resp.status_code, 200)

    def test_threatactor_vs_cve_returns_200(self):
        resp = _post("APT41", "threatactor", "CVE-2021-44228", "cve")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
