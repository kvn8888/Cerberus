"""
Tests for neo4j_client.py — entity routing logic and Cypher template rendering.
All tests are offline (no DB connection required).
"""

import sys
import os
import types
import unittest
from unittest.mock import MagicMock, patch

# ── Stub out config and neo4j before importing the module ─────────────────────
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
neo4j_stub.GraphDatabase = MagicMock()
neo4j_stub.GraphDatabase.driver = MagicMock(return_value=MagicMock())
neo4j_stub.ManagedTransaction = MagicMock()
sys.modules["neo4j"] = neo4j_stub

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import neo4j_client as db


# ── Helper: build a mock session that returns specific records ─────────────────
def _make_session(records=None):
    """
    records=None  → default to one generic record (non-empty result)
    records=[]    → empty result
    records=[r,…] → those specific records
    """
    mock_record = MagicMock()
    mock_record.data.return_value = {"path": {}}
    default = [mock_record] if records is None else records
    session = MagicMock()
    session.run.return_value = iter(default)
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__  = MagicMock(return_value=False)
    return session


def _mock_driver(session):
    """Return a driver mock whose .session() context manager yields `session`."""
    driver = MagicMock()
    driver.session.return_value = session
    return driver


class TestEntityRouting(unittest.TestCase):
    """_entity_label and _entity_key must return correct Neo4j identifiers."""

    def test_package_label(self):
        self.assertEqual(db._entity_label("package"), "Package")

    def test_package_key(self):
        self.assertEqual(db._entity_key("package"), "name")

    def test_ip_label(self):
        self.assertEqual(db._entity_label("ip"), "IP")

    def test_ip_key(self):
        self.assertEqual(db._entity_key("ip"), "address")

    def test_domain_label_and_key(self):
        self.assertEqual(db._entity_label("domain"), "Domain")
        self.assertEqual(db._entity_key("domain"), "name")

    def test_cve_label(self):
        self.assertEqual(db._entity_label("cve"), "CVE")
        self.assertEqual(db._entity_key("cve"), "id")

    def test_threatactor_label(self):
        self.assertEqual(db._entity_label("threatactor"), "ThreatActor")
        self.assertEqual(db._entity_key("threatactor"), "name")

    def test_fraudsignal_label_and_key(self):
        self.assertEqual(db._entity_label("fraudsignal"), "FraudSignal")
        self.assertEqual(db._entity_key("fraudsignal"), "juspay_id")

    def test_case_insensitive(self):
        self.assertEqual(db._entity_label("PACKAGE"), "Package")
        self.assertEqual(db._entity_label("IP"), "IP")
        self.assertEqual(db._entity_label("Package"), "Package")

    def test_unknown_type_defaults(self):
        label = db._entity_label("unknown_type")
        key   = db._entity_key("unknown_type")
        self.assertIsInstance(label, str)
        self.assertIsInstance(key, str)


class TestCacheCheckCypher(unittest.TestCase):
    """cache_check should call run() with Cypher that uses the correct label/key."""

    def _run(self, entity, entity_type, records=None):
        session = _make_session(records)
        with patch.object(db, "_driver", _mock_driver(session)):
            db.cache_check(entity, entity_type)
        return session.run.call_args

    def test_package_cache_check_uses_correct_label(self):
        args, kwargs = self._run("ua-parser-js", "package")
        cypher = args[0]
        self.assertIn("Package", cypher)
        self.assertIn("name", cypher)
        self.assertIn("confirmed", cypher)

    def test_ip_cache_check_uses_address_key(self):
        args, kwargs = self._run("203.0.113.42", "ip")
        cypher = args[0]
        self.assertIn("IP", cypher)
        self.assertIn("address", cypher)

    def test_cache_check_returns_none_on_empty_result(self):
        session = _make_session(records=[])
        with patch.object(db, "_driver", _mock_driver(session)):
            result = db.cache_check("ua-parser-js", "package")
        self.assertIsNone(result)

    def test_cache_check_returns_records_on_hit(self):
        mock_record = MagicMock()
        mock_record.data.return_value = {"from_cache": True}
        session = _make_session(records=[mock_record])
        with patch.object(db, "_driver", _mock_driver(session)):
            result = db.cache_check("ua-parser-js", "package")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["from_cache"], True)


class TestTraverse(unittest.TestCase):
    """traverse() should pick the right Cypher query for each entity type."""

    def test_package_traversal_runs_two_queries(self):
        """Package traversal runs both shortestPath and cross-domain queries."""
        session = _make_session()
        with patch.object(db, "_driver", _mock_driver(session)):
            db.traverse("ua-parser-js", "package")
        self.assertEqual(session.run.call_count, 2)

    def test_package_traversal_uses_name_property(self):
        session = _make_session()
        with patch.object(db, "_driver", _mock_driver(session)):
            db.traverse("ua-parser-js", "package")
        first_cypher = session.run.call_args_list[0][0][0]
        self.assertIn("Package", first_cypher)

    def test_ip_traversal_runs_one_query(self):
        session = _make_session()
        with patch.object(db, "_driver", _mock_driver(session)):
            db.traverse("203.0.113.42", "ip")
        self.assertEqual(session.run.call_count, 1)

    def test_ip_traversal_uses_address_property(self):
        session = _make_session()
        with patch.object(db, "_driver", _mock_driver(session)):
            db.traverse("203.0.113.42", "ip")
        cypher = session.run.call_args_list[0][0][0]
        self.assertIn("IP", cypher)
        self.assertIn("address", cypher)

    def test_traverse_result_structure(self):
        session = _make_session()
        with patch.object(db, "_driver", _mock_driver(session)):
            result = db.traverse("ua-parser-js", "package")
        self.assertIn("paths", result)
        self.assertIn("cross_domain", result)
        self.assertIn("paths_found", result)
        self.assertIsInstance(result["paths_found"], int)

    def test_traverse_empty_graph_returns_zero_paths(self):
        session = _make_session(records=[])
        with patch.object(db, "_driver", _mock_driver(session)):
            result = db.traverse("nonexistent", "package")
        self.assertEqual(result["paths_found"], 0)


class TestConfirmCypher(unittest.TestCase):
    """confirm() and write_back() should run Cypher with the expected tokens."""

    def test_confirm_sets_confirmed_flag(self):
        session = _make_session()
        with patch.object(db, "_driver", _mock_driver(session)):
            db.confirm("ua-parser-js", "package")
        cypher = session.run.call_args[0][0]
        self.assertIn("ConfirmedThreat", cypher)
        self.assertIn("r.confirmed", cypher)
        self.assertIn("confirmed_at", cypher)

    def test_confirm_uses_correct_label(self):
        session = _make_session()
        with patch.object(db, "_driver", _mock_driver(session)):
            db.confirm("203.0.113.42", "ip")
        cypher = session.run.call_args[0][0]
        self.assertIn("IP", cypher)

    def test_write_back_sets_last_analyzed(self):
        session = _make_session()
        with patch.object(db, "_driver", _mock_driver(session)):
            db.write_back("ua-parser-js", "package", "narrative")
        cypher = session.run.call_args[0][0]
        self.assertIn("last_analyzed", cypher)
        self.assertIn("cached_narrative", cypher)

    def test_write_back_passes_narrative_fields(self):
        session = _make_session()
        with patch.object(db, "_driver", _mock_driver(session)):
            db.write_back("ua-parser-js", "package", "narrative")
        kwargs = session.run.call_args[1]
        self.assertEqual(kwargs.get("narrative"), "narrative")
        self.assertIn("narrative_hash", kwargs)

    def test_confirm_passes_entity_value(self):
        session = _make_session()
        with patch.object(db, "_driver", _mock_driver(session)):
            db.confirm("ua-parser-js", "package")
        kwargs = session.run.call_args[1]
        self.assertEqual(kwargs.get("value"), "ua-parser-js")


if __name__ == "__main__":
    unittest.main(verbosity=2)
