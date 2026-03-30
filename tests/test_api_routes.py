"""
Tests for FastAPI routes — /api/query and /api/confirm.
Uses TestClient with the actual FastAPI app; stubs Neo4j driver and Anthropic.
"""

import sys
import os
import types
import unittest
from unittest.mock import MagicMock, patch

# ── Stub config ───────────────────────────────────────────────────────────────
config_stub = types.ModuleType("config")
config_stub.NEO4J_URI      = "neo4j+s://test.databases.neo4j.io"
config_stub.NEO4J_USERNAME = "neo4j"
config_stub.NEO4J_PASSWORD = "testpass"
config_stub.ANTHROPIC_KEY  = "sk-ant-test"
config_stub.NEO4J_MCP_URL  = "http://127.0.0.1:8787"
config_stub.ROCKETRIDE_URL = "http://127.0.0.1:3000"
sys.modules["config"] = config_stub

# ── Stub neo4j ────────────────────────────────────────────────────────────────
neo4j_stub = types.ModuleType("neo4j")
mock_driver = MagicMock()
neo4j_stub.GraphDatabase = MagicMock()
neo4j_stub.GraphDatabase.driver = MagicMock(return_value=mock_driver)
neo4j_stub.ManagedTransaction = MagicMock()
sys.modules["neo4j"] = neo4j_stub

# ── Stub anthropic ────────────────────────────────────────────────────────────
anthropic_stub = types.ModuleType("anthropic")
mock_anthropic_client = MagicMock()
anthropic_stub.Anthropic = MagicMock(return_value=mock_anthropic_client)
sys.modules["anthropic"] = anthropic_stub

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient


def _make_mock_session(records=None):
    mock_record = MagicMock()
    mock_record.data.return_value = {}
    session = MagicMock()
    session.run.return_value = iter(records or [])
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__  = MagicMock(return_value=False)
    return session


class TestHealthEndpoint(unittest.TestCase):
    def setUp(self):
        mock_driver.session.return_value = _make_mock_session()
        from main import app
        self.client = TestClient(app)

    def test_health_returns_ok(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})


class TestQueryEndpointCacheHit(unittest.TestCase):
    """When cache_check returns records, the endpoint must NOT call the LLM."""

    def setUp(self):
        # Fresh import to avoid state pollution between test classes
        for mod in list(sys.modules.keys()):
            if mod in ("neo4j_client", "llm", "routes.query", "routes.confirm", "main"):
                del sys.modules[mod]

        # cache_check will return a hit
        cached_record = MagicMock()
        cached_record.data.return_value = {"from_cache": True}
        session = _make_mock_session(records=[cached_record])
        mock_driver.session.return_value = session

        # LLM should not be called
        mock_anthropic_client.messages.create.reset_mock()

        from main import app
        self.client = TestClient(app)

    def test_cache_hit_returns_correct_flags(self):
        resp = self.client.post(
            "/api/query",
            json={"entity": "ua-parser-js", "type": "package"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["from_cache"])
        self.assertFalse(body["llm_called"])

    def test_cache_hit_skips_llm(self):
        self.client.post(
            "/api/query",
            json={"entity": "ua-parser-js", "type": "package"},
        )
        mock_anthropic_client.messages.create.assert_not_called()

    def test_cache_hit_includes_entity_in_response(self):
        resp = self.client.post(
            "/api/query",
            json={"entity": "ua-parser-js", "type": "package"},
        )
        body = resp.json()
        self.assertEqual(body["entity"], "ua-parser-js")
        self.assertEqual(body["entity_type"], "package")


class TestQueryEndpointCacheMissWithPaths(unittest.TestCase):
    """Cache miss + paths found -> LLM should be called."""

    def setUp(self):
        for mod in list(sys.modules.keys()):
            if mod in ("neo4j_client", "llm", "routes.query", "routes.confirm", "main"):
                del sys.modules[mod]

        # cache_check: miss (empty)
        # traverse: returns one path record
        path_record = MagicMock()
        path_record.data.return_value = {"path": {"nodes": ["pkg", "acct", "ip", "actor"]}}

        call_count = [0]
        def session_factory():
            s = _make_mock_session()
            c = call_count[0]
            call_count[0] += 1
            if c == 0:
                # cache_check -> empty
                s.run.return_value = iter([])
            else:
                # traverse queries -> return path record
                s.run.return_value = iter([path_record])
            return s

        mock_driver.session.side_effect = session_factory

        # LLM returns a narrative
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="CRITICAL: ua-parser-js is linked to APT41.")]
        mock_anthropic_client.messages.create.return_value = mock_message
        mock_anthropic_client.messages.create.reset_mock()

        from main import app
        self.client = TestClient(app)

    def tearDown(self):
        mock_driver.session.side_effect = None

    def test_cache_miss_calls_llm(self):
        self.client.post(
            "/api/query",
            json={"entity": "ua-parser-js", "type": "package"},
        )
        mock_anthropic_client.messages.create.assert_called_once()

    def test_cache_miss_returns_llm_called_true(self):
        resp = self.client.post(
            "/api/query",
            json={"entity": "ua-parser-js", "type": "package"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["from_cache"])
        self.assertTrue(body["llm_called"])

    def test_narrative_in_response(self):
        resp = self.client.post(
            "/api/query",
            json={"entity": "ua-parser-js", "type": "package"},
        )
        body = resp.json()
        self.assertIn("narrative", body)
        self.assertIn("APT41", body["narrative"])


class TestQueryEndpointEmptyGraph(unittest.TestCase):
    """Cache miss + zero paths -> LLM must NOT be called."""

    def setUp(self):
        for mod in list(sys.modules.keys()):
            if mod in ("neo4j_client", "llm", "routes.query", "routes.confirm", "main"):
                del sys.modules[mod]

        session = _make_mock_session(records=[])
        mock_driver.session.return_value = session
        mock_anthropic_client.messages.create.reset_mock()

        from main import app
        self.client = TestClient(app)

    def test_empty_graph_no_llm_call(self):
        self.client.post(
            "/api/query",
            json={"entity": "nonexistent-pkg", "type": "package"},
        )
        mock_anthropic_client.messages.create.assert_not_called()

    def test_empty_graph_returns_zero_paths(self):
        resp = self.client.post(
            "/api/query",
            json={"entity": "nonexistent-pkg", "type": "package"},
        )
        body = resp.json()
        self.assertEqual(body["paths_found"], 0)
        self.assertFalse(body["llm_called"])


class TestQueryValidation(unittest.TestCase):
    def setUp(self):
        for mod in list(sys.modules.keys()):
            if mod in ("neo4j_client", "llm", "routes.query", "routes.confirm", "main"):
                del sys.modules[mod]
        mock_driver.session.return_value = _make_mock_session()
        from main import app
        self.client = TestClient(app)

    def test_empty_entity_returns_400(self):
        resp = self.client.post(
            "/api/query",
            json={"entity": "", "type": "package"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_missing_entity_field_returns_422(self):
        resp = self.client.post("/api/query", json={"type": "package"})
        self.assertEqual(resp.status_code, 422)

    def test_default_type_is_package(self):
        # Should not crash when type is omitted — defaults to "package"
        session = _make_mock_session(records=[])
        mock_driver.session.return_value = session
        resp = self.client.post("/api/query", json={"entity": "ua-parser-js"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["entity_type"], "package")


class TestConfirmEndpoint(unittest.TestCase):
    def setUp(self):
        for mod in list(sys.modules.keys()):
            if mod in ("neo4j_client", "llm", "routes.query", "routes.confirm", "main"):
                del sys.modules[mod]
        mock_driver.session.return_value = _make_mock_session()
        from main import app
        self.client = TestClient(app)

    def test_confirm_returns_success_true(self):
        resp = self.client.post(
            "/api/confirm",
            json={"entity": "ua-parser-js", "type": "package"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["entity"], "ua-parser-js")

    def test_confirm_empty_entity_returns_400(self):
        resp = self.client.post(
            "/api/confirm",
            json={"entity": "", "type": "package"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_confirm_writes_to_neo4j(self):
        session = _make_mock_session()
        mock_driver.session.return_value = session
        self.client.post(
            "/api/confirm",
            json={"entity": "ua-parser-js", "type": "package"},
        )
        session.run.assert_called_once()
        cypher = session.run.call_args[0][0]
        self.assertIn("ConfirmedThreat", cypher)


if __name__ == "__main__":
    unittest.main(verbosity=2)
