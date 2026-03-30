"""
Tests for FastAPI routes — /api/query and /api/confirm.
Uses TestClient with the actual FastAPI app; patches neo4j_client and llm
functions directly (correct layer for route tests — not the DB driver).
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
config_stub.require = lambda key: getattr(
    config_stub,
    "ANTHROPIC_KEY" if key == "ANTHROPIC_API_KEY" else key,
)
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
from main import app

CLIENT = TestClient(app)

# ── Patch targets (module path as seen by routes/query.py) ───────────────────
CACHE_CHECK = "neo4j_client.cache_check"
TRAVERSE    = "neo4j_client.traverse"
WRITE_BACK  = "neo4j_client.write_back"
CONFIRM     = "neo4j_client.confirm"
GENERATE    = "llm.generate_narrative"
INGEST_FRAUD = "neo4j_client.ingest_fraud_signals"
JUSPAY_SUMMARY = "neo4j_client.get_juspay_summary"

EMPTY_TRAVERSAL = {"paths": [], "cross_domain": [], "paths_found": 0}
FOUND_TRAVERSAL = {
    "paths": [{"path": {"nodes": ["pkg", "acct", "ip", "actor"]}}],
    "cross_domain": [{"package": "ua-parser-js", "actor": "APT41"}],
    "paths_found": 1,
}


class TestHealthEndpoint(unittest.TestCase):
    def test_health_returns_ok(self):
        resp = CLIENT.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})


class TestQueryEndpointCacheHit(unittest.TestCase):
    """cache_check returns records → from_cache=True, LLM must NOT be called."""

    def _post(self):
        with patch(
            CACHE_CHECK,
            return_value=[{"from_cache": True, "narrative": "cached narrative"}],
        ), \
             patch(GENERATE) as mock_llm:
            resp = CLIENT.post(
                "/api/query",
                json={"entity": "ua-parser-js", "type": "package"},
            )
            return resp, mock_llm

    def test_cache_hit_returns_correct_flags(self):
        resp, _ = self._post()
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["from_cache"])
        self.assertFalse(body["llm_called"])
        self.assertEqual(body["narrative"], "cached narrative")

    def test_cache_hit_skips_llm(self):
        _, mock_llm = self._post()
        mock_llm.assert_not_called()

    def test_cache_hit_includes_entity_in_response(self):
        resp, _ = self._post()
        body = resp.json()
        self.assertEqual(body["entity"], "ua-parser-js")
        self.assertEqual(body["entity_type"], "package")

    def test_cache_hit_narrative_present(self):
        resp, _ = self._post()
        body = resp.json()
        self.assertIn("narrative", body)
        self.assertGreater(len(body["narrative"]), 0)


class TestQueryEndpointCacheMissWithPaths(unittest.TestCase):
    """Cache miss + paths found → LLM should be called."""

    def _post(self):
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="CRITICAL: ua-parser-js linked to APT41.")]
        with patch(CACHE_CHECK, return_value=None), \
             patch(TRAVERSE, return_value=FOUND_TRAVERSAL), \
             patch(WRITE_BACK), \
             patch(GENERATE, return_value="CRITICAL: ua-parser-js linked to APT41.") as mock_llm:
            resp = CLIENT.post(
                "/api/query",
                json={"entity": "ua-parser-js", "type": "package"},
            )
            return resp, mock_llm

    def test_cache_miss_calls_llm(self):
        _, mock_llm = self._post()
        mock_llm.assert_called_once()

    def test_cache_miss_returns_llm_called_true(self):
        resp, _ = self._post()
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["from_cache"])
        self.assertTrue(body["llm_called"])

    def test_narrative_in_response(self):
        resp, _ = self._post()
        body = resp.json()
        self.assertIn("narrative", body)
        self.assertIn("APT41", body["narrative"])

    def test_paths_found_count(self):
        resp, _ = self._post()
        body = resp.json()
        self.assertEqual(body["paths_found"], FOUND_TRAVERSAL["paths_found"])

    def test_llm_called_with_entity_and_traversal(self):
        """generate_narrative must receive entity, entity_type, and traversal result."""
        with patch(CACHE_CHECK, return_value=None), \
             patch(TRAVERSE, return_value=FOUND_TRAVERSAL), \
             patch(WRITE_BACK), \
             patch(GENERATE, return_value="narrative") as mock_llm:
            CLIENT.post("/api/query", json={"entity": "ua-parser-js", "type": "package"})
        call_args = mock_llm.call_args
        self.assertEqual(call_args[0][0], "ua-parser-js")
        self.assertEqual(call_args[0][1], "package")
        self.assertEqual(call_args[0][2], FOUND_TRAVERSAL)

    def test_write_back_called_after_llm(self):
        with patch(CACHE_CHECK, return_value=None), \
             patch(TRAVERSE, return_value=FOUND_TRAVERSAL), \
             patch(WRITE_BACK) as mock_wb, \
             patch(GENERATE, return_value="narrative"):
            CLIENT.post("/api/query", json={"entity": "ua-parser-js", "type": "package"})
        mock_wb.assert_called_once_with("ua-parser-js", "package", "narrative")


class TestQueryEndpointEmptyGraph(unittest.TestCase):
    """Cache miss + zero paths → LLM must NOT be called."""

    def _post(self, entity="nonexistent-pkg"):
        with patch(CACHE_CHECK, return_value=None), \
             patch(TRAVERSE, return_value=EMPTY_TRAVERSAL), \
             patch(GENERATE) as mock_llm:
            resp = CLIENT.post(
                "/api/query",
                json={"entity": entity, "type": "package"},
            )
            return resp, mock_llm

    def test_empty_graph_no_llm_call(self):
        _, mock_llm = self._post()
        mock_llm.assert_not_called()

    def test_empty_graph_returns_zero_paths(self):
        resp, _ = self._post()
        body = resp.json()
        self.assertEqual(body["paths_found"], 0)
        self.assertFalse(body["llm_called"])
        self.assertFalse(body["from_cache"])

    def test_empty_graph_narrative_explains_no_paths(self):
        resp, _ = self._post()
        narrative = resp.json()["narrative"]
        self.assertIn("No threat paths found", narrative)


class TestQueryValidation(unittest.TestCase):
    def test_empty_entity_returns_400(self):
        resp = CLIENT.post("/api/query", json={"entity": "", "type": "package"})
        self.assertEqual(resp.status_code, 400)

    def test_missing_entity_field_returns_422(self):
        resp = CLIENT.post("/api/query", json={"type": "package"})
        self.assertEqual(resp.status_code, 422)

    def test_default_type_is_package(self):
        with patch(CACHE_CHECK, return_value=None), \
             patch(TRAVERSE, return_value=EMPTY_TRAVERSAL):
            resp = CLIENT.post("/api/query", json={"entity": "ua-parser-js"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["entity_type"], "package")

    def test_whitespace_entity_returns_400(self):
        resp = CLIENT.post("/api/query", json={"entity": "   ", "type": "package"})
        self.assertEqual(resp.status_code, 400)

    def test_invalid_type_returns_422(self):
        resp = CLIENT.post("/api/query", json={"entity": "ua-parser-js", "type": "nope"})
        self.assertEqual(resp.status_code, 422)


class TestConfirmEndpoint(unittest.TestCase):
    def test_confirm_returns_success_true(self):
        with patch(CONFIRM) as mock_confirm:
            resp = CLIENT.post(
                "/api/confirm",
                json={"entity": "ua-parser-js", "type": "package"},
            )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["entity"], "ua-parser-js")

    def test_confirm_empty_entity_returns_400(self):
        resp = CLIENT.post("/api/confirm", json={"entity": "", "type": "package"})
        self.assertEqual(resp.status_code, 400)

    def test_confirm_calls_db_confirm(self):
        with patch(CONFIRM) as mock_confirm:
            CLIENT.post(
                "/api/confirm",
                json={"entity": "ua-parser-js", "type": "package"},
            )
        mock_confirm.assert_called_once_with("ua-parser-js", "package")

    def test_confirm_default_type_is_package(self):
        with patch(CONFIRM) as mock_confirm:
            resp = CLIENT.post("/api/confirm", json={"entity": "ua-parser-js"})
        self.assertEqual(resp.status_code, 200)
        mock_confirm.assert_called_once_with("ua-parser-js", "package")

    def test_confirm_ip_entity_type(self):
        with patch(CONFIRM) as mock_confirm:
            resp = CLIENT.post(
                "/api/confirm",
                json={"entity": "203.0.113.42", "type": "ip"},
            )
        self.assertEqual(resp.status_code, 200)
        mock_confirm.assert_called_once_with("203.0.113.42", "ip")

    def test_confirm_invalid_type_returns_422(self):
        resp = CLIENT.post(
            "/api/confirm",
            json={"entity": "ua-parser-js", "type": "nope"},
        )
        self.assertEqual(resp.status_code, 422)


class TestJuspayEndpoints(unittest.TestCase):
    def test_ingest_single_signal(self):
        with patch(
            INGEST_FRAUD,
            return_value={
                "ingested": 1,
                "linked_ips": 1,
                "signal_ids": ["JS-1"],
            },
        ) as mock_ingest:
            resp = CLIENT.post(
                "/api/juspay/ingest",
                json={
                    "id": "JS-1",
                    "alert_type": "account_takeover",
                    "amount": 1250,
                    "customer_ip": "203.0.113.42",
                },
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["ingested"], 1)
        normalized = mock_ingest.call_args[0][0][0]
        self.assertEqual(normalized["juspay_id"], "JS-1")
        self.assertEqual(normalized["fraud_type"], "account_takeover")
        self.assertEqual(normalized["ip_address"], "203.0.113.42")

    def test_ingest_wrapped_batch(self):
        with patch(
            INGEST_FRAUD,
            return_value={
                "ingested": 2,
                "linked_ips": 2,
                "signal_ids": ["JS-1", "JS-2"],
            },
        ) as mock_ingest:
            resp = CLIENT.post(
                "/api/juspay/ingest",
                json={
                    "signals": [
                        {
                            "juspay_id": "JS-1",
                            "fraud_type": "refund_fraud",
                            "amount": 120.5,
                            "ip_address": "203.0.113.42",
                        },
                        {
                            "transaction_id": "JS-2",
                            "signal_type": "card_not_present",
                            "transaction_amount": 800,
                            "device_ip": "203.0.113.99",
                        },
                    ]
                },
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mock_ingest.call_args[0][0]), 2)

    def test_ingest_rejects_invalid_payload(self):
        resp = CLIENT.post(
            "/api/juspay/ingest",
            json={"merchant_id": "m_123"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_juspay_summary_endpoint(self):
        with patch(
            JUSPAY_SUMMARY,
            return_value={
                "signals": 2,
                "linked_ips": 1,
                "total_amount": 5000,
                "by_type": [{"type": "account_takeover", "count": 2}],
                "actor_links": [{"actor": "APT41", "signal_count": 2}],
                "recent_signals": [{"juspay_id": "JS-1"}],
            },
        ):
            resp = CLIENT.get("/api/juspay/signals?limit=5")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["signals"], 2)

    def test_juspay_summary_limit_validation(self):
        resp = CLIENT.get("/api/juspay/signals?limit=101")
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
