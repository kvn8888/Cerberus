"""
Tests for data import scripts — parsing logic, data integrity, Cypher shapes.
All tests are offline (no DB connection or network required).
"""

import sys
import os
import types
import unittest
from unittest.mock import MagicMock, patch

# ── Stub out neo4j before any import ─────────────────────────────────────────
neo4j_stub = types.ModuleType("neo4j")
mock_driver = MagicMock()
neo4j_stub.GraphDatabase = MagicMock()
neo4j_stub.GraphDatabase.driver = MagicMock(return_value=mock_driver)
sys.modules["neo4j"] = neo4j_stub

# ── Stub dotenv ───────────────────────────────────────────────────────────────
dotenv_stub = types.ModuleType("dotenv")
dotenv_stub.load_dotenv = MagicMock()
sys.modules["dotenv"] = dotenv_stub

scripts_dir = os.path.join(os.path.dirname(__file__), "..", "scripts")
sys.path.insert(0, scripts_dir)

os.environ.setdefault("NEO4J_URI",      "neo4j+s://test")
os.environ.setdefault("NEO4J_USERNAME", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "testpass")


# ─────────────────────────────────────────────────────────────────────────────
# import_mitre tests
# ─────────────────────────────────────────────────────────────────────────────
class TestMitreParser(unittest.TestCase):

    SAMPLE_BUNDLE = {
        "objects": [
            # A valid technique
            {
                "type": "attack-pattern",
                "id": "attack-pattern--001",
                "name": "Spearphishing Attachment",
                "revoked": False,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1566.001"}
                ],
                "kill_chain_phases": [{"phase_name": "initial-access"}],
            },
            # A revoked technique — should be skipped
            {
                "type": "attack-pattern",
                "id": "attack-pattern--002",
                "name": "Old Technique",
                "revoked": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
                "kill_chain_phases": [],
            },
            # A threat actor group
            {
                "type": "intrusion-set",
                "id": "intrusion-set--001",
                "name": "APT41",
                "revoked": False,
                "aliases": ["Winnti", "Barium"],
            },
            # A revoked group — should be skipped
            {
                "type": "intrusion-set",
                "id": "intrusion-set--002",
                "name": "OldGroup",
                "revoked": True,
                "aliases": [],
            },
            # A uses relationship
            {
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--001",
                "target_ref": "attack-pattern--001",
            },
            # A non-uses relationship — should be ignored
            {
                "type": "relationship",
                "relationship_type": "mitigates",
                "source_ref": "intrusion-set--001",
                "target_ref": "attack-pattern--001",
            },
        ]
    }

    def setUp(self):
        import import_mitre
        self.m = import_mitre

    def test_parse_technique_count(self):
        techniques, actors, uses, stix_tech, stix_actor = self.m.parse_bundle(self.SAMPLE_BUNDLE)
        self.assertEqual(len(techniques), 1)

    def test_revoked_technique_excluded(self):
        techniques, *_ = self.m.parse_bundle(self.SAMPLE_BUNDLE)
        ids = [t["mitre_id"] for t in techniques]
        self.assertNotIn("T9999", ids)

    def test_technique_fields(self):
        techniques, *_ = self.m.parse_bundle(self.SAMPLE_BUNDLE)
        t = techniques[0]
        self.assertEqual(t["mitre_id"], "T1566.001")
        self.assertEqual(t["name"], "Spearphishing Attachment")
        self.assertEqual(t["tactic"], "initial-access")

    def test_actor_count(self):
        _, actors, *_ = self.m.parse_bundle(self.SAMPLE_BUNDLE)
        self.assertEqual(len(actors), 1)

    def test_revoked_actor_excluded(self):
        _, actors, *_ = self.m.parse_bundle(self.SAMPLE_BUNDLE)
        names = [a["name"] for a in actors]
        self.assertNotIn("OldGroup", names)

    def test_actor_aliases(self):
        _, actors, *_ = self.m.parse_bundle(self.SAMPLE_BUNDLE)
        a = actors[0]
        self.assertEqual(a["name"], "APT41")
        self.assertIn("Winnti", a["aliases"])

    def test_uses_relationship_count(self):
        _, _, uses, *_ = self.m.parse_bundle(self.SAMPLE_BUNDLE)
        self.assertEqual(len(uses), 1)

    def test_uses_relationship_source_and_target(self):
        _, _, uses, *_ = self.m.parse_bundle(self.SAMPLE_BUNDLE)
        src, tgt = uses[0]
        self.assertEqual(src, "intrusion-set--001")
        self.assertEqual(tgt, "attack-pattern--001")

    def test_non_uses_relationship_excluded(self):
        _, _, uses, *_ = self.m.parse_bundle(self.SAMPLE_BUNDLE)
        self.assertEqual(len(uses), 1)   # only the 'uses' one


# ─────────────────────────────────────────────────────────────────────────────
# import_cve tests
# ─────────────────────────────────────────────────────────────────────────────
class TestCveData(unittest.TestCase):

    def setUp(self):
        import import_cve
        self.m = import_cve

    def test_seed_cves_count(self):
        self.assertGreaterEqual(len(self.m.SEED_CVES), 40)

    def test_demo_cve_present(self):
        ids = [row[0] for row in self.m.SEED_CVES]
        self.assertIn("CVE-2021-27292", ids)

    def test_all_cves_have_required_fields(self):
        for row in self.m.SEED_CVES:
            cve_id, severity, cvss_score, description, pkg, actor = row
            self.assertRegex(cve_id, r"CVE-\d{4}-\d{4,7}", f"Bad CVE ID: {cve_id}")
            self.assertIn(severity, {"CRITICAL", "HIGH", "MEDIUM", "LOW"})
            self.assertIsInstance(cvss_score, float)
            self.assertGreater(len(description), 10)

    def test_cvss_scores_in_range(self):
        for row in self.m.SEED_CVES:
            _, _, cvss_score, *_ = row
            self.assertGreaterEqual(cvss_score, 0.0)
            self.assertLessEqual(cvss_score, 10.0)

    def test_ua_parser_js_linked_to_correct_cve(self):
        for row in self.m.SEED_CVES:
            cve_id, _, _, _, pkg, _ = row
            if cve_id == "CVE-2021-27292":
                self.assertEqual(pkg, "ua-parser-js")
                break


# ─────────────────────────────────────────────────────────────────────────────
# import_npm tests
# ─────────────────────────────────────────────────────────────────────────────
class TestNpmData(unittest.TestCase):

    def setUp(self):
        import import_npm
        self.m = import_npm

    def test_package_count(self):
        self.assertGreaterEqual(len(self.m.PACKAGES), 25)

    def test_demo_package_present(self):
        names = [p[0] for p in self.m.PACKAGES]
        self.assertIn("ua-parser-js", names)

    def test_ua_parser_js_fields(self):
        pkg = next(p for p in self.m.PACKAGES if p[0] == "ua-parser-js")
        name, version, registry, risk_score, publisher, _ = pkg
        self.assertEqual(version, "0.7.29")
        self.assertEqual(registry, "npm")
        self.assertEqual(publisher, "ART-BY-FAISAL")
        self.assertGreater(risk_score, 8.0)

    def test_all_packages_have_registry(self):
        for p in self.m.PACKAGES:
            self.assertIn(p[2], {"npm", "pypi"}, f"{p[0]} has invalid registry")

    def test_risk_scores_in_range(self):
        for p in self.m.PACKAGES:
            self.assertGreaterEqual(p[3], 0.0)
            self.assertLessEqual(p[3], 10.0)

    def test_depends_on_entries_reference_known_packages(self):
        known_names = {p[0] for p in self.m.PACKAGES}
        for dep, dependency in self.m.DEPENDS_ON:
            # At least one side should be a known package
            self.assertTrue(
                dep in known_names or dependency in known_names,
                f"DEPENDS_ON ({dep}, {dependency}) references no known package",
            )


# ─────────────────────────────────────────────────────────────────────────────
# import_synthetic tests
# ─────────────────────────────────────────────────────────────────────────────
class TestSyntheticData(unittest.TestCase):

    def setUp(self):
        import import_synthetic
        self.m = import_synthetic

    def test_account_ip_link_count(self):
        self.assertGreaterEqual(len(self.m.ACCOUNT_IP_LINKS), 10)

    def test_demo_account_ip_link_present(self):
        """ART-BY-FAISAL -> 203.0.113.42 is the primary demo cross-domain bridge."""
        link = next(
            (l for l in self.m.ACCOUNT_IP_LINKS if l[0] == "ART-BY-FAISAL"),
            None
        )
        self.assertIsNotNone(link, "Demo account ART-BY-FAISAL not found in ACCOUNT_IP_LINKS")
        self.assertEqual(link[1], "npm")
        self.assertEqual(link[2], "203.0.113.42")

    def test_confidence_scores_valid(self):
        for username, registry, ip, confidence in self.m.ACCOUNT_IP_LINKS:
            self.assertGreater(confidence, 0.0)
            self.assertLessEqual(confidence, 1.0)

    def test_fraud_signal_count(self):
        self.assertGreaterEqual(len(self.m.FRAUD_SIGNALS), 15)

    def test_demo_ip_has_fraud_signal(self):
        """203.0.113.42 (APT41 demo IP) should have at least one FraudSignal."""
        signals = [s for s in self.m.FRAUD_SIGNALS if s[4] == "203.0.113.42"]
        self.assertGreater(len(signals), 0)

    def test_fraud_signal_amounts_positive(self):
        for juspay_id, fraud_type, amount, currency, ip in self.m.FRAUD_SIGNALS:
            self.assertGreater(amount, 0)

    def test_fraud_signal_juspay_ids_unique(self):
        ids = [s[0] for s in self.m.FRAUD_SIGNALS]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate juspay_id in FRAUD_SIGNALS")


# ─────────────────────────────────────────────────────────────────────────────
# import_threats tests
# ─────────────────────────────────────────────────────────────────────────────
class TestThreatsData(unittest.TestCase):

    def setUp(self):
        import import_threats
        self.m = import_threats

    def test_attributed_ip_count(self):
        self.assertGreaterEqual(len(self.m.ATTRIBUTED_IPS), 20)

    def test_demo_ip_present_and_attributed(self):
        """203.0.113.42 should be present and linked to APT41."""
        match = next(
            (t for t in self.m.ATTRIBUTED_IPS if t[0] == "203.0.113.42"),
            None,
        )
        self.assertIsNotNone(match)
        self.assertEqual(match[3], "APT41")

    def test_domain_count(self):
        self.assertGreaterEqual(len(self.m.MALICIOUS_DOMAINS), 10)

    def test_demo_domain_present(self):
        """npm-registry-cdn.com is the demo APT41 domain."""
        names = [d[0] for d in self.m.MALICIOUS_DOMAINS]
        self.assertIn("npm-registry-cdn.com", names)

    def test_all_attributed_ips_have_address(self):
        for ip, geo, asn, actor in self.m.ATTRIBUTED_IPS:
            self.assertRegex(
                ip, r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
                f"Bad IP address: {ip}",
            )

    def test_all_domain_hosting_ips_are_known(self):
        """Every domain's hosting IP should exist in ATTRIBUTED_IPS."""
        known_ips = {t[0] for t in self.m.ATTRIBUTED_IPS}
        for domain, actor, hosting_ip in self.m.MALICIOUS_DOMAINS:
            if hosting_ip:
                self.assertIn(
                    hosting_ip, known_ips,
                    f"Domain {domain} links to unknown IP {hosting_ip}",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
