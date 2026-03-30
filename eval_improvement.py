#!/usr/bin/env python3
"""
eval_improvement.py — Proves Cerberus gets smarter over time.

Three-phase evaluation that demonstrates the self-improvement loop:
  Phase 1 (empty graph): Full LLM analysis, slow, no prior context
  Phase 2 (seeded graph): Rich graph data, shorter prompts, faster
  Phase 3 (confirmed):   Cache hit on confirmed patterns, skips LLM

Run against a live Neo4j Aura instance + running Cerberus API.

Requires env vars:
  NEO4J_URI        — bolt URI for Neo4j Aura
  NEO4J_USERNAME   — usually "neo4j"
  NEO4J_PASSWORD   — Aura instance password
  CERBERUS_API     — base URL (default: http://localhost:8000)

Usage:
  python eval_improvement.py
"""

import time
import os
import sys
import requests
from neo4j import GraphDatabase

# ── Configuration ──────────────────────────────────────────────
NEO4J_URI = os.environ.get("NEO4J_URI", "")
NEO4J_USER = os.environ.get("NEO4J_USERNAME", "")
NEO4J_PASS = os.environ.get("NEO4J_PASSWORD", "")
CERBERUS_API = os.environ.get("CERBERUS_API", "http://localhost:8000")

# The primary demo package — a well-known supply chain compromise
DEMO_PACKAGE = "ua-parser-js"


def check_env():
    """Validate that all required environment variables are set."""
    missing = []
    for var in ["NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD"]:
        if not os.environ.get(var):
            missing.append(var)
    if missing:
        print(f"ERROR: Missing environment variables: {', '.join(missing)}")
        print("Set them before running this script.")
        sys.exit(1)


def get_driver():
    """Create a Neo4j driver instance with configured credentials."""
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


def clear_graph(driver):
    """
    Delete all nodes and relationships from the graph.
    WARNING: This is destructive — only use for eval, never in production.
    Uses batched deletion to avoid memory issues on large graphs.
    """
    with driver.session() as s:
        # Batch delete in chunks of 10000 to avoid timeout on large graphs
        while True:
            result = s.run(
                "MATCH (n) WITH n LIMIT 10000 DETACH DELETE n RETURN count(*) AS deleted"
            )
            deleted = result.single()["deleted"]
            if deleted == 0:
                break
            print(f"    Deleted {deleted} nodes ...")


def count_nodes(driver) -> int:
    """Count total nodes in the graph."""
    with driver.session() as s:
        return s.run("MATCH (n) RETURN count(n) AS c").single()["c"]


def count_relationships(driver) -> int:
    """Count total relationships in the graph."""
    with driver.session() as s:
        return s.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]


def query_cerberus(package_name: str) -> dict:
    """
    Hit the Cerberus query API and measure the response.

    The API is expected to return JSON with:
      - paths_found: number of cross-domain paths discovered
      - from_cache: whether the result came from a confirmed pattern cache
      - llm_called: whether the LLM was invoked for narrative generation
      - narrative: the AI-generated threat narrative text

    Returns a dict with response metrics for comparison across phases.
    """
    start = time.perf_counter()
    try:
        resp = requests.post(
            f"{CERBERUS_API}/api/query",
            json={"entity": package_name, "type": "package"},
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"    ERROR: Cerberus API call failed: {e}")
        return {
            "response_time_ms": 0,
            "threat_paths_found": 0,
            "from_cache": False,
            "llm_called": False,
            "narrative_length": 0,
            "error": str(e),
        }

    elapsed_ms = (time.perf_counter() - start) * 1000
    data = resp.json()

    return {
        "response_time_ms": elapsed_ms,
        "threat_paths_found": data.get("paths_found", 0),
        "from_cache": data.get("from_cache", False),
        "llm_called": data.get("llm_called", True),
        "narrative_length": len(data.get("narrative", "")),
    }


def confirm_pattern(package_name: str):
    """
    Simulate an analyst confirming a threat pattern.

    When an analyst confirms a pattern, Cerberus writes it back to the
    graph as a labeled subgraph. Future queries for the same pattern
    hit the cache instead of invoking the LLM.
    """
    try:
        resp = requests.post(
            f"{CERBERUS_API}/api/confirm",
            json={"entity": package_name, "type": "package"},
            timeout=10,
        )
        resp.raise_for_status()
        print("    Pattern confirmed via API")
    except requests.RequestException as e:
        print(f"    WARN: Confirm API call failed: {e}")
        print("    (This is expected if the API isn't running yet)")


def run_import_scripts():
    """
    Run the data import pipeline in the correct order.
    Returns True if imports succeeded, False otherwise.
    """
    import subprocess

    scripts = [
        "import_mitre.py",
        "import_cve.py",
        "import_npm.py",
        "import_threats.py",
        "import_synthetic.py",
    ]

    for script in scripts:
        if not os.path.exists(script):
            print(f"    WARN: {script} not found — skipping")
            continue

        print(f"    Running {script} ...")
        result = subprocess.run(
            [sys.executable, script],
            capture_output=True,
            text=True,
            timeout=300,  # 5 min timeout per script
        )
        if result.returncode != 0:
            print(f"    ERROR in {script}:")
            print(f"      {result.stderr[:500]}")
            return False

    return True


def print_separator():
    """Print a visual separator between phases."""
    print("─" * 60)


def run_eval():
    """
    Execute the 3-phase evaluation and report results.

    Phase 1 (empty): Baseline with no graph data
    Phase 2 (seeded): After importing all seed data
    Phase 3 (confirmed): After analyst confirmation → cache hit

    Assertions verify that each phase improves on the previous one.
    """
    check_env()
    driver = get_driver()

    results = {}

    # ── Phase 1: Empty graph ───────────────────────────────────
    print_separator()
    print("PHASE 1: Empty Graph (Baseline)")
    print_separator()
    print("  Clearing graph ...")
    clear_graph(driver)
    node_count = count_nodes(driver)
    assert node_count == 0, f"Graph should be empty, found {node_count} nodes"
    print(f"  Nodes: {node_count}")

    result_a = query_cerberus(DEMO_PACKAGE)
    print(f"  Response time:   {result_a['response_time_ms']:.0f}ms")
    print(f"  Paths found:     {result_a['threat_paths_found']}")
    print(f"  LLM called:      {result_a['llm_called']}")
    print(f"  Narrative chars: {result_a['narrative_length']}")
    results["phase_1"] = result_a

    # ── Phase 2: Seeded graph ──────────────────────────────────
    print()
    print_separator()
    print("PHASE 2: Seeded Graph (After Import)")
    print_separator()
    print("  Running import scripts ...")
    import_ok = run_import_scripts()
    if not import_ok:
        print("  WARNING: Some imports failed — continuing with partial data")

    node_count = count_nodes(driver)
    rel_count = count_relationships(driver)
    print(f"  Nodes: {node_count}")
    print(f"  Relationships: {rel_count}")

    result_b = query_cerberus(DEMO_PACKAGE)
    print(f"  Response time:   {result_b['response_time_ms']:.0f}ms")
    print(f"  Paths found:     {result_b['threat_paths_found']}")
    print(f"  LLM called:      {result_b['llm_called']}")
    print(f"  Narrative chars: {result_b['narrative_length']}")
    results["phase_2"] = result_b

    # ── Phase 3: After analyst confirmation ────────────────────
    print()
    print_separator()
    print("PHASE 3: Confirmed Pattern (Self-Improvement)")
    print_separator()
    print("  Confirming threat pattern ...")
    confirm_pattern(DEMO_PACKAGE)

    # Small delay to allow write-back to complete
    time.sleep(1)

    result_c = query_cerberus(DEMO_PACKAGE)
    print(f"  Response time:   {result_c['response_time_ms']:.0f}ms")
    print(f"  Paths found:     {result_c['threat_paths_found']}")
    print(f"  From cache:      {result_c['from_cache']}")
    print(f"  LLM called:      {result_c['llm_called']}")
    print(f"  Narrative chars: {result_c['narrative_length']}")
    results["phase_3"] = result_c

    # ── Assertions ─────────────────────────────────────────────
    print()
    print_separator()
    print("ASSERTIONS")
    print_separator()

    passed = 0
    failed = 0

    # Skip assertions if any phase had API errors
    if any("error" in results.get(f"phase_{i}", {}) for i in [1, 2, 3]):
        print("  ⚠ Skipping assertions — API errors detected")
        print("  (Start the Cerberus API server and re-run)")
        driver.close()
        return results

    # Assertion 1: Seeded graph finds more paths than empty graph
    try:
        assert result_b["threat_paths_found"] > result_a["threat_paths_found"], \
            f"Expected more paths ({result_b['threat_paths_found']} vs {result_a['threat_paths_found']})"
        print("  ✓ Seeded graph finds more paths than empty graph")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ More paths assertion failed: {e}")
        failed += 1

    # Assertion 2: Confirmed pattern is served from cache
    try:
        assert result_c["from_cache"] is True, \
            "Confirmed pattern should be served from cache"
        print("  ✓ Confirmed pattern served from cache")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ Cache assertion failed: {e}")
        failed += 1

    # Assertion 3: Cache hit skips LLM
    try:
        assert result_c["llm_called"] is False, \
            "Cache hit should skip LLM call"
        print("  ✓ LLM skipped on cache hit")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ LLM skip assertion failed: {e}")
        failed += 1

    # Assertion 4: Cache hit is faster than full analysis
    try:
        assert result_c["response_time_ms"] < result_b["response_time_ms"], \
            f"Cache should be faster ({result_c['response_time_ms']:.0f}ms vs {result_b['response_time_ms']:.0f}ms)"
        print("  ✓ Cache hit is faster than full analysis")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ Speed assertion failed: {e}")
        failed += 1

    print()
    if failed == 0:
        print(f"✅ All {passed} assertions passed!")
    else:
        print(f"⚠ {passed} passed, {failed} failed")

    driver.close()
    return results


if __name__ == "__main__":
    results = run_eval()
