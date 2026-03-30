#!/usr/bin/env python3
"""
eval_improvement.py — Proves Cerberus gets smarter over time.

Phase 1: Empty graph     -> Full LLM analysis, ~8s, full token usage
Phase 2: Seeded graph    -> Shorter prompt, some paths pre-resolved, ~5s
Phase 3: Confirmed paths -> Cache hit on confirmed subgraphs skips LLM, ~2s

Requires: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD env vars.
Optional: CERBERUS_API (defaults to http://localhost:8000)
"""

import os
import sys
import time
import subprocess
import requests
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI    = os.environ["NEO4J_URI"]
NEO4J_USER   = os.environ["NEO4J_USERNAME"]
NEO4J_PASS   = os.environ["NEO4J_PASSWORD"]
CERBERUS_API = os.environ.get("CERBERUS_API", "http://localhost:8000")
DEMO_PACKAGE = "ua-parser-js"

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


def clear_graph():
    with driver.session() as s:
        s.run("MATCH (n) DETACH DELETE n")


def count_nodes() -> int:
    with driver.session() as s:
        return s.run("MATCH (n) RETURN count(n) AS c").single()["c"]


def query_cerberus(package_name: str) -> dict:
    start = time.perf_counter()
    resp = requests.post(
        f"{CERBERUS_API}/api/query",
        json={"entity": package_name, "type": "package"},
        timeout=60,
    )
    resp.raise_for_status()
    elapsed_ms = (time.perf_counter() - start) * 1000
    data = resp.json()
    return {
        "response_time_ms":   elapsed_ms,
        "threat_paths_found": data.get("paths_found", 0),
        "from_cache":         data.get("from_cache", False),
        "llm_called":         data.get("llm_called", True),
        "narrative_length":   len(data.get("narrative", "")),
    }


def confirm_pattern(package_name: str):
    resp = requests.post(
        f"{CERBERUS_API}/api/confirm",
        json={"entity": package_name, "type": "package"},
        timeout=15,
    )
    resp.raise_for_status()


def seed_graph():
    """Run all import scripts in sequence."""
    scripts = [
        "import_mitre.py",
        "import_cve.py",
        "import_npm.py",
        "import_threats.py",
        "import_synthetic.py",
    ]
    scripts_dir = os.path.join(os.path.dirname(__file__))
    for script in scripts:
        path = os.path.join(scripts_dir, script)
        print(f"  Running {script}...")
        result = subprocess.run(
            [sys.executable, path],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"  WARN: {script} exited {result.returncode}")
            print(result.stderr[-500:] if result.stderr else "")
        else:
            last_line = result.stdout.strip().split("\n")[-1]
            print(f"  -> {last_line}")


def run_eval():
    results = {}

    # ── Phase 1: Empty graph ──────────────────────────────────────────────────
    print("=== Phase 1: Empty graph ===")
    clear_graph()
    node_count = count_nodes()
    assert node_count == 0, f"Expected 0 nodes, got {node_count}"

    result_a = query_cerberus(DEMO_PACKAGE)
    results["phase_1"] = result_a
    print(f"  Response time:  {result_a['response_time_ms']:.0f}ms")
    print(f"  Paths found:    {result_a['threat_paths_found']}")
    print(f"  LLM called:     {result_a['llm_called']}")
    print(f"  Narrative len:  {result_a['narrative_length']} chars")

    # ── Phase 2: Seeded graph ─────────────────────────────────────────────────
    print("\n=== Phase 2: Seeded graph ===")
    seed_graph()
    node_count = count_nodes()
    print(f"  Nodes in graph: {node_count}")

    result_b = query_cerberus(DEMO_PACKAGE)
    results["phase_2"] = result_b
    print(f"  Response time:  {result_b['response_time_ms']:.0f}ms")
    print(f"  Paths found:    {result_b['threat_paths_found']}")
    print(f"  LLM called:     {result_b['llm_called']}")
    print(f"  Narrative len:  {result_b['narrative_length']} chars")

    # ── Phase 3: After analyst confirmation ───────────────────────────────────
    print("\n=== Phase 3: Confirmed pattern (cache hit) ===")
    confirm_pattern(DEMO_PACKAGE)
    # Second confirmation is idempotent — confirm again to ensure propagation
    time.sleep(0.5)

    result_c = query_cerberus(DEMO_PACKAGE)
    results["phase_3"] = result_c
    print(f"  Response time:  {result_c['response_time_ms']:.0f}ms")
    print(f"  Paths found:    {result_c['threat_paths_found']}")
    print(f"  From cache:     {result_c['from_cache']}")
    print(f"  LLM called:     {result_c['llm_called']}")
    print(f"  Narrative len:  {result_c['narrative_length']} chars")

    # ── Assertions ────────────────────────────────────────────────────────────
    print("\n=== Assertions ===")

    assert result_b["threat_paths_found"] > result_a["threat_paths_found"], (
        f"Expected more paths with seeded data. "
        f"Phase1={result_a['threat_paths_found']}, Phase2={result_b['threat_paths_found']}"
    )
    print("  ok  More paths found with seeded data")

    assert result_c["from_cache"] is True, "Expected from_cache=True after confirmation"
    print("  ok  Confirmed pattern served from cache")

    assert result_c["llm_called"] is False, "Expected llm_called=False on cache hit"
    print("  ok  LLM skipped on cache hit")

    assert result_c["response_time_ms"] < result_b["response_time_ms"], (
        f"Expected cache hit faster. "
        f"Phase2={result_b['response_time_ms']:.0f}ms, Phase3={result_c['response_time_ms']:.0f}ms"
    )
    print("  ok  Cache hit is faster than full analysis")

    print("\nAll improvement assertions passed.")
    return results


if __name__ == "__main__":
    try:
        results = run_eval()
        driver.close()
        sys.exit(0)
    except AssertionError as e:
        print(f"\nFAIL: {e}")
        driver.close()
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        driver.close()
        sys.exit(1)
