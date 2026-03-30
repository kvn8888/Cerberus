# From Seven Duplicates to One Source of Truth: Consolidating a Hackathon Codebase Under Pressure

Two developers building the same project files independently, a mysterious `hashlib` import that turned out to be critical, and the kind of false positive that teaches you to verify before you refactor. This is the story of preparing Cerberus — a cross-domain threat intelligence platform — for a hackathon, and the integration testing session that caught what code review missed.

## The Starting Point

Cerberus is a hackathon project for HackWithBay 2.0 that traces cross-domain attack chains through a Neo4j graph. Think: "give me an npm package name, and I'll show you how it connects to threat actors, malicious IPs, and financial fraud signals across three domains that no single security tool covers."

The codebase had a problem: **seven data import scripts existed in two places.** I'd written root-level versions (with features like STIX bundle caching to avoid re-downloading 43MB at the hackathon). My teammate had independently written `scripts/` versions with different tradeoffs (pre-populated CVE data, APT attribution metadata, `requests` instead of `urllib`). Both sets worked. Neither set was authoritative.

```
cerberus/
├── constraints.cypher          # Mine: detailed comments
├── import_mitre.py             # Mine: urllib + caching
├── import_cve.py               # Mine: NVD API fetcher
├── ...4 more root-level files
└── scripts/
    ├── constraints.cypher      # Teammate: minimal comments
    ├── import_mitre.py         # Teammate: requests + batching
    ├── import_cve.py           # Teammate: 50 pre-populated CVEs
    └── ...4 more scripts/ files
```

The test suite (`tests/test_import_scripts.py`) only imported from `scripts/` via `sys.path.insert(0, scripts_dir)`. The root-level files were untested ghosts. This needed to be resolved before the hackathon, not during it.

## Step 1: Choosing Winners Per File

I couldn't just pick one directory wholesale — each location had files where it was the clearly better version.

**Root versions won for:**
- `constraints.cypher` — Same 8 constraints, but with block comments explaining *why* each constraint exists (e.g., "Package nodes are unique by name... MERGE operations use them for dedup"). During a hackathon, you don't want to wonder "why is this constraint here?" at 2 AM.
- `eval_improvement.py` — Batched graph deletion (chunks of 10,000 to avoid Neo4j timeouts), graceful assertion handling with pass/fail counters instead of hard crashes, and error-tolerant API calls that let you see partial results.

**Scripts/ versions won for:**
- `import_cve.py` — 50 pre-populated CVEs with no API dependency. My version hit the NVD API, which is rate-limited and might time out at the hackathon.
- `import_threats.py` — APT attribution with geo/ASN metadata per IP.
- `import_npm.py` — Explicit relationship definitions (which packages depend on which).
- `import_synthetic.py` — 20 fraud signals with confidence scores and Juspay-style transaction IDs.

**Merged:** `import_mitre.py` — I took the teammate's cleaner `parse_bundle()` function and batched imports, but added my local caching logic. The STIX bundle is ~43MB. At a hackathon with shared WiFi, that download could take minutes. With caching, it's instant after the first run.

```python
# The critical addition: check for cached STIX data before downloading
CACHE_PATH = os.path.join(os.path.dirname(__file__), "..", "seed_data", "enterprise-attack.json")

def fetch_stix_bundle() -> dict:
    """Download (or load from cache) the MITRE ATT&CK STIX bundle."""
    if os.path.exists(CACHE_PATH):
        print(f"  Using cached STIX bundle: {CACHE_PATH}")
        with open(CACHE_PATH, "r") as f:
            return json.load(f)
    # ... download and save to CACHE_PATH
```

The decision framework was simple: **for data files, prefer the version with no external API dependency. For infrastructure files, prefer the version with better documentation and error handling.**

## Step 2: The `hashlib` False Positive

During the initial code review, I found `import hashlib` in `neo4j_client.py` and flagged it as unused. grep didn't find `hashlib` elsewhere in the file when I first looked. I removed it and the tests passed. Ship it.

Then during integration testing, I looked more carefully at `write_back()`:

```python
def write_back(entity: str, entity_type: str, narrative: str | None = None) -> None:
    # ...
    s.run(
        cypher,
        value=entity,
        narrative=narrative,
        narrative_hash=hashlib.sha256(narrative.encode("utf-8")).hexdigest(),
    )
```

`hashlib.sha256()` — right there, line 209. It's used to hash the LLM-generated narrative so the graph can detect when a cached narrative is stale. The tests passed because `write_back` was mocked at a higher level — the mock never actually called `hashlib`. Unit tests verified the Cypher template shape, not the Python execution.

**Lesson:** "Unused import" is only true if you've verified it across *all code paths the module exercises*, not just the ones your tests cover. The test suite used mocks that short-circuited before reaching the `hashlib` call. If I'd deployed this to the hackathon, the first analyst confirmation would have crashed with `NameError: name 'hashlib' is not defined`.

I restored the import immediately. The project skill doc now marks this as "VERIFIED — hashlib IS used in write_back()."

## Step 3: The config.py Red Herring

During initial review, I flagged this as a bug in my session notes:

> config.py: `ANTHROPIC_KEY` reads from `NEO4J_API_KEY` (semantic mismatch)

Later, when I actually read the code:

```python
ANTHROPIC_KEY = get("ANTHROPIC_API_KEY")  # ← this is correct!
```

The variable `ANTHROPIC_KEY` reads from the environment variable `ANTHROPIC_API_KEY`. The naming follows a common Python pattern: module-level constant (`ANTHROPIC_KEY`) vs. environment variable name (`ANTHROPIC_API_KEY`). My initial scan confused the env var name with the module constant.

**Lesson:** When reviewing config files, compare the `os.environ` key (the string in quotes) to the `.env.example`, not the Python variable name on the left side of the assignment. The Python name is internal; the env var name is the integration contract.

## Step 4: The IndentationError Nobody Noticed

When I ran `pytest` for the first time after installing dependencies, it crashed:

```
tests/test_api_routes.py:40: in <module>
    from main import app
E     File ".../backend/main.py", line 1
E       """
E   IndentationError: unexpected indent
```

Line 1 of `main.py` had a leading space before the module docstring:

```python
 """               # ← invisible leading space
main.py — Cerberus FastAPI backend entry point.
```

This is the kind of bug that hides in plain sight. Most editors don't highlight leading whitespace on the first line. `git diff` shows it as a single space. Python's parser treats it as an unexpected indent because there's nothing to indent relative to.

The fix was trivial — delete one space character. But finding it required actually running the code, not just reading it. The test suite's import mechanism (which adds `backend/` to `sys.path` and imports `main`) was the first thing that actually executed the file.

## The Data Integrity Verification

After consolidation, I ran a targeted check on the demo chain — the specific path the hackathon demo would traverse:

```
ua-parser-js → ART-BY-FAISAL → 203.0.113.42 → FraudSignal(JS-2024-0001)
```

```python
# Verify each link in the demo chain independently
import import_npm, import_synthetic

# Link 1: Package → Publisher
demo_pkg = import_npm.PACKAGES[0]
# ('ua-parser-js', '0.7.29', 'npm', 9.5, 'ART-BY-FAISAL', '...')

# Link 2: Publisher → IP
faisal_links = [l for l in import_synthetic.ACCOUNT_IP_LINKS
                if 'FAISAL' in str(l).upper()]
# [('ART-BY-FAISAL', 'npm', '203.0.113.42', 0.92)]

# Link 3: IP → FraudSignal
fraud = import_synthetic.FRAUD_SIGNALS[0]
# ('JS-2024-0001', 'card_not_present', 1250.0, 'USD', '203.0.113.42')
```

All three links verified. The data uses tuples (teammate's choice), not dicts (my original format). Both work fine for the Cypher UNWIND; tuples are slightly more memory-efficient for static seed data.

**Final volumes:** 703 techniques, 181 actors, 4,362 USES relationships, 50 CVEs, 30 packages, 15 account-IP links, 20 fraud signals, 28 attributed IPs, 16 domains. That's ~1,000 nodes and ~4,500 relationships — enough to make the graph visualization impressive without hitting Aura free-tier limits.

## What's Next

The codebase is clean and tested (88/88 tests passing). What's left before the hackathon:

1. **Frontend UI** — The React+Vite+Tailwind scaffold exists with types and an API client, but no investigation page or graph visualization yet. The `useInvestigation` hook is wired up; it needs components to render into.
2. **Live Neo4j test** — Everything passes with mocks. Running the import scripts against actual Neo4j Aura would catch Cypher syntax issues that mocks can't reveal (e.g., the `shortestPath` in `_CACHE_CHECK_TMPL` uses string `.format()` for labels, which is fragile if a label contains braces).
3. **RocketRide pipeline integration** — The YAML definitions exist but haven't been loaded into RocketRide yet. This is an hour-1 task at the hackathon.

If I were doing this again, I'd establish a "scripts live in `scripts/` only" convention on day one, with a README explaining why. The parallel development wasn't wasted — the teammate's pre-populated CVE data was better than my API-fetching approach — but the merge cost time we could have spent on the frontend.

---

Sometimes the most valuable debugging session is the one where you put back what you removed.
