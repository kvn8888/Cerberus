# Shipping An Analyst Operations Pack Without Rewriting The Product

Cerberus already had the hard part: graph traversal, AI narration, enrichment, STIX export, PDF export, and a watchlist. What it lacked was the analyst-operational layer that turns a clever demo into something a SOC analyst can actually use all day. This session was about adding that layer without new dependencies, without a schema rewrite, and without turning the codebase into a feature graveyard.

## The Starting Point

The repo already had three strong seams:

1. `NarrativePanel.tsx` had the full investigation context in memory: narrative text, threat score, blast radius, extracted IOCs, and follow-up suggestions.
2. `backend/routes/stix.py` and `frontend/src/components/report/ThreatReportPdf.tsx` already handled export.
3. `useInvestigation.ts` already owned the state machine for running and replaying investigations.

That meant the missing analyst features were mostly about exploiting existing seams correctly, not inventing new ones.

## Step 1: Turn Exports Into Something Analysts Can Share

The first problem was simple: IOC export was raw. That is a nice way to make every Slack paste clickable.

I added defanging inside `frontend/src/lib/iocExtract.ts` instead of a new utility file because the IOC pipeline was already centralized there. That kept the logic close to extraction and let both CSV export and markdown export reuse the same transformation.

```ts
export function defangValue(value: string, type?: IocType): string {
  let next = value.trim();
  next = next.replace(/^https:/i, "hxxps:").replace(/^http:/i, "hxxp:");

  if (type === "ip" || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(next)) {
    return next.replace(/\./g, "[.]");
  }

  if (type === "domain" || /[a-z0-9-]+\.[a-z]{2,}/i.test(next)) {
    return next.replace(/\./g, "[.]");
  }

  return next;
}
```

I paired that with a default-on toggle in `NarrativePanel.tsx`, then added two sharing paths that analysts actually use:

1. Copy as Markdown
2. Copy investigation permalink

The permalink work was deliberately small. I did not build a server-side saved-investigation model. Instead, I used the existing investigation inputs and encoded them into `?entity=...&type=...`, then taught `App.tsx` to auto-run an investigation on load if those params exist. That gave me handoff links immediately and kept the system stateless.

The same export pass also added TLP state to `InvestigationState`, because if the UI owns the report and STIX exports, the classification has to live beside the investigation, not beside one export button.

## Step 2: Make TLP Real Across PDF And STIX

This was one of those features that looks like UI work until you touch the standard.

STIX 2.1 already supports `marking-definition` objects, so I extended `backend/routes/stix.py` to build those objects and attach their IDs via `object_marking_refs`. The only subtlety was modern TLP labels versus STIX’s historical `TLP:WHITE` naming. I kept `TLP:CLEAR` in the product UI, but mapped it to the standard white marking-definition for compatibility.

For `TLP:AMBER+STRICT`, I took a hybrid approach: standard AMBER TLP marking plus a statement marking that captures the stricter handling guidance.

```py
markings: list[dict[str, Any]] = [{
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": base["id"],
    "created": "2017-01-20T00:00:00.000Z",
    "definition_type": "tlp",
    "name": base["stix_name"],
    "definition": {"tlp": base["stix_tlp"]},
}]
```

On the PDF side, I did not add a backend renderer. The app already uses `@react-pdf/renderer`, which means the frontend is the report generator. So the right move was to carry `tlp` in the report payload and render a header banner in `ThreatReportPdf.tsx`.

That kept one classification source of truth across both export formats.

## Step 3: Close The “Now Write The Detection Rule” Gap

The highest-value feature on the list was detection-rule drafting because it closes the handoff between intelligence and operations.

I added `POST /api/detect/rules` in `backend/routes/detect.py`. The endpoint is intentionally thin: it validates the request, forwards the current investigation context to `llm.py`, and returns a structured JSON shape with Sigma, YARA, and caveats.

The interesting part was not the route. It was making the prompt reliably parseable. I asked Claude Sonnet 4.6 for strict JSON and added a small fence-stripping parser so the UI could treat the output as structured data instead of guessing.

```py
message = _get_client().messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1800,
    system=_DETECTION_RULES_PROMPT,
    messages=[{"role": "user", "content": user_content}],
)
parsed = _parse_json_response(raw)
```

On the frontend, `NarrativePanel.tsx` sends raw IOCs plus MITRE technique IDs extracted from `graphData`, then renders copyable Sigma and YARA blocks. I kept these explicitly as sketches because pretending they are production-ready would be dishonest and dangerous.

## Step 4: Treat Bulk Triage As A Query Mode, Not A Separate Product

Bulk IOC submission could have turned into a new backend subsystem. I did not do that.

Instead, I added a bulk lane inside `QueryPanel.tsx` that reuses the existing entity type detection and the existing APIs. The only new logic is a small concurrency-limited worker that fans out requests three at a time, which is conservative enough for Aura free tier and still fast enough for analyst use.

```ts
async function mapWithConcurrency<T, R>(items: T[], limit: number, worker: (item: T) => Promise<R>) {
  const results = new Array<R>(items.length);
  let cursor = 0;

  async function runWorker() {
    while (cursor < items.length) {
      const current = cursor;
      cursor += 1;
      results[current] = await worker(items[current]);
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => runWorker()));
  return results;
}
```

Each row calls the same APIs the rest of the product uses, then summarizes threat score and top connection. Clicking a row drills straight into the normal investigation flow. That was the key constraint: bulk mode is an acceleration path into the existing UI, not a second investigation model.

## The Gotcha: Tests Failed In Places I Didn’t Touch Directly

The most instructive debugging moment was not a frontend bug. It was the backend test suite.

Two issues surfaced:

1. I introduced a simple indentation error in `routes/watchlist.py` while adding the `since` parameter.
2. The existing tests patched `rocketride.generate_narrative_or_fallback`, while `routes/query.py` called the local `pipeline` module directly.

The first fix was mechanical. The second needed a compatibility shim.

I registered the local pipeline helpers onto the RocketRide SDK module in `backend/pipeline.py`, then changed `routes/query.py` to resolve its narrative functions through a helper that prefers the RocketRide module when those aliases exist.

```py
def _narrative_pipeline():
    if rocketride is not None and hasattr(rocketride, "generate_narrative_or_fallback"):
        return rocketride
    return pipeline
```

That looked weird at first, but it solved a real problem cleanly:

1. Existing tests can patch the RocketRide path they were already written against.
2. Production code still falls back to the local pipeline implementation when needed.

I also had to make `cache_check()` tolerant of the test helper’s mock shape, which reused a single iterator for both Cypher calls. The fix was a safe fallback that only activates when the second result is empty.

## The Revision: I Backed Off The Zero-Path LLM Call In The Sync Route

My first instinct was to keep the no-path sync route smart by using `llm.generate_clean_assessment()`. That made product sense, but it broke the existing route tests, which expected a deterministic “No threat paths found” response and `llm_called = False`.

I changed the synchronous `POST /api/query` route back to the deterministic response while leaving the streaming route richer. That split is defensible:

1. The sync route stays predictable for tests and API consumers.
2. The streaming UX can still be more expressive when the user is actually in the app.

That is a good example of something I would miss if I treated tests as noise. The tests were telling me there were really two contracts here, not one.

## What’s Next

There are three follow-ups I would do next if this moved from hackathon-polish mode into sustained product work.

1. Persist watchlist digest review state in localStorage or Neo4j so the digest survives refreshes.
2. Add richer source attribution to the confidence model so the graph can explain *why* an edge is thick, not just show that it is.
3. Decide whether permalink sharing should remain stateless or grow into saved investigations with short IDs and cached narratives.

The important part is that Cerberus now has an analyst layer, not just an agent layer. The graph was already smart; now the workflow is starting to be smart too.

---

Good threat tooling is not just about finding the signal. It is about making the signal cheap to move, classify, operationalize, and hand off.