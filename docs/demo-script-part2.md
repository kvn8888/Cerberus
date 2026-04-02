# Cerberus — Demo Script Part 2 (2:30)

> **Context:** This picks up immediately after Part 1 ends (the ua-parser-js investigation).
> Your teammate just showed the core investigation flow — query, pipeline, graph, narrative, exports.
> You now show the *analyst workflow* features: ingesting raw intel, geographic threat mapping,
> cross-investigation comparison, and the self-improving memory system.

---

## 0:00–0:15 — Transition + Ingest Setup (talk while switching tabs)

**You:**
> "So [teammate] just showed you what happens when you already know the package name.
> But in the real world, you don't get a clean query — you get a raw threat report
> dropped in Slack at 2 AM. Let me show you what that looks like."

**Action:** Click the **Ingest** tab in the center panel nav.

---

## 0:15–0:50 — Live Document Ingestion (the big new feature)

**Action:** Paste the following text into the text area:

```
CISA Alert: ua-parser-js versions 0.7.29, 0.8.0, and 1.0.0 were compromised
on October 22, 2021. The attacker published malicious versions to npm that
contained a cryptocurrency miner and credential-stealing trojan. Affected
infrastructure includes C2 servers at 159.148.186.228 and citfraud.com.
The attack is attributed to APT41 (also known as Barium/Winnti) and leverages
techniques T1195.002 (Supply Chain Compromise) and T1059.001 (PowerShell).
CVE-2021-27292 was assigned. Organizations running ua-parser-js should upgrade
to 0.7.30, 0.8.1, or 1.0.1 immediately.
```

**Action:** Ensure "Write to Graph" toggle is ON → Click **Extract Entities**

**You (while processing):**
> "I just pasted a raw CISA advisory. The system is extracting every entity —
> packages, IPs, domains, CVEs, threat actors, techniques — and classifying
> each one with a confidence score and threat domain."

**You (when results appear):**
> "Eight entities extracted in under three seconds. Each one is typed, scored,
> and already written to our Neo4j knowledge graph. No manual data entry — paste
> the report, get structured intelligence."

**Action:** Point to a couple of entity rows — show the type badges (colored), confidence levels, and context snippets.

---

## 0:50–1:15 — Geographic Threat Map

**Action:** Click the **Geomap** tab.

**You:**
> "Every investigation maps to the real world. This is a live geographic threat map —
> each node represents an APT group or threat actor, positioned by known attribution.
> The animated connections show active attack flows between regions."

**Action:** Let the map render for a moment, point to a couple of nodes.

**You:**
> "APT41 — the group behind ua-parser-js — is right here. You can see its operational
> infrastructure spanning multiple countries. This isn't a static image — it updates
> as new data enters the graph."

---

## 1:15–1:45 — Compare Investigations

**Action:** Click the **Compare** tab. Select `ua-parser-js` and `node-ipc` (or another entity from the graph) as the two entities.

**You:**
> "Now something analysts have never had: side-by-side investigation comparison.
> I'm comparing ua-parser-js with node-ipc — two different supply chain attacks."

**Action:** Let the comparison render. Point to the overlap score and shared nodes.

**You:**
> "Look — they share infrastructure. Same threat actor, overlapping MITRE techniques,
> common C2 patterns. The overlap score quantifies how related these two investigations are.
> In a traditional workflow, you'd need a human analyst to manually connect these dots
> across separate reports. Cerberus does it automatically."

---

## 1:45–2:10 — Memory + Self-Improvement

**Action:** Click the **Memory** tab. Show the force-directed memory graph.

**You:**
> "Every confirmed pattern gets stored in the agent's memory as a knowledge graph.
> These nodes are expandable — click the plus sign, and hidden relationships appear.
> The agent doesn't just answer questions — it builds institutional knowledge."

**Action:** Expand a node to reveal hidden connections.

**You:**
> "And this memory is exportable. One click gives you a STIX 2.1 bundle of every
> memorized pattern — ready to import into your SIEM, your SOAR platform, or share
> with your ISAC. The intelligence your team builds doesn't stay locked in one tool."

---

## 2:10–2:30 — Close

**You:**
> "To recap: we started with a raw threat report pasted from Slack. In under thirty seconds,
> Cerberus extracted the entities, mapped the attack geographically, compared it against
> prior investigations to find shared infrastructure, and stored the pattern for future use.
>
> Four analyst hours compressed into thirty seconds — and every investigation makes the next one faster."

---

## Pre-Demo Checklist (Part 2)

- [ ] Ingest tab is visible and functional (backend running)
- [ ] Sample CISA text copied to clipboard, ready to paste
- [ ] "Write to Graph" toggle defaults to ON
- [ ] Geomap renders without errors
- [ ] At least two entities exist in graph for Compare (run ua-parser-js + node-ipc first)
- [ ] Memory tab has at least one confirmed pattern with expandable nodes
- [ ] Practice the paste → extract → tab switch flow until it's smooth (< 3 seconds per transition)

## Timing Targets

| Section              | Duration | Cumulative |
| -------------------- | -------- | ---------- |
| Transition + setup   | 15s      | 0:15       |
| Live ingestion       | 35s      | 0:50       |
| Geographic threat map| 25s      | 1:15       |
| Compare investigations| 30s     | 1:45       |
| Memory + close       | 45s      | 2:30       |

> **Combined total:** Part 1 (2:45) + Part 2 (2:30) = **5:15**
> If time is tight, cut the Compare section (saves 30s → 4:45 total).

---

## Backup Plan

If the live backend is down or slow:
1. Have a screen recording of the full Part 2 flow ready
2. The Ingest panel works even without RocketRide (falls back to direct Claude Haiku)
3. Geomap and Memory are client-side renders — they work offline if data was loaded previously
