# Cerberus — Demo Script Part 2 (1:15)

> **Context:** Picks up right after Part 1. Your teammate showed the query → graph → narrative flow.
> You show: raw document ingestion, geographic mapping, and memory.

---

## 0:00–0:10 — Transition

**You:**
> "[Teammate] showed you what happens when you know the package name.
> But analysts don't get clean queries — they get raw reports in Slack at 2 AM."

**Action:** Click the **Ingest** tab.

---

## 0:10–0:35 — Ingest (the money shot)

**Action:** Paste the sample text (pre-copied to clipboard), toggle "Write to Graph" ON, click **Extract Entities**.

```
CISA Alert: ua-parser-js versions 0.7.29, 0.8.0, and 1.0.0 were compromised
on October 22, 2021. The attacker published malicious versions containing a
cryptocurrency miner and credential-stealing trojan. Affected infrastructure
includes command-and-control servers at 159.148.186.228 and citfraud.com.
The attack is attributed to APT41. CVE-2021-27292 was assigned.
```

**You (while it processes):**
> "Paste a raw advisory, hit extract. A RocketRide pipeline reads the text and
> pulls out every entity — packages, IPs, domains, vulnerabilities, threat groups —
> scored by confidence and written straight to the graph."

**You (when results appear — ~3s):**
> "Eight entities, three seconds, zero manual work."

---

## 0:35–0:50 — Geomap (15 seconds, visual wow)

**Action:** Click **Geomap** tab. Let it render.

**You:**
> "Every entity maps to the real world. APT41 is right here — you can see their
> infrastructure spanning multiple countries. This updates live as new data enters the graph."

---

## 0:50–1:05 — Memory (15 seconds)

**Action:** Click **Memory** tab. Expand one node.

**You:**
> "Every confirmed pattern is stored in the agent's memory graph. Click to expand
> hidden relationships. One click exports everything as a shareable data bundle.
> The RocketRide agent learns from every investigation."

---

## 1:05–1:15 — Close

**You:**
> "Raw report to structured intelligence in thirty seconds.
> Four hours of analyst work — automated, and it gets faster every time."

---

## Timing

| Section    | Duration | Cumulative |
| ---------- | -------- | ---------- |
| Transition | 10s      | 0:10       |
| Ingest     | 25s      | 0:35       |
| Geomap     | 15s      | 0:50       |
| Memory     | 15s      | 1:05       |
| Close      | 10s      | 1:15       |

> **Combined:** Part 1 (2:45) + Part 2 (1:15) = **4:00 total**

---

## Checklist

- [ ] Sample text copied to clipboard before you start
- [ ] "Write to Graph" toggle defaults ON
- [ ] Geomap and Memory tabs have data from the Part 1 investigation
- [ ] Backup: screen recording ready if live demo fails
