# threatlens Architecture

## Overview

threatlens is an **agentic security alert triage platform**. It takes a raw
SIEM/EDR alert, enriches it with external and internal context, reasons over the
evidence, and produces an analyst-ready triage note. The LLM is one component in a
much larger pipeline; deterministic processing, tool selection, evidence collection,
policy enforcement, and output validation all live outside the model.

## Pipeline

```
Raw SIEM / EDR Alert
        |
        v
+-------------------+     ingestion/{wazuh,suricata,elastic,synthetic}.py
| Ingestion Layer   |     parse + validate + normalize -> NormalizedAlert
+---------+---------+
          |
          v
+-------------------+     enrichment/engine.py + enrichment/registry.py
| Enrichment Agent  |     select applicable tools, execute allowlisted tools
|                   |     VirusTotal / AbuseIPDB / Asset / History / MITRE
+---------+---------+
          |
          v
+-------------------+     reasoning/engine.py + reasoning/confidence.py
| Reasoning Engine  |     structured LLM output + evidence grounding
|                   |     TP / FP / benign / needs_investigation
+---------+---------+
          |
          v
+-------------------+     agents/policies.py
| Policy Engine     |     deterministic minimum severities, human review
+---------+---------+
          |
          v
+-------------------+     models/triage.py
| Triage Output     |     analyst note / JSON / API / PDF
+-------------------+
```

## Layered responsibilities

| Layer | Package | Deterministic? | Responsibility |
|-------|---------|----------------|----------------|
| Ingestion | `ingestion/` | Yes | Source-specific parsing into one schema |
| Enrichment | `enrichment/` | Mostly | Tool selection + allowlisted execution |
| Evidence | `reasoning/evidence_builder.py` | Yes | Turn tool output into citable evidence |
| Reasoning | `reasoning/engine.py` | No (LLM) | Classification, severity, narrative |
| Confidence | `reasoning/confidence.py` | Yes | Blend model + evidence + tool reliability |
| Policy | `agents/policies.py` | Yes | Non-overridable safety constraints |
| Output | `models/triage.py` | Yes | Human-readable + structured result |

The agent state machine (`agents/state_machine.py`) makes every stage explicit and
auditable. The LLM never controls transitions, tool selection, or final severity.

## Component diagram

```
              +-----------------+
              |  NormalizedAlert |
              +--------+--------+
                       |
        +--------------+---------------+
        |                              |
        v                              v
+---------------+            +------------------+
| EnrichmentEngine |         |   ToolRegistry    |
| - select_tools   |-------->| - allowlist       |
| - merge results  |         | - budget/retries  |
+-------+----------+         | - audit + metrics |
        |                    +------------------+
        v
+----------------+   +-------------------+   +----------------+
| EvidenceBuilder|-->|  ReasoningEngine  |-->|  PolicyEngine  |
+----------------+   |  (LLMProvider)    |   +--------+-------+
                     +-------------------+            |
                              |                       v
                     +-------------------+   +------------------+
                     |ConfidenceCalculator|  |   TriageResult   |
                     +-------------------+   +------------------+
```

## Provider abstraction

`LLMProvider` is a `Protocol` with a single `generate_structured` method. The two
implementations are:

- `MockLLMProvider` - deterministic, offline, used for tests and demos.
- `OpenAIProvider` - real HTTP client, schema-validated, allowlisted, retried.

The rest of the system depends only on the protocol, so providers are swappable
without touching business logic.

## Persistence

SQLite via SQLAlchemy 2.0. Tables: `alerts`, `triage_results`, `evidence`,
`tool_calls`, `agent_runs`, `audit_events`, `assets`. Repository classes in
`storage/repositories.py` isolate business logic from the ORM, so PostgreSQL can
be introduced by changing only `DATABASE_URL`.
