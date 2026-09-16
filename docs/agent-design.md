# Agent Design

## Why not `alert -> prompt -> LLM -> answer`

That pattern cannot be audited, cannot enforce policy, and trusts attacker-controlled
text. threatlens instead models triage as an explicit state machine with distinct
stages and a controlled tool layer.

## State machine

```
RECEIVED
  -> NORMALIZED
  -> CLASSIFIED
  -> ENRICHING
       (failure -> ENRICHMENT_FAILED)
  -> EVIDENCE_VALIDATION
  -> REASONING
       (failure -> REASONING_FAILED)
  -> DECISION_VALIDATION
       (failure -> VALIDATION_FAILED)
  -> TRIAGE_GENERATION
  -> COMPLETED  |  ESCALATED
```

Transitions are validated against `ALLOWED_TRANSITIONS`. Illegal transitions raise
`InvalidStateTransition`. Every transition is logged with `alert_id` and
`agent_run_id`.

## Tool selection

The agent does **not** ask the model which tools to call. `EnrichmentEngine.select_tools`
inspects the normalized alert and asks each registered tool `is_applicable`:

- PowerShell alert -> asset context, history, MITRE.
- External IP -> VirusTotal, AbuseIPDB, asset context, history, MITRE.
- Hash-only alert -> VirusTotal (file), history, MITRE.

This keeps tool selection deterministic and free of prompt-injection risk.

## Tool registry

`ToolRegistry` is the only path to a tool. It enforces:

- **Allowlisting** - unregistered names raise `ToolNotRegisteredError`.
- **Tool budget** - `ToolBudget` caps calls per alert (`MAX_TOOL_CALLS`).
- **Retries** - bounded exponential backoff.
- **Timeouts** - every call runs under `asyncio.wait_for`.
- **Audit + metrics** - every call emits an audit event and metrics.

## Evidence model

Tool output is converted to first-class `Evidence` objects with stable IDs
(`EVID-XXXXXXXX`). The LLM may only reference evidence by ID. Unknown IDs are
dropped and logged; they never reach the final result.

## Reasoning contract

The LLM must return `RawReasoningOutput`:

```json
{
  "classification": "true_positive",
  "severity": "high",
  "confidence": 0.87,
  "evidence_ids": ["EVID-..."],
  "observations": ["..."],
  "inferences": ["..."],
  "reasoning_summary": "...",
  "recommended_actions": [{"action": "...", "rationale": "...", "priority": 1}],
  "escalation_required": true,
  "uncertainties": ["..."]
}
```

Malformed output raises `StructuredGenerationError`, which the agent catches and
converts into a deterministic fallback triage.

## Policy enforcement

`PolicyEngine` runs after reasoning and can only *raise* severity or *require* human
review - never lower safety. Examples:

- Confirmed malware hash -> minimum severity HIGH.
- Malicious indicator + critical asset -> minimum severity HIGH.
- Critical asset + high alert severity -> escalate.
- Model says benign but enrichment shows a malicious indicator -> override to
  `needs_investigation`.

## Human-in-the-loop

The agent can recommend actions (isolate host, block IP, disable account, ...) but
never executes them. `TriageResult.action_executed` is always `"none"`, and every
recommended action carries `requires_human_approval = true`.
