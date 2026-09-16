# Reliability

## Structured outputs only

The reasoning layer never consumes free-form text. The LLM must return a JSON object
validating against `RawReasoningOutput`. Failures raise `StructuredGenerationError`,
which the agent converts into a deterministic fallback. Evidence references are IDs,
so the model cannot invent evidence that does not exist.

## Evidence grounding

Every meaningful conclusion references one or more `Evidence` objects. The engine
resolves referenced IDs against the actual evidence list; unknown IDs are dropped and
logged. `tests/agent/test_triage_agent.py` asserts that true-positive results carry
evidence.

## Confidence is computed, not trusted

`ConfidenceCalculator` blends:

```
final = 0.45 * model_confidence
      + 0.35 * evidence_confidence   (mean evidence confidence + source diversity)
      + 0.20 * tool_reliability      (per-source reliability)
      - contradiction_penalty        (conflicting enrichment)
      - missing_telemetry_penalty    (missing context, degraded tools)
```

The result is clamped to `[0.05, 0.99]`. This is a **heuristic**, not a calibrated
probability. Treat it as a ranking signal for analyst prioritization, not as a
probability of compromise. Calibration requires labelled historical outcomes and
should be added as a separate evaluation pipeline.

## Deterministic rules override the model

`PolicyEngine` enforces minimum severities and human-review requirements that the
LLM cannot override. The final severity is `max(model_severity, policy_minimum)`.

## Failure handling

| Failure | Behaviour |
|---------|-----------|
| Tool failure | Continue with remaining evidence, mark degraded, lower confidence |
| Tool timeout | Bounded retry, then degrade |
| Tool budget exhausted | Reject call, continue safely |
| Malformed LLM output | Fall back to deterministic triage |
| LLM unavailable | Fall back to deterministic triage |
| Conflicting evidence | Reduce confidence, require human review |
| Missing asset context | Record explicit uncertainty |
| Contradictory severity | Final severity >= policy minimum |

Tested in `tests/agent/test_failures.py`.

## Evaluation framework

`EvaluationRunner` runs a labelled dataset (10 cases covering malicious IP, suspicious
PowerShell, malicious hash, benign scanner, benign monitoring, malicious domain, brute
force, lateral movement, malicious URL, ambiguous authentication) and reports:

- classification accuracy
- severity agreement
- evidence grounding
- average tool calls
- average latency
- failure rate

Run with `threatlens evaluate`. Metrics are reported for the run that actually
executed; nothing is fabricated.

## Observability

Structured JSON logs carry `request_id`, `alert_id`, `triage_id`, and `agent_run_id`.
Every state transition, tool call, and policy decision is logged and audited. Metrics
cover triage latency, tool latency, tool errors, agent failures, alerts processed, and
classification/severity distributions, exposed at `/api/v1/metrics` and
`/api/v1/metrics/prometheus`. Optional OpenTelemetry OTLP export is enabled with
`OTEL_ENABLED=true` after installing `.[otel]`; it exports traces and mirrors the
existing counters/histograms without removing the local endpoints.

## Limitations

- Confidence is heuristic, not calibrated.
- Mock enrichment is deterministic; it is not a substitute for live reputation feeds.
- MITRE mapping is a local ruleset, not the full ATT&CK corpus.
- The mock LLM is rule-based; a real model may disagree with the deterministic signals.
- SQLite is the default; use PostgreSQL for concurrent deployments.
- PDF output requires WeasyPrint system libraries; HTML output is platform-independent.
- Metrics are process-local; use a Prometheus/OpenTelemetry collector for multi-worker deployments.
