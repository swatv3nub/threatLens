# threatlens

**Agentic security alert triage platform** — an AI agent that takes raw SIEM/EDR alerts, enriches them with external and internal context, reasons over the evidence, and produces concise analyst-ready triage notes.

The LLM is one component in a larger pipeline; deterministic processing, tool selection, evidence collection, policy enforcement, and output validation all live outside the model.

> **Status**: Production-quality portfolio project demonstrating SOC operations + AI agent reliability engineering.

---

## Architecture

```
Raw SIEM / EDR Alert
        │
        ▼
┌───────────────────┐
│ Ingestion Layer   │  → NormalizedAlert (Pydantic v2)
│ Parse + Validate  │     ingestion/{wazuh,suricata,elastic,synthetic}.py
│ + Normalize       │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Enrichment Agent  │  → EnrichmentContext
│                   │     enrichment/engine.py + registry.py
│ IP Reputation     │     VirusTotal / AbuseIPDB / Asset / History / MITRE
│ Domain Reputation │
│ Asset Context     │
│ Alert History     │
│ MITRE ATT&CK      │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Evidence Builder  │  → EvidenceBundle (deterministic, citable IDs)
│                   │     reasoning/evidence_builder.py
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Reasoning Engine  │  → ReasoningResult (structured JSON only)
│                   │     reasoning/engine.py + prompts.py
│ TP / FP / Escalate│
│ Severity          │
│ Confidence        │
│ Evidence refs     │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Confidence Calc   │  → Blended heuristic (model + evidence + tools)
│                   │     reasoning/confidence.py
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Policy Engine     │  → Deterministic guardrails (non-overridable)
│                   │     agents/policies.py
│ min severity HIGH │
│ escalation rules  │
│ human review req  │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Triage Output     │  → TriageResult (analyst note + JSON + PDF)
│                   │     models/triage.py + reports/renderer.py
└─────────┬─────────┘
```

### Component Responsibilities

| Layer | Package | Deterministic? | Responsibility |
|-------|---------|----------------|----------------|
| Ingestion | `ingestion/` | Yes | Source-specific parsing → `NormalizedAlert` |
| Enrichment | `enrichment/` | Mostly | Tool selection + allowlisted execution |
| Evidence | `reasoning/evidence_builder.py` | Yes | Turn tool output into citable `Evidence` objects |
| Reasoning | `reasoning/engine.py` | No (LLM) | Classification, severity, narrative |
| Confidence | `reasoning/confidence.py` | Yes | Blend model + evidence + tool reliability |
| Policy | `agents/policies.py` | Yes | Non-overridable safety constraints |
| Output | `models/triage.py`, `reports/` | Yes | Human-readable + structured result |

The agent state machine (`agents/state_machine.py`) makes every stage explicit and auditable. The LLM never controls transitions, tool selection, or final severity.

---

## Security Model

threatlens treats **itself as an attack surface**. Every alert field is assumed attacker-controlled.

### Prompt Injection Defense
- **Explicit system prompt separation**: `SYSTEM INSTRUCTIONS` | `SECURITY POLICY` | `UNTRUSTED ALERT DATA`
- **Input sanitization**: All alert fields truncated, control chars stripped
- **Injection scanner**: Detects patterns (`ignore previous instructions`, `call external URL`, etc.) in `command_line`, `url`, `domain`, `username`, `process_name`
- **Audit logging**: Suspicious patterns recorded; agent treats injection text as *data*, never as instruction
- **Test coverage**: `tests/security/test_prompt_injection.py`

### SSRF Protection
- **Outbound allowlist**: Only `www.virustotal.com`, `api.abuseipdb.com`, `api.openai.com` (configurable)
- **Private IP blocking**: RFC1918, loopback, link-local, metadata endpoints rejected at URL validation
- **Scheme allowlist**: Only `http`/`https`; `file:`, `gopher:`, `dict:` rejected

### Tool Allowlisting
- Only explicitly registered tools (`VirusTotalTool`, `AbuseIPDBTool`, `AssetContextTool`, `AlertHistoryTool`, `MitreLookupTool`) can ever be invoked
- The LLM **cannot** generate arbitrary HTTP requests
- Tool registry validates every call against the allowlist

### Rate Limiting & Budgets
- Per-client API rate limit (sliding window)
- Per-alert tool-call budget (default 10 calls)
- Per-tool retry budget with exponential backoff
- Global tool timeout (default 10s)

### Secret Management
- Zero hardcoded credentials
- `.env` file (gitignored) + `.env.example` template
- `SecretStr` wrapper prevents accidental logging of API keys
- Audit log redaction scrubs sensitive keys from persisted events

### Human-in-the-Loop
- **No automatic destructive actions** — the agent only *recommends*
- `action_executed: "none"` always
- Every `RecommendedAction` has `requires_human_approval: true`
- Policy engine forces `requires_human_review: true` on TP, degraded enrichment, or missing context

---

## Reliability Engineering

### Structured Outputs Only
The reasoning layer never consumes free-form text. The LLM must return JSON validating against `RawReasoningOutput`. Failures raise `StructuredGenerationError` → deterministic fallback.

### Evidence Grounding
Every meaningful conclusion references one or more `Evidence` objects. The engine resolves referenced IDs against the actual evidence list; unknown IDs are dropped and logged. Tests assert true-positive results carry evidence.

### Confidence is Computed, Not Trusted
`ConfidenceCalculator` blends:
```
final = 0.45 * model_confidence
      + 0.35 * evidence_confidence   (mean + source diversity bonus)
      + 0.20 * tool_reliability      (per-source weights)
      - contradiction_penalty        (conflicting enrichment)
      - missing_telemetry_penalty    (missing context, degraded tools)
```
Clamped to `[0.05, 0.99]`. **This is a heuristic, not a calibrated probability.** Documented as such in code and reports.

### Deterministic Guardrails
The `PolicyEngine` enforces non-overridable rules:
- Known malicious hash → minimum severity HIGH
- Malicious indicator + critical asset → minimum severity HIGH
- Critical asset + high alert severity → CRITICAL
- Benign classification with malicious indicator present → overridden to NEEDS_INVESTIGATION
- Degraded enrichment → human review required

### Failure Handling
| Failure | Behavior |
|---------|----------|
| Tool failure | Degrade gracefully, continue with remaining evidence, reduce confidence |
| LLM schema validation failure | Retry once, then deterministic fallback (`needs_investigation`, confidence ≤ 0.3) |
| LLM unavailable | Deterministic fallback |
| Tool budget exhausted | Skip remaining tools, continue with available evidence |
| Contradictory enrichment | Flag contradiction, reduce confidence, require human review |

---

## Quick Start

### Prerequisites
- Python 3.11+
- WeasyPrint system dependencies (for PDF): `pango`, `cairo`, `gdk-pixbuf`, `ffi` (see [WeasyPrint install guide](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html))

### Installation
```bash
# Clone and install
git clone <repo>
cd ThreatLens
pip install -e ".[dev]"    # includes weasyprint, pytest, ruff, mypy, bandit

# Optional OpenTelemetry OTLP traces and metrics
pip install -e "[otel]"

# Or just the core
pip install -e .
```

### Configuration
Copy `.env.example` to `.env` and adjust:
```bash
cp .env.example .env
# Edit: LLM_PROVIDER=mock (default) or openai, API keys, etc.
```

For production, set `APP_ENV=production`, `API_AUTH_ENABLED=true`, and provide a
long random `API_KEY`. Production startup rejects mock providers and missing provider
credentials.

For multiple tenants, use `API_CLIENTS` instead of a shared `API_KEY`:

```env
API_AUTH_ENABLED=true
API_CLIENTS={"tenant-a-analyst":{"role":"analyst","tenant_id":"tenant-a"},"tenant-a-viewer":{"role":"viewer","tenant_id":"tenant-a"}}
```

`viewer` can read, `analyst` can submit alerts and triage requests, and `admin` can
read metrics and administer all tenants. Tenant-scoped records are filtered in the
repository layer.

### Database Migrations

Apply migrations before using an existing local database, especially after pulling
changes that add or alter stored fields:

```bash
alembic upgrade head
```

This preserves existing data and brings SQLite or PostgreSQL to the current schema.
For a fresh development database, the same command is safe to run before starting
the API. Check the migration status with:

```bash
alembic current
```

### OpenTelemetry Export

OpenTelemetry is optional and disabled by default. Install the extra and configure an
OTLP HTTP collector such as the OpenTelemetry Collector, Grafana Alloy, or Jaeger:

```bash
pip install -e "[otel]"
OTEL_ENABLED=true
OTEL_SERVICE_NAME=threatlens
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
OTEL_EXPORTER_OTLP_HEADERS=
threatlens serve
```

The `/v1/metrics` and `/v1/metrics/prometheus` endpoints are available. OTLP export adds
distributed traces and mirrors counters/histograms to the collector. If the extra is
absent or the collector is unavailable, local logging and metrics continue to work.

### Run the Demo
```bash
# Single alert triage (CLI)
threatlens triage samples/synthetic/malicious_ip.json

# JSON output
threatlens triage samples/synthetic/malicious_ip.json --json

# Replay all synthetic scenarios
threatlens replay samples/synthetic/

# Run evaluation suite
threatlens evaluate

# Generate PDF report (requires WeasyPrint system deps)
threatlens triage samples/synthetic/malicious_ip.json
threatlens report <triage-id>  # PDF, with automatic HTML fallback
threatlens report <triage-id> --format html  # platform-independent HTML
```

### Start the API Server
```bash
threatlens serve
# or
make dev

# Health check
curl http://localhost:8000/v1/health

# Submit alert for triage
curl -X POST http://localhost:8000/v1/triage \
  -H "Content-Type: application/json" \
  -d '{"source": "synthetic", "alert": {...}}'
```

### Docker
```bash
docker compose up --build
# API at http://localhost:8000
```

### Production Deployment

Use the production compose file with an external PostgreSQL instance and inject
secrets through the environment or a secret manager:

```bash
$env:THREATLENS_API_KEY="replace-with-a-long-random-value"
$env:OPENAI_API_KEY="..."
$env:VIRUSTOTAL_API_KEY="..."
$env:ABUSEIPDB_API_KEY="..."
$env:DATABASE_URL="postgresql+psycopg://user:password@db/threatlens"
$env:THREATLENS_DOMAIN="api.triage.example.com"
docker compose -f docker-compose.production.yml up --build
```

The production compose file keeps the application private on the Docker network and
uses Caddy to terminate HTTPS on ports 80/443. Use your PostgreSQL provider's managed
backup and retention controls for production.

Production startup runs `alembic upgrade head` before starting multiple Uvicorn workers.
Redis provides the shared rate-limit state required across workers. For manual schema
operations, run `alembic upgrade head` with the production `DATABASE_URL`.

Phase 2 also adds RBAC and tenant-scoped storage. API clients are configured as JSON
in `API_CLIENTS`; use `viewer` for read-only access, `analyst` for alert submission
and triage, and `admin` for metrics and unrestricted access.

For development or a single-process SQLite pilot, create a backup with:

```bash
threatlens backup --output backups/threatlens.db
```

---

## Evaluation

Run the built-in evaluation suite against 10 curated scenarios:

```bash
threatlens evaluate
```

Output:
```
Evaluation Results
------------------------------
Alerts evaluated:        10
Classification accuracy: 100%
Severity agreement:      90%
Evidence grounded:       100%
Average tool calls:      4.2
Average latency:         0.00s
Failure rate:            0%
```

Metrics measured:
- **Classification accuracy** — exact match on TP/FP/benign/needs_investigation
- **Severity agreement** — exact match on informational/low/medium/high/critical
- **Evidence grounded** — % of triage results with ≥1 evidence object
- **Average tool calls** — efficiency of enrichment
- **Average latency** — end-to-end wall time
- **Failure rate** — % of cases with exceptions

---

## Testing

```bash
# All tests
make test          # or: pytest

# Lint
make lint          # or: ruff check .

# Type check
make typecheck     # or: mypy threatlens

# Security scan
make security      # or: bandit -c pyproject.toml -r threatlens

# Full check
make check
```

### Test Suite
- **Unit** (`tests/unit/`): Validation, ingestion, policies, rate limiter, confidence, allowlist
- **Agent** (`tests/agent/`): Triage agent happy path, state machine, failure modes
- **Integration** (`tests/integration/`): API, evaluation runner
- **Security** (`tests/security/`): Prompt injection, SSRF, secret redaction

---

## Project Structure

```
threatlens/
├── agents/           # State machine, policies, triage agent
├── api/              # FastAPI routes, schemas, dependencies
├── cli.py            # Typer CLI (ingest, triage, report, replay, evaluate, serve)
├── config.py         # Pydantic Settings (.env)
├── container.py      # Dependency injection / wiring
├── enrichment/       # Tool registry, engine, VirusTotal, AbuseIPDB, Asset, History, MITRE
├── evaluation/       # Dataset, runner, metrics
├── ingestion/        # Wazuh, Suricata, Elastic, Synthetic ingestors
├── llm/              # Provider abstraction (OpenAI, Mock), factory
├── models/           # Pydantic models (Alert, Evidence, Enrichment, Reasoning, Triage)
├── observability/    # JSON logging, metrics, tracing
├── reports/          # Jinja2 + WeasyPrint PDF/HTML renderer
├── security/         # Allowlist, audit, rate limiter, prompt guard, secrets, validation
├── storage/          # SQLAlchemy + SQLite (swap for Postgres)
└── reasoning/        # Engine, confidence, evidence builder, prompts
```

---

## Sample Alerts

| File | Description | Expected |
|------|-------------|----------|
| `samples/synthetic/syn-001.json` | Malicious IP → critical asset | TP / Critical |
| `samples/synthetic/syn-002.json` | Suspicious PowerShell | NI / Medium |
| `samples/synthetic/syn-003.json` | Known malicious hash | TP / High |
| `samples/synthetic/syn-004.json` | Benign vulnerability scanner | FP / Low |
| `samples/synthetic/syn-005.json` | Internal monitoring healthcheck | FP / Low |
| `samples/synthetic/syn-006.json` | Malicious DNS query | TP / High |
| `samples/synthetic/syn-007.json` | Failed login brute force → VPN | TP / Critical |
| `samples/synthetic/syn-008.json` | Lateral movement via SMB | NI / Medium |
| `samples/synthetic/syn-009.json` | Suspicious web request (malicious URL) | TP / High |
| `samples/synthetic/syn-010.json` | Ambiguous auth anomaly | NI / Medium |
| `samples/wazuh/alert.json` | Wazuh auth failure | — |
| `samples/suricata/eve.json` | Suricata C2 beacon | — |
| `samples/elastic/alert.json` | Elastic Encoded PowerShell | — |

---

## Known Limitations

| Area | Limitation |
|------|------------|
| **PDF on Windows** | WeasyPrint requires GTK/pango/cairo system libs; use `--format html` or install the native libraries |
| **Confidence calibration** | Heuristic blend; not a calibrated probability; treat it as a ranking signal, not a probability |
| **MITRE mapping** | Static local dataset; no live ATT&CK API |
| **Historical correlation** | SQLite is the default and is suitable for development/small deployments; use a PostgreSQL URL for concurrent deployments |
| **LLM provider** | OpenAI + Mock only; no local model (Ollama/vLLM) support yet |
| **Scale** | Metrics are process-local; run one worker per metrics stream or add an external Prometheus/OpenTelemetry collector for multi-worker deployments |

---

## Future Work

- Kafka / Elasticsearch ingestion connectors
- Real Wazuh / Suricata / EDR integrations
- SOAR integration (Cortex XSOAR, Splunk SOAR, etc.)
- Analyst feedback loop → model evaluation pipeline
- PostgreSQL + Alembic migrations
- OpenTelemetry + Prometheus exporter
- Calibrated confidence (temperature scaling / isotonic regression)
- Approval-based response actions (isolate host, block IP, disable account)
- Multi-tenant with RBAC

---

## License

MIT
