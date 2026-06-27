# agent-trajectory-guard

An OpenTelemetry Collector **processor** (Go) that buffers AI-agent trajectories
by `trace_id` and runs **deterministic** adversarial invariants over them —
per-step, trajectory-level, and reasoning↔action consistency — flagging
violations in standard telemetry **before export** to any backend.

## Why

Most agent-observability tooling judges trajectories with an **LLM-as-judge**:
non-deterministic and gameable. An agent that splits a harmful goal into
individually-benign steps (read protected file → copy → rename → send) slips
past per-action checks *and* past nondeterministic judges.

This processor is a deterministic, transparent, **trajectory-aware** verifier on
the standard OTel GenAI telemetry bus. It catches the composite multi-step
attack that per-step and neuro-judge checks miss.

Threat model is **adversarial** (the agent actively evades), not "agent that
tries but errs".

## Where it sits

```
receiver → [ agent-trajectory-guard ] → exporter (Langfuse / Datadog / Tempo / …)
```

It sees every span before it leaves the perimeter, on the standard
**OpenTelemetry GenAI Semantic Conventions** bus — compatible with any
OTel-emitting framework and any OTLP backend.

> **Glass, not hand.** This lives in the *telemetry* path, not the *execution*
> path. It can DETECT and FLAG/ROUTE/DROP telemetry. It **cannot block the
> agent's execution** in real time. It is the eye, not the hand.

## Detection layers

| Level | File | What it catches |
|-------|------|-----------------|
| **0 — per-step** (stateless) | `perstep.go` | A single destructive tool call against a protected resource → `protected_resource_destruction`. |
| **1a — taint tracking** (the heart) | `taint.go` | A value derived from a protected resource reaching an egress action through a benign-looking chain → `taint_exfiltration`. |
| **1b — state-machine invariants** | `invariants.go` | `excessive_deletion`, `forbidden_ordering`, `action_rate_anomaly` (all opt-in). |
| **2 — reasoning↔action consistency** | `consistency.go` | Declared intent ≠ actual action → `reasoning_action_mismatch` (opt-in, weakest layer). |

### The fork (why Level 2 being weak doesn't matter)

- reasoning ≠ action → caught by Level 2 (consistency)
- reasoning = action but action is bad → caught by Level 1 (taint/invariants),
  because the harm is now in the honest action stream

The agent's truthfulness becomes irrelevant to safety. The safety case does
**not** depend on Level 2.

## Multi-convention normalization

Real instrumentations place tool calls differently. The normalization layer
(`normalize.go`) recognizes all three so detection is convention-agnostic:

| Convention | tool-call marker | tool name | arguments |
|---|---|---|---|
| OTel GenAI (canonical) | `gen_ai.operation.name=execute_tool` | `gen_ai.tool.name` | `gen_ai.tool.call.arguments` |
| OpenInference | `openinference.span.kind=TOOL` | `tool.name` | `tool.parameters` / `input.value` |
| OpenLLMetry | nested on chat span | `gen_ai.completion.{c}.tool_calls.{t}.name` | `…tool_calls.{t}.arguments` |

## Build & run

Build a custom collector embedding this processor via OCB:

```bash
go run go.opentelemetry.io/collector/cmd/builder@v0.155.0 --config builder-config.yaml
./_build/otelcol-trajectory-guard --config config.yaml
```

Send the demo exfiltration chain (OTLP/HTTP):

```bash
curl -s -X POST http://localhost:4318/v1/traces \
  -H "Content-Type: application/json" --data-binary @testdata/exfil-trace.json
```

The `send_email` span is annotated `security.violation: taint_exfiltration`;
the preceding `read_file` / `copy_file` / `rename_file` spans are untouched.

## Configuration

See `config.yaml` for the full example. Key fields:

```yaml
processors:
  agenttrajectoryguard:
    mode: annotate                 # annotate (default) | drop
    eviction_timeout: 5m
    destructive_tools: [delete_file, rm, drop_table]
    protected_resources: ["/etc/secrets", "production.db"]
    egress_tools: [send_email, http_post, upload_file]
    max_deletes: 5                 # Level 1b, 0 disables
    forbidden_orderings:
      - {first: read_file, then: http_post}
    max_actions_per_window: 50     # Level 1b
    rate_window: 10s
    consistency_enabled: false     # Level 2, off by default
```

## Output modes

- **annotate** — set `security.violation` on offending span(s), pass through.
- **drop** — omit offending spans from the forwarded batch.

## Non-goals / honest limits

- Not a research solution to faithfulness; reasoning is treated as **untrusted**.
- Not an execution blocker; telemetry-path detector only (eye, not hand).
- Not a neuro-judge; deterministic by design — transparent + reproducible over
  smart-but-opaque.
- Level 1a taint propagation is a **conservative over-approximation** (a step
  touching tainted data taints all its identifiers). This is intentional and
  may over-flag; it is tunable.
- No claim of completeness — by Rice's theorem no verifier catches all. The
  goal is to raise the cost of, and narrow the space of, undetected multi-step
  attacks.
