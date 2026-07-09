# agent-trajectory-guard

[![CI](https://github.com/AndreyChegdomin/agent-trajectory-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/AndreyChegdomin/agent-trajectory-guard/actions/workflows/ci.yml)

An OpenTelemetry Collector processor (Go) that buffers AI-agent trajectories by
`trace_id` and runs deterministic adversarial invariants over them — per-step,
trajectory-level, and reasoning↔action consistency — flagging violations in
standard telemetry **before export** to any backend.

Module: `github.com/AndreyChegdomin/agent-trajectory-guard`
(Go package name: `agenttrajectoryguard`).

## Why

Most agent-observability tooling judges trajectories with an LLM-as-judge:
non-deterministic and gameable. An agent that splits a harmful goal into
individually benign steps (read protected file → copy → rename → send) slips
past per-action checks and past nondeterministic judges alike.

This processor is a deterministic, transparent, **trajectory-aware** verifier
on the standard OTel GenAI telemetry bus. It targets the composite multi-step
attack that per-step and LLM-judge checks miss.

The threat model is adversarial (the agent actively evades), not an agent that
tries but errs.

## Where it sits

```
receiver → [ agent-trajectory-guard ] → exporter (Langfuse / Datadog / Tempo / …)
```

It sees every span before it leaves the perimeter, on the standard
OpenTelemetry GenAI Semantic Conventions bus — compatible with any
OTel-emitting framework and any OTLP backend.

It lives in the telemetry path, not the execution path: it can detect and
flag/route/drop telemetry, but it **cannot block** the agent's execution in
real time. It is the eye, not the hand.

## Detection layers

| Level | File | What it catches |
|-------|------|-----------------|
| 0 — per-step (stateless) | `perstep.go` | A single destructive tool call against a protected resource (matched by path segment / glob / whole token, not substring) → `protected_resource_destruction`. |
| 1a — taint tracking | `taint.go` | A value derived from a protected resource reaching an egress action through a benign-looking chain → `taint_exfiltration`. **Directed data-flow by argument role** (tainted source → sink), not co-occurrence. |
| 1b — state-machine invariants | `invariants.go` | `excessive_deletion`, `forbidden_ordering`, `action_rate_anomaly` (all opt-in). |
| 1c — shape-only (payload-free) | `shape.go` | `size_exfil_silhouette` (large read → comparable egress by size), `suspicious_sequence:<name>` (bad tool-class sequence), reuses `action_rate_anomaly`. Needs **no argument payloads**. |
| 2 — reasoning↔action consistency | `consistency.go` | Declared intent ≠ actual action → `reasoning_action_mismatch` (opt-in, weakest layer). |

### The fork (why Level 2 being weak doesn't matter)

- reasoning ≠ action → caught by Level 2 (consistency)
- reasoning = action but action is bad → caught by Level 1 (taint/invariants),
  because the harm is now in the honest action stream

The agent's truthfulness becomes irrelevant to safety. The safety case does
**not** depend on Level 2.

## Multi-convention normalization

Real instrumentations place tool calls differently. The normalization layer
(`normalize.go`) recognizes all three, so detection is convention-agnostic:

| Convention | tool-call marker | tool name | arguments |
|---|---|---|---|
| OTel GenAI (canonical) | `gen_ai.operation.name=execute_tool` | `gen_ai.tool.name` | `gen_ai.tool.call.arguments` |
| OpenInference | `openinference.span.kind=TOOL` | `tool.name` | `tool.parameters` / `input.value` |
| OpenLLMetry | nested on chat span | `gen_ai.completion.{c}.tool_calls.{t}.name` | `…tool_calls.{t}.arguments` |

## Telemetry requirements — content-aware vs shape-only

Different layers need different telemetry. This matters because many production
agents (e.g. Claude Code's native OTel) **deliberately omit** tool-call
argument payloads for privacy, emitting only tool name, sizes
(`tool_input_size_bytes`, `tool_result_size_bytes`), timing, and the call
graph.

| Layer | Needs | Works on |
|---|---|---|
| 1a taint (content-aware) | tool-call **arguments** | self-hosted / fully-instrumented agents (OpenLLMetry / OpenInference with arg capture). Inert when args are redacted. |
| 1c shape (shape-only) | tool name + size + timing + sequence | privacy-preserving / managed agents that omit arg payloads. |

Privacy cuts both ways here: Level 1c needs no argument payloads, so it runs
on redacted telemetry without ever seeing secrets. Recommendation: enable 1c
always; enable 1a additionally when arguments are present.

See [docs/real-run-notes.md](docs/real-run-notes.md) for lab notes from
running the processor against real (Claude Code) telemetry — including the
finding that its native telemetry omits argument payloads entirely (names and
sizes only), which is exactly the gap the shape-only layer covers.

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

See [`config.yaml`](config.yaml) for a complete annotated example and
[docs/configuration.md](docs/configuration.md) for long-form guidance
(protected-resource matching semantics, taint role keys, shape-detector
tuning). Key fields:

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

In both modes, the per-span violation list is deduplicated: a span whose tool
calls trip the same rule repeatedly reports it once. The `security.violation`
attribute carries the primary (first, highest-ranked) violation; multi-step
findings such as taint outrank per-step ones.

## Trajectory verdict span

Per-span annotations tell you which span violated; they don't summarize the
trajectory. On eviction — when the root `invoke_agent` span has been observed
(the eviction itself happens at the next reaper sweep, up to ~30s later; the
sweep interval is fixed at 30s), when the trajectory has been inactive longer
than `eviction_timeout`, or on collector shutdown flush — a trajectory that
accumulated violations emits one synthetic span downstream:

- name `trajectory.verdict`, same `trace_id` as the trajectory, fresh span ID,
  kind Internal, zero duration, timestamped at eviction;
- `security.violation` — the primary (first observed) violation;
- `security.violations` — the full list, order-preserving and deduplicated
  across the trajectory's lifetime;
- `trajectory.steps` — number of tool-call steps retained (the count stops at
  `max_steps_per_trajectory` when truncated);
- `trajectory.truncated` — whether a capacity cap stopped state growth;
- `trajectory.root_closed` — whether the root span was seen (vs timeout
  eviction).

The verdict span covers the stateful findings (Levels 1a/1b/1c/2) accumulated
across the trajectory; Level 0 per-step findings are annotated on the
offending span at detection time and are not repeated in the verdict span.

Clean trajectories emit nothing (a debug log line only). The verdict span is
advisory telemetry: delivery failures are logged, not retried.

Known edge: spans arriving after a root-closed eviction re-create the
trajectory state, so one trace can be evicted twice and — if the late spans
also violate — produce a second `trajectory.verdict` span for the same
`trace_id`.

## Internal metrics

The processor reports its own health via the collector's standard internal
telemetry (prefix `otelcol_agenttrajectoryguard_`):

| Metric | Type | Meaning |
|---|---|---|
| `trajectories_active` | up-down counter | live trajectories currently buffered |
| `trajectories_evicted_total` | counter | trajectories finalized (root closed, timed out, or shutdown flush) |
| `violations_total` | counter, `violation` attribute | violations recorded, per violation name |
| `spans_dropped_total` | counter | spans removed in `drop` mode |

Instrument-creation failures degrade to no-ops; they never fail the processor.

## Non-goals / honest limits

- Not a research solution to faithfulness; reasoning is treated as untrusted.
- Not an execution blocker; a telemetry-path detector only.
- Not an LLM judge; deterministic by design — transparent and reproducible
  over smart-but-opaque.
- Level 1a taint is **directed data-flow by argument role**: a tainted *source*
  argument (classified by JSON key) propagates only to that step's *sink*
  arguments, and an egress violation requires a tainted source actually feeding
  an egress tool — not mere co-occurrence in the args blob. Role inference is a
  heuristic, tunable via `taint_source_keys` / `taint_sink_keys`; unkeyed
  (non-JSON) args fall back to a conservative source∪sink treatment unless
  `taint_strict_roles` is set.
- Protected-resource matching (Level 0 seed and Level 1a taint seed) is by
  path segment / doublestar glob / whole token — **not substring**. A free-text
  mention of a protected name (`grep secrets`, `secrets_test.go`,
  `/etc/secretsfoo`) is intentionally not flagged: mention ≠ access. This is a
  deliberate false-positive reduction; tune with paths/globs (`/etc/secrets`,
  `**/.env`) rather than bare words.
- Per-trajectory caps (`max_steps_per_trajectory`, `max_taint_entries`) and a
  JSON-depth limit bound memory/stack against adversarial floods; tripping a
  cap emits `trajectory_capacity_exceeded` (deep args emit `args_too_deep`).
- Level 1c shape detectors flag **silhouettes** (size/sequence/rate resembling
  abuse); they cannot identify what was accessed or leaked, only that the
  shape is suspicious. They raise suspicion for review, not proof, and are
  tunable — expect per-deployment tuning of thresholds, tool classes, and
  patterns.
- No claim of completeness — by Rice's theorem no verifier catches all. The
  goal is to raise the cost of, and narrow the space of, undetected multi-step
  attacks.

## Documentation

- [docs/configuration.md](docs/configuration.md) — long-form configuration
  guidance (matching semantics, taint roles, shape tuning).
- [docs/real-run-notes.md](docs/real-run-notes.md) — notes from a run against
  real agent telemetry (negative control; parsing and false-positive
  findings).

## License

[Apache-2.0](LICENSE).
