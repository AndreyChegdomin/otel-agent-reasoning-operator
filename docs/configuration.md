# Configuration

Full field reference lives in godoc on `Config` (`config.go`). This document
carries the longer guidance that doesn't fit inline as a struct-field comment.
See `config.yaml` for a complete, annotated example.

## Protected-resource matching (`protected_resources`)

`ProtectedResources` lists protected resource identifiers. Matching is
resource-boundary aware, **not substring**, so a mere mention never matches:

- **path patterns** (contain `/`, e.g. `/etc/secrets`): exact or
  segment-prefix match (`/etc/secrets` protects `/etc/secrets/db` but not
  `/etc/secretsfoo`);
- **glob patterns** (contain `*` or `?`, e.g. `**/.env`, `**/secrets/**`):
  doublestar match against path-like candidates;
- **plain identifiers** (e.g. `production_db`): whole-token,
  case-insensitive equality (not a substring of another word).

Empty means Level 0 never flags. These entries also seed Level 1a taint
tracking.

**Entries MUST be resource-specific** — concrete paths (`/etc/secrets`),
globs (`**/.env`, `**/secrets/**`), or structured identifiers
(`production_db`). Do NOT use bare common words (`secrets`, `data`): a bare
word in free-text args is treated as a mention, not a resource reference, so
it will not match at Level 0 (and would only invite false positives if it
did). Specificity in config is what keeps detection precise.

## Level 1a taint role keys

`TaintSourceKeys` / `TaintSinkKeys` extend the baked-in defaults used to
classify a tool argument's role from its JSON key. Source keys mark data
being read/sent; sink keys mark write destinations. Taint flows from tainted
sources to sinks only; neutral keys (logs, context, metadata) are ignored.
Provided values are added to the defaults (see `defaultTaint*Keys`).

Extend these to match your instrumentation's argument schema — e.g.
Claude Code-style tools use `file_path` / `command`:

```yaml
taint_source_keys: [file_path, command, content]
taint_sink_keys: [file_path]
```

`TaintStrictRoles`, when true, makes steps with unkeyed args (role_unknown,
e.g. non-JSON args) NOT propagate taint — fewer false positives at the cost
of false negatives. Default false: such steps fall back to treating every
token as both source and sink.

## Level 1c shape-only thresholds

`ShapeDetectorsEnabled` turns on the Level 1c family (size/sequence
silhouettes). Default on: it works on privacy-preserving telemetry that
omits argument payloads. `ReadTools` / `WriteTools` classify tool names for
shape detection (egress and destructive tools reuse `EgressTools` /
`DestructiveTools`); first-match wins, unknown tools fall into class
"other".

Size-correlation exfil silhouette (C1):

| Field | Meaning |
|---|---|
| `size_read_threshold` | bytes; large-read trigger |
| `size_egress_ratio` | egress/read size ratio to flag |
| `size_window_steps` | lookback in steps |
| `size_window_duration` | lookback in time |

`SequencePatterns` (C2) are named tool-class sequences to flag. Opt-in;
empty disables. Pattern tokens are classes (read/write/egress/
destructive/other) with an optional trailing `+` meaning one-or-more:

```yaml
sequence_patterns:
  - name: recon_then_egress
    pattern: [read+, egress]
```

## Level 1b / Level 2 opt-ins

Level 1b state-machine invariants are all opt-in (zero/empty disables):

- `max_deletes` — flags a trajectory whose cumulative count of
  destructive-tool calls exceeds this threshold.
- `forbidden_orderings` — flags a trajectory where a "then" action occurs
  after a "first" action has already happened in the same trajectory.
- `max_actions_per_window` / `rate_window` — flag bursty action frequency
  (more than `max_actions_per_window` steps within a trailing
  `rate_window`); both must be set.

Level 2 reasoning↔action consistency (`consistency_enabled`) is off by
default: reasoning is untrusted and this layer is false-positive prone; the
safety case does not depend on it.
