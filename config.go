package agenttrajectoryguard

import (
	"time"

	"go.opentelemetry.io/collector/component"
)

// VerdictMode controls what the processor does when an invariant is violated.
type VerdictMode string

const (
	// ModeAnnotate sets a security.violation attribute on offending spans and
	// passes the trace through unchanged. This is the safe default.
	ModeAnnotate VerdictMode = "annotate"
	// ModeDrop omits offending trajectory spans from the forwarded batch.
	ModeDrop VerdictMode = "drop"
)

// Config is the processor configuration, grouped by detection level: mode and
// eviction apply globally; the remaining fields configure Level 0 (per-step),
// Level 1a (taint), capacity caps, Level 1b (invariants, opt-in), Level 1c
// (shape-only), and Level 2 (consistency, opt-in) respectively.
type Config struct {
	// Mode selects verdict handling: "annotate" (default) or "drop".
	Mode VerdictMode `mapstructure:"mode"`

	// EvictionTimeout is how long an inactive trajectory lingers in the active
	// set before the reaper evicts it. Guards against unbounded memory growth
	// for trajectories whose invoke_agent span never closes.
	EvictionTimeout time.Duration `mapstructure:"eviction_timeout"`

	// DestructiveTools is the Level 0 denylist of gen_ai.tool.name values that
	// are considered destructive/egress actions (e.g. delete_file, rm). A
	// single span calling one of these against a protected resource is flagged
	// without any trajectory state.
	DestructiveTools []string `mapstructure:"destructive_tools"`

	// ProtectedResources lists protected resource identifiers, matched by path
	// segment/prefix, doublestar glob, or whole-token equality — never
	// substring. Entries must be resource-specific (concrete paths, globs, or
	// structured identifiers), not bare words. Empty means Level 0 never
	// flags. These also seed Level 1a taint tracking. See
	// docs/configuration.md for the full matching rules and rationale.
	ProtectedResources []string `mapstructure:"protected_resources"`

	// EgressTools is the set of gen_ai.tool.name values that send data out of
	// the trust boundary (send_email, http_post, upload, ...). A tainted value
	// reaching one of these is the Level 1a exfiltration violation.
	EgressTools []string `mapstructure:"egress_tools"`

	// TaintSourceKeys / TaintSinkKeys extend the baked-in defaults used to
	// classify a tool argument's role from its JSON key. Source keys mark data
	// being read/sent; sink keys mark write destinations. Taint flows from
	// tainted sources to sinks only; neutral keys (logs, context, metadata) are
	// ignored. Provided values are added to the defaults (see defaultTaint*Keys).
	TaintSourceKeys []string `mapstructure:"taint_source_keys"`
	TaintSinkKeys   []string `mapstructure:"taint_sink_keys"`

	// TaintStrictRoles, when true, makes steps with unkeyed args (role_unknown,
	// e.g. non-JSON args) NOT propagate taint — fewer false positives at the
	// cost of false negatives. Default false: such steps fall back to treating
	// every token as both source and sink.
	TaintStrictRoles bool `mapstructure:"taint_strict_roles"`

	// --- Capacity caps (anti-DoS; 0 = unlimited) ---

	// MaxStepsPerTrajectory caps the steps retained for one trajectory. Beyond
	// it the trajectory is marked truncated, emits trajectory_capacity_exceeded
	// once, and stops growing (still tracked for eviction).
	MaxStepsPerTrajectory int `mapstructure:"max_steps_per_trajectory"`

	// MaxTaintEntries caps the taint set size for one trajectory, with the same
	// truncation behavior as MaxStepsPerTrajectory.
	MaxTaintEntries int `mapstructure:"max_taint_entries"`

	// --- Level 1b state-machine invariants (all opt-in; zero/empty disables) ---

	// MaxDeletes flags a trajectory whose cumulative count of destructive-tool
	// calls exceeds this threshold. 0 disables.
	MaxDeletes int `mapstructure:"max_deletes"`

	// ForbiddenOrderings flags a trajectory where a "then" action occurs after
	// a "first" action has already happened in the same trajectory.
	ForbiddenOrderings []OrderingRule `mapstructure:"forbidden_orderings"`

	// MaxActionsPerWindow / RateWindow flag bursty action frequency: more than
	// MaxActionsPerWindow steps within a trailing RateWindow. Both must be set.
	MaxActionsPerWindow int           `mapstructure:"max_actions_per_window"`
	RateWindow          time.Duration `mapstructure:"rate_window"`

	// --- Level 1c shape-only detectors (payload-free; no arg content needed) ---

	// ShapeDetectorsEnabled turns on the Level 1c family (size/sequence
	// silhouettes). Default on: it works on privacy-preserving telemetry that
	// omits argument payloads.
	ShapeDetectorsEnabled bool `mapstructure:"shape_detectors_enabled"`

	// ReadTools / WriteTools classify tool names for shape detection (egress and
	// destructive reuse EgressTools / DestructiveTools). First-match wins;
	// unknown tools fall into class "other".
	ReadTools  []string `mapstructure:"read_tools"`
	WriteTools []string `mapstructure:"write_tools"`

	// Size-correlation exfil silhouette (C1).
	SizeReadThreshold  int64         `mapstructure:"size_read_threshold"`  // bytes; large-read trigger
	SizeEgressRatio    float64       `mapstructure:"size_egress_ratio"`    // egress/read size ratio to flag
	SizeWindowSteps    int           `mapstructure:"size_window_steps"`    // lookback in steps
	SizeWindowDuration time.Duration `mapstructure:"size_window_duration"` // lookback in time

	// SequencePatterns are named tool-CLASS sequences to flag (C2). Opt-in;
	// empty disables. Pattern tokens are classes (read/write/egress/
	// destructive/other) with an optional trailing "+" meaning one-or-more.
	SequencePatterns []SequencePattern `mapstructure:"sequence_patterns"`

	// --- Level 2 reasoning<->action consistency (opt-in; weakest layer) ---

	// ConsistencyEnabled turns on best-effort reasoning/action mismatch
	// detection. Off by default: reasoning is untrusted and this layer is
	// false-positive prone; the safety case does not depend on it.
	ConsistencyEnabled bool `mapstructure:"consistency_enabled"`
}

// OrderingRule is a forbidden temporal ordering of two tools within one
// trajectory: Then must not occur after First has occurred.
type OrderingRule struct {
	First string `mapstructure:"first"`
	Then  string `mapstructure:"then"`
}

// SequencePattern is a named tool-class sequence for Level 1c shape detection.
// Each Pattern token is a class name with an optional trailing "+" (one-or-more).
type SequencePattern struct {
	Name    string   `mapstructure:"name"`
	Pattern []string `mapstructure:"pattern"`
}

// Validate implements component.ConfigValidator.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeAnnotate, ModeDrop:
	default:
		return errInvalidMode
	}
	if c.EvictionTimeout <= 0 {
		return errInvalidEvictionTimeout
	}
	return nil
}

var _ component.Config = (*Config)(nil)
