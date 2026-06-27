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

// Config is the processor configuration. Only the fields needed for the
// skeleton (mode + eviction timeout) are populated for now; invariant-specific
// params (protected resources, thresholds) land with their respective levels.
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

	// ProtectedResources lists resource identifiers (substrings, matched
	// case-insensitively against span attribute values) that must not be the
	// target of a destructive tool. Empty means Level 0 never flags.
	// These also seed Level 1a taint tracking.
	ProtectedResources []string `mapstructure:"protected_resources"`

	// EgressTools is the set of gen_ai.tool.name values that send data out of
	// the trust boundary (send_email, http_post, upload, ...). A tainted value
	// reaching one of these is the Level 1a exfiltration violation.
	EgressTools []string `mapstructure:"egress_tools"`

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
}

// OrderingRule is a forbidden temporal ordering of two tools within one
// trajectory: Then must not occur after First has occurred.
type OrderingRule struct {
	First string `mapstructure:"first"`
	Then  string `mapstructure:"then"`
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
