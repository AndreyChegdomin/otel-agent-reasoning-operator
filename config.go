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
	ProtectedResources []string `mapstructure:"protected_resources"`
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
