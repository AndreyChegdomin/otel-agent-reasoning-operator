// Package agenttrajectoryguard is an OpenTelemetry Collector processor that
// detects adversarial AI-agent trajectories: multi-step attacks where each
// individual action looks benign but the sequence is not. It buffers spans by
// trace_id and runs deterministic checks at several levels:
//
//   - Level 0 per-step: a destructive tool call against a protected resource
//     in a single span.
//   - Level 1a taint: directed data-flow tracking; a tainted source reaching
//     an egress tool is flagged as exfiltration.
//   - Level 1b invariants: excessive_deletion, forbidden_ordering,
//     action_rate_anomaly (opt-in).
//   - Level 1c shape-only: payload-free silhouettes from tool name, size,
//     timing, and sequence.
//   - Level 2 consistency: declared intent vs. actual tool use (opt-in,
//     weakest layer).
//
// It lives in the telemetry path, not the execution path: it can detect and
// flag or drop telemetry, but it cannot block the agent's execution in real
// time. It is the eye, not the hand.
package agenttrajectoryguard
