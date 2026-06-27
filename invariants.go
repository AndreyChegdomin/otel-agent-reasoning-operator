package agenttrajectoryguard

import "strings"

// Level 1b verdict names and state counter keys.
const (
	violationExcessiveDeletion = "excessive_deletion"
	violationForbiddenOrdering = "forbidden_ordering"
	violationActionRateAnomaly = "action_rate_anomaly"

	counterDeletes = "deletes"
)

// runInvariants applies every Level 1b state-machine invariant to the newly
// appended step against accumulated trajectory state, returning the names of
// any triggered violations. Each invariant is a plain function of
// (state, newStep, cfg) and is a no-op unless its config is set.
//
// Precondition: step is already the last element of st.steps.
func runInvariants(st *TrajectoryState, step Step, cfg *Config) []string {
	var out []string
	if v, ok := checkExcessiveDeletion(st, step, cfg); ok {
		out = append(out, v)
	}
	if v, ok := checkForbiddenOrdering(st, step, cfg); ok {
		out = append(out, v)
	}
	if v, ok := checkActionRate(st, step, cfg); ok {
		out = append(out, v)
	}
	return out
}

// checkExcessiveDeletion counts destructive-tool calls across the trajectory
// and flags once the cumulative count exceeds cfg.MaxDeletes.
func checkExcessiveDeletion(st *TrajectoryState, step Step, cfg *Config) (string, bool) {
	if cfg.MaxDeletes <= 0 || !containsFold(cfg.DestructiveTools, step.toolName) {
		return "", false
	}
	st.counters[counterDeletes]++
	if st.counters[counterDeletes] > cfg.MaxDeletes {
		return violationExcessiveDeletion, true
	}
	return "", false
}

// checkForbiddenOrdering flags when the current step is a rule's "then" action
// and the rule's "first" action already occurred earlier in the trajectory.
func checkForbiddenOrdering(st *TrajectoryState, step Step, cfg *Config) (string, bool) {
	for _, rule := range cfg.ForbiddenOrderings {
		if !strings.EqualFold(step.toolName, rule.Then) {
			continue
		}
		// Scan history excluding the current (last) step.
		for i := 0; i < len(st.steps)-1; i++ {
			if strings.EqualFold(st.steps[i].toolName, rule.First) {
				return violationForbiddenOrdering, true
			}
		}
	}
	return "", false
}

// checkActionRate flags bursty behavior: more than MaxActionsPerWindow steps
// within the trailing RateWindow ending at the current step's timestamp.
func checkActionRate(st *TrajectoryState, step Step, cfg *Config) (string, bool) {
	if cfg.MaxActionsPerWindow <= 0 || cfg.RateWindow <= 0 {
		return "", false
	}
	cutoff := step.ts.Add(-cfg.RateWindow)
	count := 0
	// steps are appended in arrival (timestamp) order, so we can stop early.
	for i := len(st.steps) - 1; i >= 0; i-- {
		if st.steps[i].ts.Before(cutoff) {
			break
		}
		count++
	}
	if count > cfg.MaxActionsPerWindow {
		return violationActionRateAnomaly, true
	}
	return "", false
}
