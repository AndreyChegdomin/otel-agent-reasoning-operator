package agenttrajectoryguard

import (
	"strings"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// GenAI operation names and verdict attribute keys.
const (
	opExecuteTool = "execute_tool"

	// attrViolation is set on offending spans in annotate mode.
	attrViolation = "security.violation"

	// violationProtectedDestruction is the Level 0 verdict: a destructive tool
	// targeting a protected resource in a single step.
	violationProtectedDestruction = "protected_resource_destruction"
)

// checkPerStep is the Level 0 (stateless) verifier. It flags a span whose tool
// invocation uses a destructive tool against a protected resource. Tool calls
// are extracted via the normalization layer, so this works across OTel GenAI,
// OpenInference, and OpenLLMetry span layouts.
func checkPerStep(cfg *Config, span ptrace.Span) (string, bool) {
	for _, tc := range extractToolCalls(span) {
		if !containsFold(cfg.DestructiveTools, tc.name) {
			continue
		}
		if matchesProtected(cfg.ProtectedResources, tc.args) {
			return violationProtectedDestruction, true
		}
	}
	return "", false
}

// matchesProtected reports whether text contains any protected-resource
// substring (case-insensitive).
func matchesProtected(protected []string, text string) bool {
	if text == "" || len(protected) == 0 {
		return false
	}
	low := strings.ToLower(text)
	for _, res := range protected {
		if strings.Contains(low, strings.ToLower(res)) {
			return true
		}
	}
	return false
}

// containsFold reports whether list contains target, case-insensitively.
func containsFold(list []string, target string) bool {
	for _, s := range list {
		if strings.EqualFold(s, target) {
			return true
		}
	}
	return false
}
