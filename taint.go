package agenttrajectoryguard

import (
	"encoding/json"
	"strings"
)

// violationTaintExfiltration is the Level 1a verdict: a value derived from a
// protected resource reached an egress action through a chain of individually
// benign steps.
const violationTaintExfiltration = "taint_exfiltration"

// applyTaint runs Level 1a taint tracking for a single step against the
// accumulated trajectory state. It mutates st.taintSet and returns the
// violation name when an egress step carries tainted data.
//
// Propagation is the classic conservative over-approximation: if a step
// references any tainted (or protected-seed) identifier, every identifier it
// references becomes tainted. This is intentionally "dumb": transparent and
// reproducible beats clever-but-opaque (see README non-goals).
func applyTaint(st *TrajectoryState, step Step, cfg *Config) (string, bool) {
	tokens := extractIdentifiers(step.args)
	if len(tokens) == 0 {
		return "", false
	}

	touchesTainted := false
	for _, tok := range tokens {
		if st.taintSet[tok] || matchesProtected(cfg.ProtectedResources, tok) {
			touchesTainted = true
			break
		}
	}
	if !touchesTainted {
		return "", false
	}

	// Propagate taint to everything this step touches.
	for _, tok := range tokens {
		st.taintSet[tok] = true
	}

	if containsFold(cfg.EgressTools, step.toolName) {
		return violationTaintExfiltration, true
	}
	return "", false
}

// extractIdentifiers pulls candidate resource identifiers out of a tool's
// argument blob. Arguments are JSON across the conventions we support, so we
// parse and collect every string scalar; non-JSON falls back to delimiter
// tokenization that preserves path-like tokens.
func extractIdentifiers(args string) []string {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(args), &v); err == nil {
		return collectStrings(v, nil)
	}
	return splitTokens(args)
}

// collectStrings recursively gathers string scalar values from a decoded JSON
// value (object values and array elements; object keys are ignored).
func collectStrings(v any, acc []string) []string {
	switch t := v.(type) {
	case string:
		if s := strings.TrimSpace(t); s != "" {
			acc = append(acc, s)
		}
	case []any:
		for _, e := range t {
			acc = collectStrings(e, acc)
		}
	case map[string]any:
		for _, e := range t {
			acc = collectStrings(e, acc)
		}
	}
	return acc
}

// splitTokens tokenizes a non-JSON arg string on structural delimiters while
// keeping path/identifier characters (/, ., _, -, @) intact, so a path like
// /etc/secrets/x stays a single token. Tokens of length <= 1 are dropped.
func splitTokens(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ',', ';', ':', '=', '"', '\'',
			'{', '}', '[', ']', '(', ')', '<', '>', '|':
			return true
		}
		return false
	})
	out := fields[:0]
	for _, f := range fields {
		// Keep only resource-like tokens (paths, URLs, emails, dotted names),
		// dropping bare argument keys such as "src"/"dst" that the JSON path
		// would have skipped anyway.
		if len(f) > 1 && strings.ContainsAny(f, "/.@") {
			out = append(out, f)
		}
	}
	return out
}
