package agenttrajectoryguard

import (
	"encoding/json"
	"strings"
)

// Level 1a verdict names.
const (
	// violationTaintExfiltration: data derived from a protected resource fed an
	// egress tool through a chain of individually benign steps.
	violationTaintExfiltration = "taint_exfiltration"
	// violationArgsTooDeep: argument JSON nested beyond maxJSONDepth (an
	// adversarial stack-overflow vector); descent stopped at the limit.
	violationArgsTooDeep = "args_too_deep"
)

// maxJSONDepth bounds recursion into argument JSON to defeat maliciously deep
// nesting that would otherwise overflow the stack.
const maxJSONDepth = 64

// defaultTaintSourceKeys / defaultTaintSinkKeys classify an argument's role by
// its JSON key. Sources are data being read or sent (the payload); sinks are
// write destinations / recipients. Anything else is neutral and ignored by
// taint. Operators extend these via cfg.TaintSourceKeys / TaintSinkKeys.
var (
	defaultTaintSourceKeys = []string{
		"src", "source", "input", "from", "read_from", "path", "file", "in",
		"query", "target_read",
		// egress payload keys: the data a send/upload tool actually exfiltrates.
		"attachment", "body", "data", "content", "payload",
	}
	defaultTaintSinkKeys = []string{
		"dst", "dest", "destination", "to", "output", "write_to", "out",
		"recipient", "url", "upload_to",
	}
)

// argRoles is the role-classified view of a step's arguments.
type argRoles struct {
	sources     []string
	sinks       []string
	neutral     []string // collected for auditability; never used for taint
	roleUnknown bool     // args were unkeyed (non-JSON) — role could not be inferred
	tooDeep     bool     // JSON nesting exceeded maxJSONDepth
}

// applyTaint runs Level 1a directed taint tracking for one step against the
// accumulated trajectory state. It mutates st.taintSet (respecting the taint
// cap) and returns any violations triggered by this step.
//
// Directed rule: taint flows only when a tainted (or protected) SOURCE token is
// present, and then only to this step's SINK tokens. An egress violation fires
// only when a tainted source feeds an egress tool — i.e. tainted data is
// actually leaving, not merely co-occurring in the same args blob.
func applyTaint(st *TrajectoryState, step Step, cfg *Config) []string {
	roles := extractRoles(step.args, cfg)

	var out []string
	if roles.tooDeep {
		out = append(out, violationArgsTooDeep)
	}

	// Strict mode: ambiguous (unkeyed) args do not propagate taint.
	if roles.roleUnknown && cfg.TaintStrictRoles {
		return out
	}

	if !anyTainted(st, cfg, roles.sources) {
		return out
	}

	// Tainted source present: taint flows to this step's sinks only.
	for _, snk := range roles.sinks {
		addTaint(st, cfg, snk)
	}

	if containsFold(cfg.EgressTools, step.toolName) {
		out = append(out, violationTaintExfiltration)
	}
	return out
}

// anyTainted reports whether any token is already tainted or matches a
// protected resource (the taint seed).
func anyTainted(st *TrajectoryState, cfg *Config, tokens []string) bool {
	for _, tok := range tokens {
		if st.taintSet[tok] || matchesProtected(cfg.ProtectedResources, tok) {
			return true
		}
	}
	return false
}

// addTaint records a derived tainted identity, enforcing the per-trajectory
// taint cap. A blocked new entry marks the trajectory truncated.
func addTaint(st *TrajectoryState, cfg *Config, tok string) {
	if st.taintSet[tok] {
		return
	}
	if cfg.MaxTaintEntries > 0 && len(st.taintSet) >= cfg.MaxTaintEntries {
		st.truncated = true
		return
	}
	st.taintSet[tok] = true
}

// extractRoles parses a tool's argument blob and classifies string scalars by
// their JSON key into sources, sinks, and neutral. Non-JSON args fall back to
// delimiter tokenization with every token treated as both source and sink
// (role_unknown), so unkeyed args still propagate taint unless strict mode is on.
func extractRoles(args string, cfg *Config) argRoles {
	args = strings.TrimSpace(args)
	if args == "" {
		return argRoles{}
	}
	var v any
	if err := json.Unmarshal([]byte(args), &v); err != nil {
		toks := splitTokens(args, cfg)
		return argRoles{sources: toks, sinks: toks, roleUnknown: true}
	}

	srcKeys := keySet(defaultTaintSourceKeys, cfg.TaintSourceKeys)
	sinkKeys := keySet(defaultTaintSinkKeys, cfg.TaintSinkKeys)
	r := argRoles{}
	// A top-level scalar (e.g. a bare JSON string) has no key: role unknown.
	walkJSON(v, "", 0, srcKeys, sinkKeys, &r)
	return r
}

// walkJSON descends a decoded JSON value, classifying each string scalar by the
// nearest enclosing object key. Array elements inherit their parent key.
func walkJSON(v any, key string, depth int, srcKeys, sinkKeys map[string]bool, r *argRoles) {
	if depth > maxJSONDepth {
		r.tooDeep = true
		return
	}
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return
		}
		switch {
		case key == "":
			// No enclosing key (top-level scalar): role cannot be inferred.
			r.roleUnknown = true
			r.sources = append(r.sources, s)
			r.sinks = append(r.sinks, s)
		case srcKeys[strings.ToLower(key)]:
			r.sources = append(r.sources, s)
		case sinkKeys[strings.ToLower(key)]:
			r.sinks = append(r.sinks, s)
		default:
			r.neutral = append(r.neutral, s)
		}
	case []any:
		for _, e := range t {
			walkJSON(e, key, depth+1, srcKeys, sinkKeys, r)
		}
	case map[string]any:
		for k, e := range t {
			walkJSON(e, k, depth+1, srcKeys, sinkKeys, r)
		}
	}
}

// keySet builds a lowercased lookup set from the defaults plus any extensions.
func keySet(defaults, extra []string) map[string]bool {
	m := make(map[string]bool, len(defaults)+len(extra))
	for _, k := range defaults {
		m[strings.ToLower(k)] = true
	}
	for _, k := range extra {
		m[strings.ToLower(k)] = true
	}
	return m
}

// splitTokens tokenizes a non-JSON arg string on structural delimiters while
// keeping path/identifier characters intact, so a path like /etc/secrets/x
// stays a single token. Keeps resource-like tokens (containing /.@) plus any
// token that matches a configured protected resource or destructive tool, so
// non-path identifiers such as a table name "production_db" are still caught.
func splitTokens(s string, cfg *Config) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ',', ';', ':', '=', '"', '\'',
			'{', '}', '[', ']', '(', ')', '<', '>', '|':
			return true
		}
		return false
	})
	var out []string
	for _, f := range fields {
		if len(f) <= 1 {
			continue
		}
		if strings.ContainsAny(f, "/.@") ||
			matchesProtected(cfg.ProtectedResources, f) ||
			containsFold(cfg.DestructiveTools, f) {
			out = append(out, f)
		}
	}
	return out
}
