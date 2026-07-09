package agenttrajectoryguard

import (
	"path"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
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
		if matchesProtectedText(cfg.ProtectedResources, tc.args) {
			return violationProtectedDestruction, true
		}
	}
	return "", false
}

// matchesProtectedToken reports whether a SINGLE candidate token denotes a
// protected resource. Matching is resource-boundary aware, NOT substring, so a
// mere mention never matches. Each protected entry is matched by, in order:
//
//  1. GLOB (entry has * or ?): doublestar match against the token as a path.
//     e.g. "**/.env" matches "/app/config/.env"; "**/secrets/**" matches
//     "/var/secrets/db/pw".
//  2. PATH (entry contains "/"): exact or segment-prefix match after
//     path.Clean. "/etc/secrets" protects "/etc/secrets" and "/etc/secrets/db"
//     but NOT "/etc/secretsfoo".
//  3. PLAIN identifier: whole-token case-insensitive equality. "production_db"
//     matches the token "production_db" but NOT "myproduction_db_backup".
func matchesProtectedToken(protected []string, token string) bool {
	if token == "" {
		return false
	}
	for _, entry := range protected {
		if entry == "" {
			continue
		}
		switch {
		case strings.ContainsAny(entry, "*?"):
			if ok, err := doublestar.Match(entry, token); err == nil && ok {
				return true
			}
		case strings.Contains(entry, "/"):
			ce := path.Clean(entry)
			ct := path.Clean(token)
			if ct == ce || strings.HasPrefix(ct, ce+"/") {
				return true
			}
		default:
			if strings.EqualFold(entry, token) {
				return true
			}
		}
	}
	return false
}

// matchesProtectedText tokenizes a free-text arg blob and runs the per-token
// matcher on every resource-shaped candidate token. A candidate is any token
// carrying a non-letter character (a path/URL/dotted-or-underscored identifier
// such as "/etc/secrets", "production.db", "production_db", "drop_table"); a
// bare run of letters (e.g. "secrets" in "grep secrets") is a mention, not a
// resource reference, and is not a candidate. Letting the per-token matcher
// then decide is what makes plain identifiers (rule 3) work in Level 0 free
// text, while still ignoring bare-word mentions. Used only by Level 0.
func matchesProtectedText(protected []string, text string) bool {
	if text == "" || len(protected) == 0 {
		return false
	}
	for _, tok := range argTokens(text) {
		if isResourceShaped(tok) && matchesProtectedToken(protected, tok) {
			return true
		}
	}
	return false
}

// isResourceShaped reports whether a token looks like a resource reference
// rather than a bare word: it contains at least one non-ASCII-letter rune
// (digit, "/", ".", "_", "-", "@", ...). A pure run of letters does not qualify.
func isResourceShaped(tok string) bool {
	for _, r := range tok {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return true
		}
	}
	return false
}

func containsFold(list []string, target string) bool {
	for _, s := range list {
		if strings.EqualFold(s, target) {
			return true
		}
	}
	return false
}
