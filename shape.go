package agenttrajectoryguard

import "strings"

// Level 1c (shape-only) verdict names. These flag a SILHOUETTE resembling abuse
// from payload-free metadata (tool name, size, timing, sequence). They are
// suspicions for review, not proof — they cannot say WHAT was accessed/leaked.
const (
	violationSizeExfilSilhouette = "size_exfil_silhouette"
	// suspicious_sequence verdicts are suffixed with the matched pattern name.
	violationSuspiciousSeqPrefix = "suspicious_sequence:"
)

// Tool classes for shape detection.
const (
	classRead        = "read"
	classWrite       = "write"
	classEgress      = "egress"
	classDestructive = "destructive"
	classOther       = "other"
)

// maxSeqScanWindow bounds the sequence-matcher lookback so a very long
// trajectory cannot make matching quadratic. A pattern must start within this
// many steps of the latest one.
const maxSeqScanWindow = 1024

// toolClass maps a tool name to its class by config membership (first match
// wins: read, write, egress, destructive), defaulting to "other".
func toolClass(name string, cfg *Config) string {
	switch {
	case containsFold(cfg.ReadTools, name):
		return classRead
	case containsFold(cfg.WriteTools, name):
		return classWrite
	case containsFold(cfg.EgressTools, name):
		return classEgress
	case containsFold(cfg.DestructiveTools, name):
		return classDestructive
	default:
		return classOther
	}
}

// runShapeDetectors runs the Level 1c family against the latest step in state.
// It depends only on payload-free Step fields (toolName, sizes, ts, order).
func runShapeDetectors(st *TrajectoryState, cfg *Config) []string {
	var out []string
	if v, ok := checkSizeExfil(st, cfg); ok {
		out = append(out, v)
	}
	out = append(out, checkSequencePatterns(st, cfg)...)
	return out
}

// checkSizeExfil (C1): the latest step is an egress whose input size is
// comparable to a recent large read's result size — an exfiltration silhouette,
// inferred from sizes alone without seeing any content.
func checkSizeExfil(st *TrajectoryState, cfg *Config) (string, bool) {
	if len(st.steps) == 0 {
		return "", false
	}
	idx := len(st.steps) - 1
	cur := st.steps[idx]
	if toolClass(cur.toolName, cfg) != classEgress || cur.inputSize <= 0 {
		return "", false
	}
	for i := idx - 1; i >= 0; i-- {
		s := st.steps[i]
		// The window closes at whichever bound is reached first (steps or time);
		// a non-positive bound means that dimension is not limiting.
		withinStep := cfg.SizeWindowSteps <= 0 || (idx-i) <= cfg.SizeWindowSteps
		withinTime := cfg.SizeWindowDuration <= 0 || cur.ts.Sub(s.ts) <= cfg.SizeWindowDuration
		if !(withinStep && withinTime) {
			break
		}
		if toolClass(s.toolName, cfg) != classRead || s.resultSize < cfg.SizeReadThreshold {
			continue
		}
		// Most recent large read in window: compare egress size to it and stop.
		if float64(cur.inputSize) >= cfg.SizeEgressRatio*float64(s.resultSize) {
			return violationSizeExfilSilhouette, true
		}
		return "", false
	}
	return "", false
}

// seqToken is one element of a sequence pattern: a class, optionally one-or-more.
type seqToken struct {
	class string
	plus  bool
}

// checkSequencePatterns (C2): emit a suspicion for each configured tool-class
// pattern that matches a contiguous run ending at the latest step.
func checkSequencePatterns(st *TrajectoryState, cfg *Config) []string {
	if len(cfg.SequencePatterns) == 0 || len(st.steps) == 0 {
		return nil
	}
	classes := recentClasses(st, cfg)
	var out []string
	for _, p := range cfg.SequencePatterns {
		toks := parsePattern(p.Pattern)
		if len(toks) > 0 && seqMatchesEnd(toks, classes) {
			out = append(out, violationSuspiciousSeqPrefix+p.Name)
		}
	}
	return out
}

// recentClasses returns the tool classes of the most recent steps (bounded by
// maxSeqScanWindow), in order.
func recentClasses(st *TrajectoryState, cfg *Config) []string {
	start := 0
	if len(st.steps) > maxSeqScanWindow {
		start = len(st.steps) - maxSeqScanWindow
	}
	classes := make([]string, 0, len(st.steps)-start)
	for _, s := range st.steps[start:] {
		classes = append(classes, toolClass(s.toolName, cfg))
	}
	return classes
}

func parsePattern(pattern []string) []seqToken {
	toks := make([]seqToken, 0, len(pattern))
	for _, p := range pattern {
		if strings.HasSuffix(p, "+") {
			toks = append(toks, seqToken{class: strings.TrimSuffix(p, "+"), plus: true})
		} else {
			toks = append(toks, seqToken{class: p})
		}
	}
	return toks
}

// seqMatchesEnd reports whether the pattern matches a contiguous subsequence of
// classes that ends at the final class (so it fires when the shape completes).
func seqMatchesEnd(pat []seqToken, classes []string) bool {
	for start := 0; start <= len(classes); start++ {
		if consumeSeq(pat, classes[start:]) {
			return true
		}
	}
	return false
}

// consumeSeq matches pat against the entirety of cs (both must be fully consumed).
func consumeSeq(pat []seqToken, cs []string) bool {
	if len(pat) == 0 {
		return len(cs) == 0
	}
	t := pat[0]
	if !t.plus {
		if len(cs) == 0 || cs[0] != t.class {
			return false
		}
		return consumeSeq(pat[1:], cs[1:])
	}
	// one-or-more of t.class: count the run, then try each split.
	n := 0
	for n < len(cs) && cs[n] == t.class {
		n++
	}
	for k := 1; k <= n; k++ {
		if consumeSeq(pat[1:], cs[k:]) {
			return true
		}
	}
	return false
}
