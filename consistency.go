package agenttrajectoryguard

import (
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// violationReasoningActionMismatch is the Level 2 verdict: the agent's stated
// intent named a different action than the one it actually took.
const violationReasoningActionMismatch = "reasoning_action_mismatch"

// attrOutputMessages carries the model's output (reasoning + tool decisions).
const attrOutputMessages = "gen_ai.output.messages"

// extractReasoning gathers the untrusted reasoning blob for a span from its
// events (an unstructured text blob per the GenAI conventions) and its output
// messages attribute. Returned lowercased for case-insensitive matching.
//
// HARD CAVEAT: reasoning is attacker-controlled and may be fabricated. This is
// best-effort; see the §4 fork — Level 1 catches harm regardless of what the
// reasoning claims.
func extractReasoning(span ptrace.Span) string {
	var b strings.Builder
	events := span.Events()
	for i := 0; i < events.Len(); i++ {
		ev := events.At(i)
		b.WriteString(ev.Name())
		b.WriteByte(' ')
		ev.Attributes().Range(func(_ string, v pcommon.Value) bool {
			b.WriteString(v.AsString())
			b.WriteByte(' ')
			return true
		})
	}
	if v, ok := span.Attributes().Get(attrOutputMessages); ok {
		b.WriteString(v.AsString())
	}
	return strings.ToLower(b.String())
}

// declaredTools returns the vocabulary tools mentioned in the reasoning text.
func declaredTools(reasoning string, vocab []string) []string {
	if reasoning == "" {
		return nil
	}
	var out []string
	for _, tool := range vocab {
		if tool != "" && strings.Contains(reasoning, strings.ToLower(tool)) {
			out = append(out, tool)
		}
	}
	return out
}

// consistencyVocab is the set of tool names the consistency check looks for in
// reasoning: the security-relevant tools (destructive + egress).
func consistencyVocab(cfg *Config) []string {
	vocab := make([]string, 0, len(cfg.DestructiveTools)+len(cfg.EgressTools))
	vocab = append(vocab, cfg.DestructiveTools...)
	vocab = append(vocab, cfg.EgressTools...)
	return vocab
}

// checkConsistency flags when a declared intent exists for the trajectory but
// the actual action taken is not among the declared tools.
func checkConsistency(st *TrajectoryState, step Step, cfg *Config) (string, bool) {
	if !cfg.ConsistencyEnabled || len(st.pendingIntent) == 0 {
		return "", false
	}
	for _, declared := range st.pendingIntent {
		if strings.EqualFold(declared, step.toolName) {
			return "", false // action matches a declared intent
		}
	}
	return violationReasoningActionMismatch, true
}
