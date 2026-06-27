package agenttrajectoryguard

import (
	"sort"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

func consistencyCfg(enabled bool) *Config {
	return &Config{
		Mode:               ModeAnnotate,
		EvictionTimeout:    time.Minute,
		DestructiveTools:   []string{"delete_file"},
		EgressTools:        []string{"send_email"},
		ConsistencyEnabled: enabled,
	}
}

// chatSpanWithReasoning builds a chat span carrying reasoning text in both an
// event blob and the output messages attribute.
func chatSpanWithReasoning(traceID [16]byte, eventText, outputMsg string) ptrace.Span {
	s := newSpan()
	s.SetTraceID(traceID)
	s.Attributes().PutStr(attrOperationName, "chat")
	s.Attributes().PutStr(attrOutputMessages, outputMsg)
	ev := s.Events().AppendEmpty()
	ev.SetName(eventText)
	return s
}

func TestExtractReasoning(t *testing.T) {
	s := chatSpanWithReasoning([16]byte{1}, "Thinking: I will SEND_EMAIL", `{"content":"plan: send_email then stop"}`)
	got := extractReasoning(s)
	if !strings.Contains(got, "send_email") {
		t.Errorf("reasoning %q missing expected token", got)
	}
}

func TestDeclaredTools(t *testing.T) {
	vocab := []string{"delete_file", "send_email", "http_post"}
	got := declaredTools("i will send_email and maybe delete_file", vocab)
	sort.Strings(got)
	want := []string{"delete_file", "send_email"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v", got, want)
	}
}

// observeChainForConsistency feeds a reasoning span then an action span through
// a tracker and returns the violations from the action span.
func observeChainForConsistency(t *testing.T, cfg *Config, declaredText, actualTool string) []string {
	t.Helper()
	tr := newTracker(cfg, zap.NewNop())
	id := [16]byte{9}
	tr.observe(chatSpanWithReasoning(id, "", declaredText))

	act := newSpan()
	act.SetTraceID(id)
	act.Attributes().PutStr(attrOperationName, "execute_tool")
	act.Attributes().PutStr(attrToolName, actualTool)
	act.Attributes().PutStr(attrToolCallArgs, `{"x":"y"}`)
	return tr.observe(act)
}

func TestConsistencyMismatchFlagged(t *testing.T) {
	// Declares send_email, actually calls delete_file -> mismatch.
	v := observeChainForConsistency(t, consistencyCfg(true), `{"content":"i will send_email"}`, "delete_file")
	if !containsStr(v, violationReasoningActionMismatch) {
		t.Errorf("expected %s, got %v", violationReasoningActionMismatch, v)
	}
}

func TestConsistencyMatchNotFlagged(t *testing.T) {
	// Declares send_email and actually calls send_email -> no mismatch.
	v := observeChainForConsistency(t, consistencyCfg(true), `{"content":"i will send_email"}`, "send_email")
	if containsStr(v, violationReasoningActionMismatch) {
		t.Errorf("matching action should not flag: %v", v)
	}
}

func TestConsistencyDisabledByDefault(t *testing.T) {
	v := observeChainForConsistency(t, consistencyCfg(false), `{"content":"i will send_email"}`, "delete_file")
	if containsStr(v, violationReasoningActionMismatch) {
		t.Errorf("disabled consistency should not flag: %v", v)
	}
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
