package agenttrajectoryguard

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor/processortest"
)

func testPerStepConfig() *Config {
	return &Config{
		Mode:               ModeAnnotate,
		EvictionTimeout:    1,
		DestructiveTools:   []string{"delete_file", "rm"},
		ProtectedResources: []string{"/etc/secrets", "production.db"},
	}
}

// toolSpan builds an execute_tool span with the given tool and one arg-like
// string attribute carrying the target.
func toolSpan(tool, target string) ptrace.Span {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().
		ScopeSpans().AppendEmpty().
		Spans().AppendEmpty()
	span.Attributes().PutStr(attrOperationName, opExecuteTool)
	span.Attributes().PutStr(attrToolName, tool)
	if target != "" {
		span.Attributes().PutStr("gen_ai.tool.call.arguments", target)
	}
	return span
}

// TestMatchesProtectedToken covers boundary-aware matching of a single token:
// glob (rule 1), path segment/prefix (rule 2), whole-token identifier (rule 3).
func TestMatchesProtectedToken(t *testing.T) {
	cases := []struct {
		name      string
		protected []string
		token     string
		want      bool
	}{
		// positives — real access
		{"path dir-prefix", []string{"/etc/secrets"}, "/etc/secrets/db", true},
		{"path exact", []string{"/etc/secrets"}, "/etc/secrets", true},
		{"glob dotfile", []string{"**/.env"}, "/app/config/.env", true},
		{"glob nested", []string{"**/secrets/**"}, "/var/secrets/db/pw", true},
		{"plain identifier", []string{"production_db"}, "production_db", true},
		// negatives — the false positives we are killing
		{"path not on boundary", []string{"/etc/secrets"}, "/etc/secretsfoo/x", false},
		{"identifier not whole token", []string{"production_db"}, "myproduction_db_backup", false},
		{"identifier substring", []string{"secrets"}, "secrets_test.go", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesProtectedToken(tc.protected, tc.token); got != tc.want {
				t.Errorf("matchesProtectedToken(%v, %q) = %v, want %v", tc.protected, tc.token, got, tc.want)
			}
		})
	}
}

// TestMatchesProtectedText covers the free-text (Level 0) call site: only
// resource-shaped tokens are candidates, so bare-word mentions don't match.
func TestMatchesProtectedText(t *testing.T) {
	cases := []struct {
		name      string
		protected []string
		text      string
		want      bool
	}{
		{"bare word in command", []string{"secrets"}, "grep -rn secrets .", false},
		{"substring filename", []string{"secrets"}, "secrets_test.go", false},
		{"dotted name as own token", []string{"production.db"}, "migrated production.db yesterday", true},
		{"real path arg", []string{"/etc/secrets"}, `{"file":"/etc/secrets/key.pem"}`, true},
		{"path mention inside sentence", []string{"/etc/secrets"}, "please read /etc/secrets/key.pem later", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesProtectedText(tc.protected, tc.text); got != tc.want {
				t.Errorf("matchesProtectedText(%v, %q) = %v, want %v", tc.protected, tc.text, got, tc.want)
			}
		})
	}
}

func TestCheckPerStep(t *testing.T) {
	cfg := testPerStepConfig()
	cases := []struct {
		name     string
		tool     string
		target   string
		wantFlag bool
	}{
		{"destructive on protected", "delete_file", "/etc/secrets/key.pem", true},
		{"destructive case-insensitive resource", "rm", "PRODUCTION.DB", true},
		{"destructive on benign target", "delete_file", "/tmp/scratch.txt", false},
		{"benign tool on protected", "read_file", "/etc/secrets/key.pem", false},
		{"destructive no target", "rm", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := checkPerStep(cfg, toolSpan(tc.tool, tc.target))
			if ok != tc.wantFlag {
				t.Fatalf("flag = %v, want %v (violation=%q)", ok, tc.wantFlag, v)
			}
			if ok && v != violationProtectedDestruction {
				t.Errorf("violation = %q, want %q", v, violationProtectedDestruction)
			}
		})
	}
}

// runProcessor pushes one execute_tool span through a processor with the given
// config and returns the span the sink received (or nil if dropped).
func runProcessor(t *testing.T, cfg *Config, tool, target string) ptrace.Span {
	t.Helper()
	sink := &consumertest.TracesSink{}
	p := newGuardProcessor(processortest.NewNopSettings(componentType), cfg, sink)

	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.Attributes().PutStr(attrOperationName, opExecuteTool)
	span.Attributes().PutStr(attrToolName, tool)
	span.Attributes().PutStr("gen_ai.tool.call.arguments", target)

	if err := p.ConsumeTraces(context.Background(), td); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}
	got := sink.AllTraces()
	if len(got) == 0 {
		return ptrace.Span{}
	}
	spans := got[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	if spans.Len() == 0 {
		return ptrace.Span{}
	}
	return spans.At(0)
}

func TestAnnotateModeFlagsSpan(t *testing.T) {
	cfg := testPerStepConfig()
	span := runProcessor(t, cfg, "delete_file", "/etc/secrets/key.pem")
	v, ok := span.Attributes().Get(attrViolation)
	if !ok {
		t.Fatal("expected security.violation attribute on offending span")
	}
	if v.AsString() != violationProtectedDestruction {
		t.Errorf("violation = %q, want %q", v.AsString(), violationProtectedDestruction)
	}
}

func TestAnnotateModeLeavesBenignSpan(t *testing.T) {
	cfg := testPerStepConfig()
	span := runProcessor(t, cfg, "delete_file", "/tmp/scratch.txt")
	if _, ok := span.Attributes().Get(attrViolation); ok {
		t.Error("benign span should not be annotated")
	}
}

func TestDropModeRemovesOffendingSpan(t *testing.T) {
	cfg := testPerStepConfig()
	cfg.Mode = ModeDrop
	span := runProcessor(t, cfg, "delete_file", "/etc/secrets/key.pem")
	if span != (ptrace.Span{}) {
		t.Error("offending span should be dropped in drop mode")
	}
}
