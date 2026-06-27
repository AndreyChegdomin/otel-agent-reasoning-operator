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
