package agenttrajectoryguard

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor/processortest"
)

func TestFactoryDefaultConfig(t *testing.T) {
	f := NewFactory()
	cfg, ok := f.CreateDefaultConfig().(*Config)
	if !ok {
		t.Fatalf("default config is not *Config")
	}
	if cfg.Mode != ModeAnnotate {
		t.Errorf("default mode = %q, want %q", cfg.Mode, ModeAnnotate)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("default config invalid: %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	bad := &Config{Mode: "nonsense", EvictionTimeout: 1}
	if err := bad.Validate(); err == nil {
		t.Error("expected error for invalid mode")
	}
	zeroTimeout := &Config{Mode: ModeAnnotate}
	if err := zeroTimeout.Validate(); err == nil {
		t.Error("expected error for zero eviction_timeout")
	}
}

// newGenAITrace builds a one-span trace carrying GenAI attributes.
func newGenAITrace(opName, toolName string) ptrace.Traces {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().
		ScopeSpans().AppendEmpty().
		Spans().AppendEmpty()
	span.SetName("test-span")
	span.Attributes().PutStr(attrOperationName, opName)
	if toolName != "" {
		span.Attributes().PutStr(attrToolName, toolName)
	}
	return td
}

func TestConsumeTracesPassesThrough(t *testing.T) {
	sink := &consumertest.TracesSink{}
	f := NewFactory()
	p, err := f.CreateTraces(context.Background(), processortest.NewNopSettings(componentType), f.CreateDefaultConfig(), sink)
	if err != nil {
		t.Fatalf("CreateTraces: %v", err)
	}

	in := newGenAITrace("execute_tool", "read_file")
	if err := p.ConsumeTraces(context.Background(), in); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}

	got := sink.AllTraces()
	if len(got) != 1 {
		t.Fatalf("sink received %d traces, want 1", len(got))
	}
	span := got[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if v := stringAttr(span.Attributes(), attrToolName); v != "read_file" {
		t.Errorf("forwarded tool name = %q, want read_file", v)
	}
}
