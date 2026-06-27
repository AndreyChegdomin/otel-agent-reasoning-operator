package agenttrajectoryguard

import (
	"context"
	"testing"
	"time"

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

func TestProcessorAccumulatesAcrossBatches(t *testing.T) {
	sink := &consumertest.TracesSink{}
	cfg := &Config{Mode: ModeAnnotate, EvictionTimeout: time.Minute}
	p := newGuardProcessor(processortest.NewNopSettings(componentType), cfg, sink)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p.tracker.now = clk.now

	// Two separate batches, same trace_id — state must accumulate.
	batch := func(op, tool, args string) ptrace.Traces {
		td := ptrace.NewTraces()
		s := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
		s.SetTraceID(traceA)
		s.Attributes().PutStr(attrOperationName, op)
		if tool != "" {
			s.Attributes().PutStr(attrToolName, tool)
			s.Attributes().PutStr(attrToolCallArgs, args)
		}
		return td
	}
	_ = p.ConsumeTraces(context.Background(), batch("execute_tool", "read_file", "/data/a"))
	_ = p.ConsumeTraces(context.Background(), batch("execute_tool", "write_file", "/data/b"))

	if p.tracker.activeCount() != 1 {
		t.Fatalf("active = %d, want 1", p.tracker.activeCount())
	}
	p.tracker.mu.Lock()
	steps := len(p.tracker.active[traceA].steps)
	p.tracker.mu.Unlock()
	if steps != 2 {
		t.Errorf("accumulated steps = %d, want 2", steps)
	}

	// And it reaps once stale.
	clk.advance(2 * time.Minute)
	if ev := p.tracker.reapOnce(); len(ev) != 1 {
		t.Errorf("reaped %d, want 1", len(ev))
	}
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
