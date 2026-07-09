package agenttrajectoryguard

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
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

// oneSpanBatch builds a one-span trace on traceID with op/tool set.
func oneSpanBatch(traceID pcommon.TraceID, op, tool string) ptrace.Traces {
	td := ptrace.NewTraces()
	s := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	s.SetTraceID(traceID)
	s.Attributes().PutStr(attrOperationName, op)
	if tool != "" {
		s.Attributes().PutStr(attrToolName, tool)
	}
	return td
}

// verdictSpans returns all spans named trajectory.verdict the sink received.
func verdictSpans(sink *consumertest.TracesSink) []ptrace.Span {
	var out []ptrace.Span
	for _, td := range sink.AllTraces() {
		rss := td.ResourceSpans()
		for i := 0; i < rss.Len(); i++ {
			sss := rss.At(i).ScopeSpans()
			for j := 0; j < sss.Len(); j++ {
				spans := sss.At(j).Spans()
				for k := 0; k < spans.Len(); k++ {
					if spans.At(k).Name() == "trajectory.verdict" {
						out = append(out, spans.At(k))
					}
				}
			}
		}
	}
	return out
}

// TestShutdownFlushEmitsVerdictSpan: a violating trajectory still live at
// shutdown must be flushed and its verdict span delivered to the next
// consumer before Shutdown returns.
func TestShutdownFlushEmitsVerdictSpan(t *testing.T) {
	sink := &consumertest.TracesSink{}
	cfg := &Config{
		Mode:               ModeAnnotate,
		EvictionTimeout:    time.Minute,
		ForbiddenOrderings: []OrderingRule{{First: "read_secret", Then: "send_email"}},
	}
	p := newGuardProcessor(processortest.NewNopSettings(componentType), cfg, sink)
	if err := p.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	_ = p.ConsumeTraces(context.Background(), oneSpanBatch(traceA, "execute_tool", "read_secret"))
	_ = p.ConsumeTraces(context.Background(), oneSpanBatch(traceA, "execute_tool", "send_email"))

	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	got := verdictSpans(sink)
	if len(got) != 1 {
		t.Fatalf("sink received %d trajectory.verdict spans, want 1", len(got))
	}
	if got[0].TraceID() != traceA {
		t.Errorf("verdict trace id = %s, want %s", got[0].TraceID(), traceA)
	}
	if v := stringAttr(got[0].Attributes(), attrViolation); v != violationForbiddenOrdering {
		t.Errorf("verdict security.violation = %q, want %q", v, violationForbiddenOrdering)
	}
}

// settingsWithReader returns nop settings whose MeterProvider feeds a
// ManualReader so tests can collect the processor's internal metrics.
func settingsWithReader() (processor.Settings, *sdkmetric.ManualReader) {
	set := processortest.NewNopSettings(componentType)
	reader := sdkmetric.NewManualReader()
	set.MeterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	return set, reader
}

// metricSum collects and returns the summed int64 datapoints of the named
// instrument, filtered to points carrying every given attribute. Returns 0
// if the instrument has no matching points yet.
func metricSum(t *testing.T, reader *sdkmetric.ManualReader, name string, attrs ...attribute.KeyValue) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric %s is %T, want Sum[int64]", name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				match := true
				for _, kv := range attrs {
					if v, ok := dp.Attributes.Value(kv.Key); !ok || v != kv.Value {
						match = false
						break
					}
				}
				if match {
					total += dp.Value
				}
			}
		}
	}
	return total
}

func TestMetricsLifecycleAndViolations(t *testing.T) {
	set, reader := settingsWithReader()
	sink := &consumertest.TracesSink{}
	cfg := &Config{
		Mode:               ModeAnnotate,
		EvictionTimeout:    time.Minute,
		ForbiddenOrderings: []OrderingRule{{First: "read_secret", Then: "send_email"}},
	}
	p := newGuardProcessor(set, cfg, sink)

	_ = p.ConsumeTraces(context.Background(), oneSpanBatch(traceA, "execute_tool", "read_secret"))
	if got := metricSum(t, reader, "otelcol_agenttrajectoryguard_trajectories_active"); got != 1 {
		t.Errorf("trajectories_active = %d after create, want 1", got)
	}

	_ = p.ConsumeTraces(context.Background(), oneSpanBatch(traceA, "execute_tool", "send_email"))
	_ = p.ConsumeTraces(context.Background(), oneSpanBatch(traceA, opInvokeAgent, ""))
	for _, st := range p.tracker.reapOnce() {
		p.tracker.finalize(st)
	}

	if got := metricSum(t, reader, "otelcol_agenttrajectoryguard_trajectories_active"); got != 0 {
		t.Errorf("trajectories_active = %d after eviction, want 0", got)
	}
	if got := metricSum(t, reader, "otelcol_agenttrajectoryguard_trajectories_evicted_total"); got != 1 {
		t.Errorf("trajectories_evicted_total = %d, want 1", got)
	}
	if got := metricSum(t, reader, "otelcol_agenttrajectoryguard_violations_total",
		attribute.String("violation", violationForbiddenOrdering)); got != 1 {
		t.Errorf("violations_total{violation=%s} = %d, want 1", violationForbiddenOrdering, got)
	}
}

func TestMetricsSpansDropped(t *testing.T) {
	set, reader := settingsWithReader()
	sink := &consumertest.TracesSink{}
	cfg := &Config{
		Mode:               ModeDrop,
		EvictionTimeout:    time.Minute,
		ForbiddenOrderings: []OrderingRule{{First: "read_secret", Then: "send_email"}},
	}
	p := newGuardProcessor(set, cfg, sink)

	_ = p.ConsumeTraces(context.Background(), oneSpanBatch(traceA, "execute_tool", "read_secret"))
	_ = p.ConsumeTraces(context.Background(), oneSpanBatch(traceA, "execute_tool", "send_email"))

	if got := metricSum(t, reader, "otelcol_agenttrajectoryguard_spans_dropped_total"); got != 1 {
		t.Errorf("spans_dropped_total = %d, want 1", got)
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
