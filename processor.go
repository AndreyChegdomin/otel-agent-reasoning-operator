package agenttrajectoryguard

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
)

// OTel GenAI Semantic Convention attribute keys this processor reads.
const (
	attrOperationName = "gen_ai.operation.name"
	attrToolName      = "gen_ai.tool.name"
)

// Internal telemetry: meter name is the module path; instrument names carry
// the collector-conventional otelcol_<component>_ prefix.
const (
	meterName    = "github.com/AndreyChegdomin/agent-trajectory-guard"
	metricPrefix = "otelcol_agenttrajectoryguard_"
)

// guardMetrics holds the processor's internal metric instruments. All
// methods are nil-receiver- and nil-instrument-safe so a failed instrument
// creation (or a bare tracker in tests) degrades to no-ops, never a crash.
type guardMetrics struct {
	active     metric.Int64UpDownCounter
	evicted    metric.Int64Counter
	violations metric.Int64Counter
	dropped    metric.Int64Counter
}

// newGuardMetrics creates the instrument set. Instrument creation errors are
// logged and leave that instrument nil (a no-op via the nil-safe wrappers);
// they never fail processor creation.
func newGuardMetrics(mp metric.MeterProvider, logger *zap.Logger) *guardMetrics {
	if mp == nil {
		return nil
	}
	meter := mp.Meter(meterName)
	m := &guardMetrics{}
	var err error
	if m.active, err = meter.Int64UpDownCounter(metricPrefix + "trajectories_active"); err != nil {
		logger.Warn("failed to create trajectories_active instrument", zap.Error(err))
	}
	if m.evicted, err = meter.Int64Counter(metricPrefix + "trajectories_evicted_total"); err != nil {
		logger.Warn("failed to create trajectories_evicted_total instrument", zap.Error(err))
	}
	if m.violations, err = meter.Int64Counter(metricPrefix + "violations_total"); err != nil {
		logger.Warn("failed to create violations_total instrument", zap.Error(err))
	}
	if m.dropped, err = meter.Int64Counter(metricPrefix + "spans_dropped_total"); err != nil {
		logger.Warn("failed to create spans_dropped_total instrument", zap.Error(err))
	}
	return m
}

func (m *guardMetrics) addActive(delta int64) {
	if m == nil || m.active == nil {
		return
	}
	m.active.Add(context.Background(), delta)
}

func (m *guardMetrics) incEvicted() {
	if m == nil || m.evicted == nil {
		return
	}
	m.evicted.Add(context.Background(), 1)
}

func (m *guardMetrics) incViolation(name string) {
	if m == nil || m.violations == nil {
		return
	}
	m.violations.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("violation", name)))
}

func (m *guardMetrics) incDropped() {
	if m == nil || m.dropped == nil {
		return
	}
	m.dropped.Add(context.Background(), 1)
}

// guardProcessor is the consumer.Traces implementation. It runs the Level 0
// per-step check on every span and feeds the stateful tracker (Level 1a/1b/1c
// taint, invariants, shape) so multi-step trajectories are checked as a whole,
// then applies the configured verdict (annotate or drop).
type guardProcessor struct {
	cfg     *Config
	logger  *zap.Logger
	next    consumer.Traces
	tracker *tracker
	metrics *guardMetrics
}

func newGuardProcessor(set processor.Settings, cfg *Config, next consumer.Traces) *guardProcessor {
	p := &guardProcessor{
		cfg:     cfg,
		logger:  set.Logger,
		next:    next,
		tracker: newTracker(cfg, set.Logger),
		metrics: newGuardMetrics(set.MeterProvider, set.Logger),
	}
	p.tracker.metrics = p.metrics
	// Verdict spans originate in the tracker (reaper goroutine or shutdown
	// flush), outside any ConsumeTraces call, so they carry a fresh
	// context.Background(). Delivery failures are logged, not retried: a
	// verdict span is advisory telemetry, not pipeline data.
	p.tracker.emit = func(td ptrace.Traces) {
		if err := next.ConsumeTraces(context.Background(), td); err != nil {
			set.Logger.Warn("failed to deliver trajectory verdict span", zap.Error(err))
		}
	}
	return p
}

// Capabilities reports that this processor mutates the data it forwards:
// annotate mode writes attributes and drop mode removes spans.
func (p *guardProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (p *guardProcessor) Start(context.Context, component.Host) error {
	p.tracker.start()
	return nil
}

func (p *guardProcessor) Shutdown(context.Context) error {
	p.tracker.stop()
	return nil
}

// ConsumeTraces iterates the span tree, runs the Level 0 per-step verifier on
// each span, applies the configured verdict (annotate or drop), then forwards.
func (p *guardProcessor) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		sss := rss.At(i).ScopeSpans()
		for j := 0; j < sss.Len(); j++ {
			spans := sss.At(j).Spans()
			// RemoveIf lets drop mode excise offending spans in place;
			// annotate mode mutates and keeps them (returns false).
			spans.RemoveIf(p.applyVerdict)
		}
	}
	return p.next.ConsumeTraces(ctx, td)
}

// applyVerdict runs the per-step check on one span and enacts the configured
// mode. Returns true only when the span must be removed (drop mode + flagged).
func (p *guardProcessor) applyVerdict(span ptrace.Span) bool {
	// Level 1a (stateful): accumulate trajectory state for every span, even
	// ones dropped below, so taint sees the full action history.
	violations := p.tracker.observe(span)
	// Level 0 (stateless) per-step check.
	if v, ok := checkPerStep(p.cfg, span); ok {
		violations = append(violations, v)
	}
	if len(violations) == 0 {
		return false
	}
	for _, v := range violations {
		p.metrics.incViolation(v)
	}

	// Taint violations come first from observe(), so the primary verdict
	// favors the multi-step finding over the per-step one.
	primary := violations[0]
	if p.cfg.Mode == ModeDrop {
		p.metrics.incDropped()
		p.logger.Warn("dropping offending span",
			zap.String("trace_id", span.TraceID().String()),
			zap.String("span_id", span.SpanID().String()),
			zap.String("violation", primary),
			zap.Strings("violations", violations),
		)
		return true
	}
	span.Attributes().PutStr(attrViolation, primary)
	p.logger.Warn("flagged offending span",
		zap.String("trace_id", span.TraceID().String()),
		zap.String("span_id", span.SpanID().String()),
		zap.String("violation", primary),
		zap.Strings("violations", violations),
	)
	return false
}

// stringAttr returns the string value of key, or "" if absent.
func stringAttr(attrs pcommon.Map, key string) string {
	if v, ok := attrs.Get(key); ok {
		return v.AsString()
	}
	return ""
}

var _ processor.Traces = (*guardProcessor)(nil)
