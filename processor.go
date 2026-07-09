package agenttrajectoryguard

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"
)

// OTel GenAI Semantic Convention attribute keys this processor reads.
const (
	attrOperationName = "gen_ai.operation.name"
	attrToolName      = "gen_ai.tool.name"
)

// guardProcessor is the consumer.Traces implementation. It runs the Level 0
// per-step check on every span and feeds the stateful tracker (Level 1a/1b/1c
// taint, invariants, shape) so multi-step trajectories are checked as a whole,
// then applies the configured verdict (annotate or drop).
type guardProcessor struct {
	cfg     *Config
	logger  *zap.Logger
	next    consumer.Traces
	tracker *tracker
}

func newGuardProcessor(set processor.Settings, cfg *Config, next consumer.Traces) *guardProcessor {
	return &guardProcessor{
		cfg:     cfg,
		logger:  set.Logger,
		next:    next,
		tracker: newTracker(cfg, set.Logger),
	}
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

	// Taint violations come first from observe(), so the primary verdict
	// favors the multi-step finding over the per-step one.
	primary := violations[0]
	if p.cfg.Mode == ModeDrop {
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
