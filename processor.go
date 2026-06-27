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

// guardProcessor is the consumer.Traces implementation. For the skeleton it is
// a pass-through that proves spans flow and gen_ai.* attributes are readable;
// state/taint/invariants layer on in later build-order steps.
type guardProcessor struct {
	cfg    *Config
	logger *zap.Logger
	next   consumer.Traces
}

func newGuardProcessor(set processor.Settings, cfg *Config, next consumer.Traces) *guardProcessor {
	return &guardProcessor{
		cfg:    cfg,
		logger: set.Logger,
		next:   next,
	}
}

// Capabilities reports that this processor mutates the data it forwards:
// annotate mode writes attributes and drop mode removes spans.
func (p *guardProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (p *guardProcessor) Start(context.Context, component.Host) error { return nil }
func (p *guardProcessor) Shutdown(context.Context) error              { return nil }

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
	violation, flagged := checkPerStep(p.cfg, span)
	if !flagged {
		return false
	}
	if p.cfg.Mode == ModeDrop {
		p.logger.Warn("dropping offending span",
			zap.String("trace_id", span.TraceID().String()),
			zap.String("span_id", span.SpanID().String()),
			zap.String("violation", violation),
		)
		return true
	}
	span.Attributes().PutStr(attrViolation, violation)
	p.logger.Warn("flagged offending span",
		zap.String("trace_id", span.TraceID().String()),
		zap.String("span_id", span.SpanID().String()),
		zap.String("violation", violation),
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
