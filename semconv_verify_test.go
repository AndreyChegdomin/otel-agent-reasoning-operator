package agenttrajectoryguard

import (
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// This file is the "verify by hand on a real span" gate before building taint
// logic. Each builder reproduces how a real instrumentation library actually
// lays out a tool-call span, using attribute keys taken from the published
// specs (not invented). It documents which shapes the current Level 0 gate
// catches and which it misses.
//
// Sources (verified):
//   - OTel GenAI semconv (canonical): gen_ai.operation.name=execute_tool,
//     gen_ai.tool.name, gen_ai.tool.call.arguments|result (Opt-In attributes).
//   - OpenInference (Arize/Phoenix): openinference.span.kind=TOOL, tool.name,
//     tool.parameters (JSON string), input.value. NO gen_ai.operation.name.
//   - OpenLLMetry (Traceloop): tool calls nested on a chat/LLM span as
//     gen_ai.completion.{i}.tool_calls.{j}.name|arguments. NO gen_ai.tool.name.

const protectedTarget = "/etc/secrets/key.pem"

// canonicalOTelToolSpan — OpenTelemetry GenAI Semantic Conventions execute_tool.
func canonicalOTelToolSpan() ptrace.Span {
	s := newSpan()
	a := s.Attributes()
	a.PutStr("gen_ai.operation.name", "execute_tool")
	a.PutStr("gen_ai.tool.name", "delete_file")
	a.PutStr("gen_ai.tool.call.id", "call_abc123")
	a.PutStr("gen_ai.tool.type", "function")
	a.PutStr("gen_ai.tool.call.arguments", `{"path":"`+protectedTarget+`"}`)
	a.PutStr("gen_ai.provider.name", "anthropic")
	return s
}

// openInferenceToolSpan — Arize OpenInference TOOL span.
func openInferenceToolSpan() ptrace.Span {
	s := newSpan()
	a := s.Attributes()
	a.PutStr("openinference.span.kind", "TOOL")
	a.PutStr("tool.name", "delete_file")
	a.PutStr("tool.parameters", `{"path":"`+protectedTarget+`"}`)
	a.PutStr("input.value", `{"path":"`+protectedTarget+`"}`)
	a.PutStr("input.mime_type", "application/json")
	return s
}

// openLLMetryToolCallSpan — Traceloop nests tool calls on the chat span.
func openLLMetryToolCallSpan() ptrace.Span {
	s := newSpan()
	a := s.Attributes()
	a.PutStr("gen_ai.operation.name", "chat")
	a.PutStr("gen_ai.completion.0.role", "assistant")
	a.PutStr("gen_ai.completion.0.tool_calls.0.name", "delete_file")
	a.PutStr("gen_ai.completion.0.tool_calls.0.arguments", `{"path":"`+protectedTarget+`"}`)
	a.PutStr("traceloop.entity.input", `{"path":"`+protectedTarget+`"}`)
	return s
}

func newSpan() ptrace.Span {
	return ptrace.NewTraces().ResourceSpans().AppendEmpty().
		ScopeSpans().AppendEmpty().Spans().AppendEmpty()
}

func TestRealSpanShapes(t *testing.T) {
	cfg := &Config{
		Mode:               ModeAnnotate,
		EvictionTimeout:    1,
		DestructiveTools:   []string{"delete_file", "rm"},
		ProtectedResources: []string{protectedTarget},
	}

	// All three layouts MUST be caught: the normalization layer recognizes the
	// canonical OTel GenAI bus plus the two most popular real-world
	// instrumentations (OpenInference, OpenLLMetry). This is the verified
	// foundation taint logic (Level 1a) builds on.
	for _, tc := range []struct {
		name string
		span ptrace.Span
	}{
		{"OTel GenAI canonical (gen_ai.tool.name)", canonicalOTelToolSpan()},
		{"OpenInference (tool.name)", openInferenceToolSpan()},
		{"OpenLLMetry (nested tool_calls)", openLLMetryToolCallSpan()},
	} {
		if _, ok := checkPerStep(cfg, tc.span); !ok {
			t.Errorf("%s: tool call NOT detected — normalization gap", tc.name)
		}
	}
}
