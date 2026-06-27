package agenttrajectoryguard

import (
	"sort"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Attribute keys for the instrumentation conventions we normalize. Verified
// against published specs (see semconv_verify_test.go for sources).
const (
	// OTel GenAI semantic conventions (canonical bus).
	attrToolCallArgs = "gen_ai.tool.call.arguments"

	// OpenInference (Arize/Phoenix).
	attrOIKind   = "openinference.span.kind"
	attrOIName   = "tool.name"
	attrOIParams = "tool.parameters"
	attrOIInput  = "input.value"

	// OpenLLMetry (Traceloop) nests tool calls on the chat/LLM span under
	// indexed keys: gen_ai.completion.{c}.tool_calls.{t}.{name,arguments}.
	prefixOLMCompletion = "gen_ai.completion."
	segmentOLMToolCalls = ".tool_calls."
)

// toolCall is a normalized tool invocation extracted from a span, independent
// of which instrumentation library produced it.
type toolCall struct {
	name string
	args string // best-effort argument text (used for resource matching)
}

// extractToolCalls returns the tool invocations carried by a span, recognizing
// OTel GenAI canonical, OpenInference, and OpenLLMetry layouts. Returns nil for
// spans that are not tool calls.
func extractToolCalls(span ptrace.Span) []toolCall {
	attrs := span.Attributes()

	// 1. Canonical OTel GenAI: gen_ai.operation.name == execute_tool.
	if stringAttr(attrs, attrOperationName) == opExecuteTool {
		if name := stringAttr(attrs, attrToolName); name != "" {
			return []toolCall{{name: name, args: stringAttr(attrs, attrToolCallArgs)}}
		}
	}

	// 2. OpenInference: openinference.span.kind == TOOL.
	if strings.EqualFold(stringAttr(attrs, attrOIKind), "TOOL") {
		if name := stringAttr(attrs, attrOIName); name != "" {
			args := stringAttr(attrs, attrOIParams)
			if args == "" {
				args = stringAttr(attrs, attrOIInput)
			}
			return []toolCall{{name: name, args: args}}
		}
	}

	// 3. OpenLLMetry: tool calls nested on a chat span.
	if calls := extractOLMToolCalls(attrs); len(calls) > 0 {
		return calls
	}

	return nil
}

// extractOLMToolCalls pulls indexed tool calls out of OpenLLMetry attributes.
// Pairs each ...tool_calls.{t}.name with its sibling .arguments, in stable
// key order so behavior is deterministic.
func extractOLMToolCalls(attrs pcommon.Map) []toolCall {
	names := map[string]string{}
	args := map[string]string{}
	attrs.Range(func(k string, v pcommon.Value) bool {
		if !strings.HasPrefix(k, prefixOLMCompletion) || !strings.Contains(k, segmentOLMToolCalls) {
			return true
		}
		switch {
		case strings.HasSuffix(k, ".name"):
			names[strings.TrimSuffix(k, ".name")] = v.AsString()
		case strings.HasSuffix(k, ".arguments"):
			args[strings.TrimSuffix(k, ".arguments")] = v.AsString()
		}
		return true
	})
	prefixes := make([]string, 0, len(names))
	for p := range names {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)
	out := make([]toolCall, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, toolCall{name: names[p], args: args[p]})
	}
	return out
}
