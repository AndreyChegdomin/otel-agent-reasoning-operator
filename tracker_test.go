package agenttrajectoryguard

import (
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

func testTracker(timeout time.Duration) (*tracker, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	tr := newTracker(&Config{Mode: ModeAnnotate, EvictionTimeout: timeout}, zap.NewNop())
	tr.now = clk.now
	return tr, clk
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// spanIn builds a span on the given trace_id with op/tool/args set.
func spanIn(traceID pcommon.TraceID, op, tool, args string) ptrace.Span {
	s := newSpan()
	s.SetTraceID(traceID)
	a := s.Attributes()
	a.PutStr(attrOperationName, op)
	if tool != "" {
		a.PutStr(attrToolName, tool)
		a.PutStr(attrToolCallArgs, args)
	}
	return s
}

var traceA = pcommon.TraceID([16]byte{0xAA})
var traceB = pcommon.TraceID([16]byte{0xBB})

func TestObserveAccumulatesPerTrace(t *testing.T) {
	tr, _ := testTracker(time.Minute)

	tr.observe(spanIn(traceA, "execute_tool", "read_file", "/data/a"))
	tr.observe(spanIn(traceA, "execute_tool", "write_file", "/data/b"))
	tr.observe(spanIn(traceB, "execute_tool", "send_email", "x@y.z"))

	if tr.activeCount() != 2 {
		t.Fatalf("active = %d, want 2", tr.activeCount())
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if got := len(tr.active[traceA].steps); got != 2 {
		t.Errorf("traceA steps = %d, want 2", got)
	}
	if got := len(tr.active[traceB].steps); got != 1 {
		t.Errorf("traceB steps = %d, want 1", got)
	}
}

func TestReapEvictsStale(t *testing.T) {
	tr, clk := testTracker(time.Minute)
	tr.observe(spanIn(traceA, "execute_tool", "read_file", "/data/a"))

	// Not yet stale.
	if ev := tr.reapOnce(); len(ev) != 0 {
		t.Fatalf("evicted %d before timeout, want 0", len(ev))
	}
	// Past the timeout.
	clk.advance(2 * time.Minute)
	ev := tr.reapOnce()
	if len(ev) != 1 {
		t.Fatalf("evicted %d after timeout, want 1", len(ev))
	}
	if tr.activeCount() != 0 {
		t.Errorf("active = %d after reap, want 0", tr.activeCount())
	}
}

func TestReapEvictsClosedRoot(t *testing.T) {
	tr, _ := testTracker(time.Hour) // long timeout: only rootClosed should evict
	tr.observe(spanIn(traceA, "execute_tool", "read_file", "/data/a"))
	tr.observe(spanIn(traceA, opInvokeAgent, "", ""))

	ev := tr.reapOnce()
	if len(ev) != 1 || !ev[0].rootClosed {
		t.Fatalf("expected 1 rootClosed eviction, got %d", len(ev))
	}
}

func TestStepCapTripsSignalAndBoundsMemory(t *testing.T) {
	tr, _ := testTracker(time.Hour)
	tr.cfg.MaxStepsPerTrajectory = 5

	signals := 0
	for i := 0; i < 50; i++ {
		for _, v := range tr.observe(spanIn(traceA, "execute_tool", "read_file", "/data/a")) {
			if v == violationCapacityExceeded {
				signals++
			}
		}
	}
	tr.mu.Lock()
	steps := len(tr.active[traceA].steps)
	truncated := tr.active[traceA].truncated
	tr.mu.Unlock()

	if steps > 5 {
		t.Errorf("steps = %d, want capped at 5", steps)
	}
	if !truncated {
		t.Error("trajectory should be marked truncated")
	}
	if signals != 1 {
		t.Errorf("capacity signal emitted %d times, want exactly 1", signals)
	}
}

func TestTaintCapBoundsTaintSet(t *testing.T) {
	tr, _ := testTracker(time.Hour)
	tr.cfg.MaxTaintEntries = 2
	tr.cfg.ProtectedResources = []string{"/etc/secrets"}

	// Each copy adds one new sink to the taint set; the 3rd is blocked.
	tr.observe(spanIn(traceA, "execute_tool", "copy_file", `{"src":"/etc/secrets/x","dst":"/tmp/1"}`))
	tr.observe(spanIn(traceA, "execute_tool", "copy_file", `{"src":"/tmp/1","dst":"/tmp/2"}`))
	var sawSignal bool
	for _, v := range tr.observe(spanIn(traceA, "execute_tool", "copy_file", `{"src":"/tmp/2","dst":"/tmp/3"}`)) {
		if v == violationCapacityExceeded {
			sawSignal = true
		}
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if got := len(tr.active[traceA].taintSet); got > 2 {
		t.Errorf("taintSet = %d, want capped at 2", got)
	}
	if !sawSignal {
		t.Error("expected trajectory_capacity_exceeded once taint cap is hit")
	}
}

// olmToolCallSpan builds an OpenLLMetry-style span carrying N tool calls
// nested under gen_ai.completion.0.tool_calls.{i}.{name,arguments}.
func olmToolCallSpan(traceID pcommon.TraceID, tools ...string) ptrace.Span {
	s := newSpan()
	s.SetTraceID(traceID)
	a := s.Attributes()
	a.PutStr(attrOperationName, "chat")
	for i, tool := range tools {
		a.PutStr("gen_ai.completion.0.tool_calls."+itoa(i)+".name", tool)
		a.PutStr("gen_ai.completion.0.tool_calls."+itoa(i)+".arguments", "{}")
	}
	return s
}

func itoa(i int) string {
	return string(rune('0' + i))
}

// TestObserveDedupesViolationWithinSingleSpan: a span with two tool calls
// that both trigger the same rule (forbidden_ordering) must yield that
// violation only once from a single observe() call.
func TestObserveDedupesViolationWithinSingleSpan(t *testing.T) {
	tr, _ := testTracker(time.Hour)
	tr.cfg.ForbiddenOrderings = []OrderingRule{{First: "read_secret", Then: "send_email"}}

	// Establish "read_secret" earlier in the trajectory.
	tr.observe(spanIn(traceA, "execute_tool", "read_secret", ""))

	// One span, two tool calls, both "send_email" -> both trigger
	// forbidden_ordering against the same trajectory history.
	violations := tr.observe(olmToolCallSpan(traceA, "send_email", "send_email"))

	count := 0
	for _, v := range violations {
		if v == violationForbiddenOrdering {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("forbidden_ordering appeared %d times in observe() return, want 1 (dedup within call): %v", count, violations)
	}
}

// TestStateViolationsAccumulateDeduped: violations across multiple observe
// calls accumulate into TrajectoryState.violations, order-preserving and
// deduplicated across calls.
func TestStateViolationsAccumulateDeduped(t *testing.T) {
	tr, _ := testTracker(time.Hour)
	tr.cfg.ForbiddenOrderings = []OrderingRule{{First: "read_secret", Then: "send_email"}}
	tr.cfg.MaxDeletes = 1
	tr.cfg.DestructiveTools = []string{"delete_file"}

	tr.observe(spanIn(traceA, "execute_tool", "read_secret", ""))
	tr.observe(spanIn(traceA, "execute_tool", "send_email", ""))       // forbidden_ordering (1st)
	tr.observe(spanIn(traceA, "execute_tool", "delete_file", ""))      // counter=1, no violation yet
	tr.observe(spanIn(traceA, "execute_tool", "delete_file", ""))      // counter=2 -> excessive_deletion
	tr.observe(spanIn(traceA, "execute_tool", "send_email", ""))       // forbidden_ordering again (dup)

	tr.mu.Lock()
	got := tr.active[traceA].violations
	tr.mu.Unlock()

	want := []string{violationForbiddenOrdering, violationExcessiveDeletion}
	if len(got) != len(want) {
		t.Fatalf("st.violations = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("st.violations = %v, want %v", got, want)
		}
	}
}

// evictAll mirrors the reaper loop body: collect under the lock, finalize
// outside it.
func evictAll(tr *tracker) {
	for _, st := range tr.reapOnce() {
		tr.finalize(st)
	}
}

// violate feeds traceA a forbidden_ordering violation (read_secret then
// send_email) and closes the root so reapOnce evicts it.
func violate(tr *tracker) {
	tr.cfg.ForbiddenOrderings = []OrderingRule{{First: "read_secret", Then: "send_email"}}
	tr.observe(spanIn(traceA, "execute_tool", "read_secret", ""))
	tr.observe(spanIn(traceA, "execute_tool", "send_email", ""))
	tr.observe(spanIn(traceA, opInvokeAgent, "", ""))
}

func TestFinalizeEmitsVerdictSpan(t *testing.T) {
	tr, clk := testTracker(time.Hour)
	var emitted []ptrace.Traces
	tr.emit = func(td ptrace.Traces) { emitted = append(emitted, td) }

	violate(tr)
	evictAll(tr)

	if len(emitted) != 1 {
		t.Fatalf("emit called %d times, want 1", len(emitted))
	}
	td := emitted[0]
	if n := td.SpanCount(); n != 1 {
		t.Fatalf("verdict traces carry %d spans, want 1", n)
	}
	span := td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if span.Name() != "trajectory.verdict" {
		t.Errorf("span name = %q, want trajectory.verdict", span.Name())
	}
	if span.TraceID() != traceA {
		t.Errorf("trace id = %s, want %s", span.TraceID(), traceA)
	}
	if span.SpanID().IsEmpty() {
		t.Error("span id must be a fresh non-zero id")
	}
	if !span.ParentSpanID().IsEmpty() {
		t.Errorf("parent span id = %s, want empty (root)", span.ParentSpanID())
	}
	if span.Kind() != ptrace.SpanKindInternal {
		t.Errorf("kind = %v, want Internal", span.Kind())
	}
	wantTS := pcommon.NewTimestampFromTime(clk.t)
	if span.StartTimestamp() != wantTS || span.EndTimestamp() != wantTS {
		t.Errorf("timestamps = %v/%v, want both %v (eviction time)",
			span.StartTimestamp(), span.EndTimestamp(), wantTS)
	}

	a := span.Attributes()
	if got := stringAttr(a, "security.violation"); got != violationForbiddenOrdering {
		t.Errorf("security.violation = %q, want %q", got, violationForbiddenOrdering)
	}
	vs, ok := a.Get("security.violations")
	if !ok || vs.Slice().Len() != 1 || vs.Slice().At(0).Str() != violationForbiddenOrdering {
		t.Errorf("security.violations = %v, want [%q]", vs, violationForbiddenOrdering)
	}
	if steps, ok := a.Get("trajectory.steps"); !ok || steps.Int() != 2 {
		t.Errorf("trajectory.steps = %v, want 2", steps)
	}
	if tr2, ok := a.Get("trajectory.truncated"); !ok || tr2.Bool() {
		t.Errorf("trajectory.truncated = %v, want false", tr2)
	}
	if rc, ok := a.Get("trajectory.root_closed"); !ok || !rc.Bool() {
		t.Errorf("trajectory.root_closed = %v, want true", rc)
	}
}

func TestFinalizeCleanTrajectoryEmitsNothing(t *testing.T) {
	tr, _ := testTracker(time.Hour)
	calls := 0
	tr.emit = func(ptrace.Traces) { calls++ }

	tr.observe(spanIn(traceA, "execute_tool", "read_file", "/data/a"))
	tr.observe(spanIn(traceA, opInvokeAgent, "", ""))
	evictAll(tr)

	if calls != 0 {
		t.Fatalf("emit called %d times for a clean trajectory, want 0", calls)
	}
}

func TestFinalizeEmitsOnce(t *testing.T) {
	tr, _ := testTracker(time.Hour)
	calls := 0
	tr.emit = func(ptrace.Traces) { calls++ }

	violate(tr)
	ev := tr.reapOnce()
	if len(ev) != 1 {
		t.Fatalf("evicted %d, want 1", len(ev))
	}
	tr.finalize(ev[0])
	tr.finalize(ev[0]) // double-finalize must not re-emit

	if calls != 1 {
		t.Fatalf("emit called %d times, want exactly 1", calls)
	}
}

func TestFinalizeNilEmitDoesNotPanic(t *testing.T) {
	tr, _ := testTracker(time.Hour) // bare tracker: no emit func wired
	violate(tr)
	evictAll(tr) // must not panic despite violations and nil emit
}

func TestStartStopFlushes(t *testing.T) {
	tr, _ := testTracker(time.Hour)
	tr.start()
	tr.observe(spanIn(traceA, "execute_tool", "read_file", "/data/a"))
	tr.stop() // must flush remaining

	if tr.activeCount() != 0 {
		t.Errorf("active = %d after stop, want 0 (flushed)", tr.activeCount())
	}
}
