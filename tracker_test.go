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

func TestStartStopFlushes(t *testing.T) {
	tr, _ := testTracker(time.Hour)
	tr.start()
	tr.observe(spanIn(traceA, "execute_tool", "read_file", "/data/a"))
	tr.stop() // must flush remaining

	if tr.activeCount() != 0 {
		t.Errorf("active = %d after stop, want 0 (flushed)", tr.activeCount())
	}
}
