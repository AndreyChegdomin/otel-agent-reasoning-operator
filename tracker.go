package agenttrajectoryguard

import (
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// reapInterval is how often the reaper goroutine scans for evictable
// trajectories. Distinct from Config.EvictionTimeout (per-trajectory age).
const reapInterval = 30 * time.Second

// GenAI operation names used for trajectory bookkeeping.
const opInvokeAgent = "invoke_agent"

// Step is a single observed action in a trajectory, normalized across
// instrumentation conventions.
type Step struct {
	spanID   pcommon.SpanID
	opName   string
	toolName string
	args     string
	ts       time.Time
}

// TrajectoryState is the accumulated, ordered history for one trace_id. It is
// the state that per-step checks cannot see and that the multi-step invariants
// (taint, ordering, counters) operate over.
type TrajectoryState struct {
	traceID      pcommon.TraceID
	steps        []Step
	taintSet     map[string]bool // reserved for Level 1a taint tracking
	counters     map[string]int  // reserved for Level 1b invariants
	lastActivity time.Time
	rootClosed   bool // invoke_agent span observed (trajectory likely complete)
	emitted      bool // final verdict already emitted on eviction
}

// tracker holds live trajectories keyed by trace_id. The mutex guards both the
// active map and the per-state slices, since trace batches arrive concurrently.
type tracker struct {
	mu     sync.Mutex
	active map[pcommon.TraceID]*TrajectoryState
	cfg    *Config
	logger *zap.Logger

	now    func() time.Time // injectable clock for deterministic tests
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func newTracker(cfg *Config, logger *zap.Logger) *tracker {
	return &tracker{
		active: make(map[pcommon.TraceID]*TrajectoryState),
		cfg:    cfg,
		logger: logger,
		now:    time.Now,
		stopCh: make(chan struct{}),
	}
}

// observe records every step a span contributes into its trajectory state,
// creating the state on first sight of a trace_id.
func (t *tracker) observe(span ptrace.Span) {
	traceID := span.TraceID()
	opName := stringAttr(span.Attributes(), attrOperationName)

	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.active[traceID]
	if st == nil {
		st = &TrajectoryState{
			traceID:  traceID,
			taintSet: make(map[string]bool),
			counters: make(map[string]int),
		}
		t.active[traceID] = st
	}

	now := t.now()
	st.lastActivity = now
	if opName == opInvokeAgent {
		st.rootClosed = true
	}

	for _, tc := range extractToolCalls(span) {
		st.steps = append(st.steps, Step{
			spanID:   span.SpanID(),
			opName:   opName,
			toolName: tc.name,
			args:     tc.args,
			ts:       now,
		})
	}
}

// reapOnce evicts and returns trajectories that are complete (rootClosed) or
// stale (inactive longer than EvictionTimeout). Caller finalizes the returned
// states outside the lock.
func (t *tracker) reapOnce() []*TrajectoryState {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	var evicted []*TrajectoryState
	for id, st := range t.active {
		if st.rootClosed || now.Sub(st.lastActivity) > t.cfg.EvictionTimeout {
			evicted = append(evicted, st)
			delete(t.active, id)
		}
	}
	return evicted
}

// activeCount returns the number of live trajectories (test/observability aid).
func (t *tracker) activeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.active)
}

// finalize emits the trajectory's final verdict exactly once on eviction.
// For now it logs; later it aggregates the trajectory-level verdict.
func (t *tracker) finalize(st *TrajectoryState) {
	if st.emitted {
		return
	}
	st.emitted = true
	t.logger.Debug("trajectory evicted",
		zap.String("trace_id", st.traceID.String()),
		zap.Int("steps", len(st.steps)),
		zap.Bool("root_closed", st.rootClosed),
	)
}

// start launches the reaper goroutine.
func (t *tracker) start() {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		ticker := time.NewTicker(reapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-t.stopCh:
				return
			case <-ticker.C:
				for _, st := range t.reapOnce() {
					t.finalize(st)
				}
			}
		}
	}()
}

// stop signals the reaper to exit, waits for it, then flushes all remaining
// trajectories so nothing is lost on shutdown.
func (t *tracker) stop() {
	close(t.stopCh)
	t.wg.Wait()

	t.mu.Lock()
	remaining := make([]*TrajectoryState, 0, len(t.active))
	for id, st := range t.active {
		remaining = append(remaining, st)
		delete(t.active, id)
	}
	t.mu.Unlock()

	for _, st := range remaining {
		t.finalize(st)
	}
}
