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

// violationCapacityExceeded signals a trajectory that hit a capacity cap — an
// adversarial DoS signal in its own right, since normal agents do not.
const violationCapacityExceeded = "trajectory_capacity_exceeded"

// Step is a single observed action in a trajectory, normalized across
// instrumentation conventions.
type Step struct {
	spanID   pcommon.SpanID
	opName   string
	toolName string
	args     string
	ts       time.Time

	// Payload-free signals for Level 1c shape detection. Sizes are byte counts
	// that survive privacy redaction; 0 means "unknown" (detectors skip it).
	inputSize  int64
	resultSize int64
}

// TrajectoryState is the accumulated, ordered history for one trace_id. It is
// the state that per-step checks cannot see and that the multi-step invariants
// (taint, ordering, counters) operate over.
type TrajectoryState struct {
	traceID      pcommon.TraceID
	steps        []Step
	taintSet     map[string]bool // Level 1a: tainted values derived from protected sources
	counters     map[string]int  // Level 1b: per-invariant running counts (e.g. delete count)
	lastActivity time.Time
	rootClosed   bool // invoke_agent span observed (trajectory likely complete)
	emitted      bool // final verdict already emitted on eviction

	// pendingIntent is the most recent declared intent (Level 2): tools the
	// reasoning said it would use, awaiting comparison to actual actions.
	pendingIntent []string

	// truncated is set when a capacity cap (steps or taint entries) is hit;
	// the trajectory stops growing. capacityEmitted ensures the
	// trajectory_capacity_exceeded signal is emitted only once.
	truncated       bool
	capacityEmitted bool
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
// creating the state on first sight of a trace_id, and runs the stateful
// Level 1a taint invariant. Returns the violations triggered by this span.
func (t *tracker) observe(span ptrace.Span) []string {
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

	// Level 2: refresh declared intent from this span's reasoning, if any, so
	// subsequent actions in the trajectory can be compared against it.
	if t.cfg.ConsistencyEnabled {
		if reasoning := extractReasoning(span); reasoning != "" {
			if declared := declaredTools(reasoning, consistencyVocab(t.cfg)); len(declared) > 0 {
				st.pendingIntent = declared
			}
		}
	}

	spanIn, spanOut := extractSizes(span)

	var violations []string
	for _, tc := range extractToolCalls(span) {
		// Capacity cap: stop growing this trajectory once over the step limit.
		if t.cfg.MaxStepsPerTrajectory > 0 && len(st.steps) >= t.cfg.MaxStepsPerTrajectory {
			st.truncated = true
			break
		}
		// Input size: prefer the redaction-safe size attribute; fall back to the
		// arg length only when the payload itself is present (self-hosted case).
		inSize := spanIn
		if inSize == 0 && tc.args != "" {
			inSize = int64(len(tc.args))
		}
		step := Step{
			spanID:     span.SpanID(),
			opName:     opName,
			toolName:   tc.name,
			args:       tc.args,
			ts:         now,
			inputSize:  inSize,
			resultSize: spanOut,
		}
		st.steps = append(st.steps, step)
		// Level 1a taint (outranks later levels), then Level 1b invariants,
		// then Level 2 consistency. applyTaint may also enforce the taint cap.
		violations = append(violations, applyTaint(st, step, t.cfg)...)
		violations = append(violations, runInvariants(st, step, t.cfg)...)
		if v, ok := checkConsistency(st, step, t.cfg); ok {
			violations = append(violations, v)
		}
		// Level 1c shape-only detectors (payload-free).
		if t.cfg.ShapeDetectorsEnabled {
			violations = append(violations, runShapeDetectors(st, t.cfg)...)
		}
	}

	// Emit the capacity signal once, after any cap (steps or taint) tripped.
	if st.truncated && !st.capacityEmitted {
		st.capacityEmitted = true
		violations = append(violations, violationCapacityExceeded)
	}
	return violations
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

// finalize runs exactly once per trajectory, on eviction. It currently only
// logs the trajectory summary; it emits no trajectory-level verdict yet
// (per-span violations are already handled in observe/applyVerdict).
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
