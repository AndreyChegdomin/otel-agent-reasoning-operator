package agenttrajectoryguard

import (
	"crypto/rand"
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

	// violations accumulates every distinct violation name observed across the
	// trajectory's lifetime, order-preserving and deduplicated. Consumed by
	// the eviction-time trajectory-level verdict (Task 5).
	violations []string

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

	// emit delivers a trajectory verdict span downstream. Wired by
	// newGuardProcessor to next.ConsumeTraces; nil in bare-tracker tests, and
	// finalize must tolerate that. MUST only be called outside t.mu: it feeds
	// the downstream pipeline, which can block or re-enter arbitrary code.
	emit func(ptrace.Traces)

	// metrics is the processor's internal instrument set; nil-safe (a bare
	// tracker or failed instrument creation leaves it nil / partially nil).
	metrics *guardMetrics
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

// appendUnique appends each element of src onto dst that is not already
// present in dst, preserving the order src elements first appear in.
func appendUnique(dst []string, src ...string) []string {
	for _, v := range src {
		found := false
		for _, existing := range dst {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
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
		t.metrics.addActive(1)
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
		// appendUnique dedups within this observe() call: a span carrying N
		// tool calls that repeatedly hit the same rule reports it once.
		violations = appendUnique(violations, applyTaint(st, step, t.cfg)...)
		violations = appendUnique(violations, runInvariants(st, step, t.cfg)...)
		if v, ok := checkConsistency(st, step, t.cfg); ok {
			violations = appendUnique(violations, v)
		}
		// Level 1c shape-only detectors (payload-free).
		if t.cfg.ShapeDetectorsEnabled {
			violations = appendUnique(violations, runShapeDetectors(st, t.cfg)...)
		}
	}

	// Emit the capacity signal once, after any cap (steps or taint) tripped.
	if st.truncated && !st.capacityEmitted {
		st.capacityEmitted = true
		violations = appendUnique(violations, violationCapacityExceeded)
	}

	// Accumulate into the trajectory-level record for Task 5's eviction-time
	// verdict: order-preserving, deduplicated across the trajectory lifetime.
	st.violations = appendUnique(st.violations, violations...)

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

// Verdict span name and attribute keys (per-span attrViolation is reused).
const (
	verdictSpanName          = "trajectory.verdict"
	attrViolations           = "security.violations"
	attrTrajectorySteps      = "trajectory.steps"
	attrTrajectoryTruncated  = "trajectory.truncated"
	attrTrajectoryRootClosed = "trajectory.root_closed"
)

// finalize runs exactly once per trajectory, on eviction (st.emitted guards
// re-entry). A trajectory that accumulated violations yields a single
// trajectory.verdict span delivered downstream via t.emit; clean
// trajectories only log. Callers MUST invoke finalize outside t.mu (reap
// collects under the lock, finalization happens after unlock): emit feeds
// the downstream pipeline and must never run while the tracker is locked.
//
// Known inherited edge (intentionally not fixed here): spans that arrive
// AFTER a rootClosed eviction re-create the trajectory state in observe(),
// so one trace can be evicted twice and — if the late spans also violate —
// produce a second trajectory.verdict span for the same trace_id.
func (t *tracker) finalize(st *TrajectoryState) {
	if st.emitted {
		return
	}
	st.emitted = true
	t.metrics.addActive(-1)
	t.metrics.incEvicted()

	if len(st.violations) == 0 {
		t.logger.Debug("trajectory evicted",
			zap.String("trace_id", st.traceID.String()),
			zap.Int("steps", len(st.steps)),
			zap.Bool("root_closed", st.rootClosed),
		)
		return
	}
	if t.emit != nil {
		t.emit(t.verdictTraces(st))
	}
}

// verdictTraces builds the one-span ptrace.Traces summarizing a violating
// trajectory: same trace_id, fresh random root span, zero-duration at
// eviction time.
func (t *tracker) verdictTraces(st *TrajectoryState) ptrace.Traces {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetTraceID(st.traceID)
	var sid [8]byte
	_, _ = rand.Read(sid[:]) // crypto/rand.Read never fails (crashes the program instead)
	span.SetSpanID(pcommon.SpanID(sid))
	span.SetName(verdictSpanName)
	span.SetKind(ptrace.SpanKindInternal)
	ts := pcommon.NewTimestampFromTime(t.now())
	span.SetStartTimestamp(ts)
	span.SetEndTimestamp(ts)

	a := span.Attributes()
	a.PutStr(attrViolation, st.violations[0])
	vs := a.PutEmptySlice(attrViolations)
	vs.EnsureCapacity(len(st.violations))
	for _, v := range st.violations {
		vs.AppendEmpty().SetStr(v)
	}
	a.PutInt(attrTrajectorySteps, int64(len(st.steps)))
	a.PutBool(attrTrajectoryTruncated, st.truncated)
	a.PutBool(attrTrajectoryRootClosed, st.rootClosed)
	return td
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
