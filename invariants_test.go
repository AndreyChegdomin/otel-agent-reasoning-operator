package agenttrajectoryguard

import (
	"testing"
	"time"
)

// feed appends steps to a state and returns violations from the last step.
func feed(st *TrajectoryState, cfg *Config, steps ...Step) []string {
	var last []string
	for _, s := range steps {
		st.steps = append(st.steps, s)
		last = runInvariants(st, s, cfg)
	}
	return last
}

func tstep(tool string, ts time.Time) Step { return Step{toolName: tool, ts: ts} }

func TestExcessiveDeletion(t *testing.T) {
	cfg := &Config{DestructiveTools: []string{"delete_file"}, MaxDeletes: 2}
	st := newState()
	base := time.Unix(0, 0)

	// 2 deletes: at threshold, not over.
	if v := feed(st, cfg, tstep("delete_file", base), tstep("delete_file", base)); len(v) != 0 {
		t.Fatalf("at threshold flagged: %v", v)
	}
	// 3rd delete: over threshold.
	v := feed(st, cfg, tstep("delete_file", base))
	if len(v) != 1 || v[0] != violationExcessiveDeletion {
		t.Errorf("got %v, want [%s]", v, violationExcessiveDeletion)
	}
}

func TestExcessiveDeletionDisabledByDefault(t *testing.T) {
	cfg := &Config{DestructiveTools: []string{"delete_file"}} // MaxDeletes == 0
	st := newState()
	base := time.Unix(0, 0)
	for i := 0; i < 10; i++ {
		if v := feed(st, cfg, tstep("delete_file", base)); len(v) != 0 {
			t.Fatalf("disabled invariant flagged: %v", v)
		}
	}
}

func TestForbiddenOrdering(t *testing.T) {
	cfg := &Config{ForbiddenOrderings: []OrderingRule{{First: "read_secrets", Then: "http_post"}}}
	st := newState()
	base := time.Unix(0, 0)

	// http_post before read_secrets ever happened: fine.
	if v := feed(st, cfg, tstep("http_post", base)); len(v) != 0 {
		t.Fatalf("ordering flagged with no prior 'first': %v", v)
	}
	// Now read_secrets, then http_post: forbidden.
	v := feed(st, cfg, tstep("read_secrets", base), tstep("http_post", base))
	if len(v) != 1 || v[0] != violationForbiddenOrdering {
		t.Errorf("got %v, want [%s]", v, violationForbiddenOrdering)
	}
}

func TestActionRateAnomaly(t *testing.T) {
	cfg := &Config{MaxActionsPerWindow: 3, RateWindow: time.Second}
	st := newState()
	base := time.Unix(100, 0)

	// 3 actions within the window: at threshold.
	v := feed(st, cfg,
		tstep("t", base),
		tstep("t", base.Add(100*time.Millisecond)),
		tstep("t", base.Add(200*time.Millisecond)),
	)
	if len(v) != 0 {
		t.Fatalf("at threshold flagged: %v", v)
	}
	// 4th within window: over.
	v = feed(st, cfg, tstep("t", base.Add(300*time.Millisecond)))
	if len(v) != 1 || v[0] != violationActionRateAnomaly {
		t.Errorf("got %v, want [%s]", v, violationActionRateAnomaly)
	}
}

func TestActionRateOutsideWindow(t *testing.T) {
	cfg := &Config{MaxActionsPerWindow: 2, RateWindow: time.Second}
	st := newState()
	base := time.Unix(100, 0)
	// Actions spaced beyond the window never accumulate.
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * 2 * time.Second)
		if v := feed(st, cfg, tstep("t", ts)); len(v) != 0 {
			t.Fatalf("spaced actions flagged at i=%d: %v", i, v)
		}
	}
}
