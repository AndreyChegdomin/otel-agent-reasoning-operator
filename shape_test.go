package agenttrajectoryguard

import (
	"testing"
	"time"
)

func shapeCfg() *Config {
	return &Config{
		ShapeDetectorsEnabled: true,
		ReadTools:             []string{"read_file"},
		WriteTools:            []string{"write_file"},
		EgressTools:           []string{"http_post"},
		SizeReadThreshold:     1_000_000,
		SizeEgressRatio:       0.5,
		SizeWindowSteps:       10,
		SizeWindowDuration:    60 * time.Second,
	}
}

// sstep builds a payload-free step: args is EMPTY — only shape metadata is set.
func sstep(tool string, in, out int64, ts time.Time) Step {
	return Step{toolName: tool, args: "", inputSize: in, resultSize: out, ts: ts}
}

func feedShape(st *TrajectoryState, cfg *Config, steps ...Step) []string {
	var last []string
	for _, s := range steps {
		st.steps = append(st.steps, s)
		last = runShapeDetectors(st, cfg)
	}
	return last
}

// --- C1: size-correlation exfil silhouette ---

func TestSizeExfilSilhouetteFires(t *testing.T) {
	cfg := shapeCfg()
	st := newState()
	base := time.Unix(1000, 0)
	v := feedShape(st, cfg,
		sstep("read_file", 0, 2_000_000, base),                  // large read (2MB)
		sstep("http_post", 1_500_000, 0, base.Add(time.Second)), // comparable egress
	)
	if !containsStr(v, violationSizeExfilSilhouette) {
		t.Errorf("expected %s, got %v", violationSizeExfilSilhouette, v)
	}
}

func TestSizeExfilSilhouetteSmallEgressNoFire(t *testing.T) {
	cfg := shapeCfg()
	st := newState()
	base := time.Unix(1000, 0)
	v := feedShape(st, cfg,
		sstep("read_file", 0, 2_000_000, base),
		sstep("http_post", 10_000, 0, base.Add(time.Second)), // 10KB << 0.5*2MB
	)
	if containsStr(v, violationSizeExfilSilhouette) {
		t.Errorf("small egress must not flag: %v", v)
	}
}

func TestSizeExfilSilhouetteOutOfWindowNoFire(t *testing.T) {
	cfg := shapeCfg()
	st := newState()
	base := time.Unix(1000, 0)
	steps := []Step{sstep("read_file", 0, 2_000_000, base)}
	// 11 unrelated steps push the egress past the 10-step window.
	for i := 1; i <= 11; i++ {
		steps = append(steps, sstep("noop", 0, 0, base.Add(time.Duration(i)*time.Second)))
	}
	steps = append(steps, sstep("http_post", 1_500_000, 0, base.Add(20*time.Second)))
	v := feedShape(st, cfg, steps...)
	if containsStr(v, violationSizeExfilSilhouette) {
		t.Errorf("egress outside window must not flag: %v", v)
	}
}

// --- C2: suspicious sequence ---

func seqCfg() *Config {
	cfg := shapeCfg()
	cfg.SequencePatterns = []SequencePattern{
		{Name: "recon_then_egress", Pattern: []string{"read+", "egress"}},
		{Name: "read_modify_egress", Pattern: []string{"read", "write", "egress"}},
	}
	return cfg
}

func TestSuspiciousSequenceFires(t *testing.T) {
	cfg := seqCfg()
	st := newState()
	base := time.Unix(1000, 0)
	v := feedShape(st, cfg,
		sstep("read_file", 0, 100, base),
		sstep("read_file", 0, 100, base.Add(time.Second)),
		sstep("http_post", 100, 0, base.Add(2*time.Second)),
	)
	if !containsStr(v, violationSuspiciousSeqPrefix+"recon_then_egress") {
		t.Errorf("expected recon_then_egress, got %v", v)
	}
}

func TestSuspiciousSequenceNoEgressNoFire(t *testing.T) {
	cfg := seqCfg()
	st := newState()
	base := time.Unix(1000, 0)
	v := feedShape(st, cfg,
		sstep("read_file", 0, 100, base),
		sstep("write_file", 100, 0, base.Add(time.Second)),
	)
	for _, viol := range v {
		if len(viol) >= len(violationSuspiciousSeqPrefix) && viol[:len(violationSuspiciousSeqPrefix)] == violationSuspiciousSeqPrefix {
			t.Errorf("no egress yet, sequence must not fire: %v", v)
		}
	}
}

// --- C3: rate anomaly is payload-free (reuses Level 1b checkActionRate) ---

func TestRateAnomalyIsPayloadFree(t *testing.T) {
	cfg := &Config{MaxActionsPerWindow: 3, RateWindow: time.Second}
	st := newState()
	base := time.Unix(100, 0)
	// Steps carry NO args — proves the rate detector needs only timing.
	for i := 0; i < 3; i++ {
		s := sstep("act", 0, 0, base.Add(time.Duration(i)*100*time.Millisecond))
		st.steps = append(st.steps, s)
		if v := runInvariants(st, s, cfg); len(v) != 0 {
			t.Fatalf("at threshold flagged: %v", v)
		}
	}
	over := sstep("act", 0, 0, base.Add(300*time.Millisecond))
	st.steps = append(st.steps, over)
	if v := runInvariants(st, over, cfg); !containsStr(v, violationActionRateAnomaly) {
		t.Errorf("expected %s, got %v", violationActionRateAnomaly, v)
	}
}
