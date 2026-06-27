package agenttrajectoryguard

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
)

// typeStr is the component type as referenced in collector config under
// processors:. Must be unique across the assembled collector.
const typeStr = "agenttrajectoryguard"

var (
	errInvalidMode            = errors.New("mode must be \"annotate\" or \"drop\"")
	errInvalidEvictionTimeout = errors.New("eviction_timeout must be > 0")
)

// componentType is resolved once at package init; MustNewType panics on an
// invalid name, which can only happen if typeStr above is malformed.
var componentType = component.MustNewType(typeStr)

// NewFactory returns a processor.Factory for the agent-trajectory-guard
// processor, registering the traces capability.
func NewFactory() processor.Factory {
	return processor.NewFactory(
		componentType,
		createDefaultConfig,
		processor.WithTraces(createTracesProcessor, component.StabilityLevelDevelopment),
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		Mode:            ModeAnnotate,
		EvictionTimeout: 5 * time.Minute,
		// Common destructive tool names; ProtectedResources is left empty so the
		// operator must opt in to what is actually protected.
		DestructiveTools:   []string{"delete_file", "rm", "drop_table", "delete_object"},
		ProtectedResources: nil,
		// Common egress tool names for Level 1a taint exfiltration.
		EgressTools: []string{
			"send_email", "http_post", "http_request", "upload_file",
			"send_message", "publish", "put_object", "webhook",
		},
		// Capacity caps (anti-DoS). Taint role keys use baked-in defaults.
		MaxStepsPerTrajectory: 10000,
		MaxTaintEntries:       50000,
	}
}

func createTracesProcessor(
	_ context.Context,
	set processor.Settings,
	cfg component.Config,
	next consumer.Traces,
) (processor.Traces, error) {
	pCfg := cfg.(*Config)
	return newGuardProcessor(set, pCfg, next), nil
}
