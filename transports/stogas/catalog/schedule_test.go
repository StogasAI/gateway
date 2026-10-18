package catalog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

var promotedChainHash = "sha256:" + strings.Repeat("b", 64)

func runtimeWithSchedule(t *testing.T, schedule []map[string]any) []byte {
	t.Helper()
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	runtime["schedule"] = schedule
	data, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// promotedDeployment returns a base deployment whose output costs 10 USD per million tokens, with
// the chains that the build compiles for a changed state.
func promotedDeployment(t *testing.T, deploymentID string) map[string]any {
	t.Helper()
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	deployment := runtime["graph"].(map[string]any)["deployments"].(map[string]any)[deploymentID].(map[string]any)
	for _, route := range deployment["routes"].(map[string]any) {
		route := route.(map[string]any)
		route["pricing"].(map[string]any)[billing.MeterOutputTokens] = map[string]any{billing.RatePerMillionTokens: "10"}
		route["chainHash"] = promotedChainHash
	}
	return deployment
}

func outputRate(deployment Deployment) string {
	return deployment.Pricing[billing.MeterOutputTokens][billing.RatePerMillionTokens]
}

func TestScheduledStatesApplyFromTheirStartUntilTheNextEntry(t *testing.T) {
	snap, err := snapshotFromCatalogBytes(runtimeWithSchedule(t, []map[string]any{
		{"start": "2026-11-01T00:00:00Z", "graph": map[string]any{"deployments": map[string]any{
			"openai-gpt-5.6-sol": promotedDeployment(t, "openai-gpt-5.6-sol"),
		}}},
		{"start": "2026-12-01T00:00:00Z", "graph": map[string]any{}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		at     time.Time
		output string
		chain  bool
	}{
		{at: time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC), output: "20"},
		{at: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), output: "10", chain: true},
		{at: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), output: "20"},
	} {
		state := snap.at(test.at)
		deployment, ok := state.deploymentFromCompiledAt("openai-gpt-5.6-sol", state.graph.Routes["openai-responses"], test.at)
		if !ok || outputRate(deployment) != test.output ||
			deployment.Pricing[billing.MeterInputTokens][billing.RatePerMillionTokens] != "4" ||
			(deployment.ChainHash == promotedChainHash) != test.chain {
			t.Fatalf("%s: unexpected deployment %#v", test.at, deployment)
		}
	}

	// A Fast request that ran at Standard settles at the Standard price of the state it started
	// in, even after that state ends.
	started := time.Date(2026, 11, 30, 23, 59, 59, 0, time.UTC)
	state := snap.at(started)
	fast, ok := state.deploymentFromCompiledAt("openai-gpt-5.6-sol-fast", state.graph.Routes["openai-responses"], started)
	if !ok {
		t.Fatal("Fast deployment unavailable")
	}
	standard, ok := StandardTierDeployment(schemas.OpenAI, RouteResponses, fast)
	if !ok || standard.ID != "openai-gpt-5.6-sol" || outputRate(standard) != "10" || standard.ChainHash != promotedChainHash {
		t.Fatalf("Standard settlement ignored the state the request started in: %#v", standard)
	}
}

func TestRequestsUseTheCatalogStateInEffect(t *testing.T) {
	snap, err := snapshotFromCatalogBytes(runtimeWithSchedule(t, []map[string]any{
		{"start": "2000-01-01T00:00:00Z", "graph": map[string]any{"deployments": map[string]any{
			"openai-gpt-5.6-sol": promotedDeployment(t, "openai-gpt-5.6-sol"),
		}}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	previous := active.Load()
	t.Cleanup(func() { active.Store(previous) })
	active.Store(snap)
	resolved, err := ResolveRequest(RequestInput{
		Body:   []byte(`{"model":"openai-gpt-5.6-sol","input":"hello"}`),
		Method: "POST",
		Path:   "/v1/responses",
		Policy: policyConfig(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if outputRate(resolved.Deployment) != "10" || resolved.Deployment.ChainHash != promotedChainHash {
		t.Fatalf("request used another catalog state: %#v", resolved.Deployment)
	}
}

func TestSnapshotValidationRejectsInvalidSchedules(t *testing.T) {
	unpriced := promotedDeployment(t, "openai-gpt-5.6-sol")
	delete(unpriced["routes"].(map[string]any)["openai-responses"].(map[string]any)["pricing"].(map[string]any), billing.MeterOutputTokens)
	empty := map[string]any{}
	for _, test := range []struct {
		name     string
		schedule []map[string]any
		message  string
	}{
		{
			name:     "out of order",
			schedule: []map[string]any{{"start": "2026-12-01T00:00:00Z", "graph": empty}, {"start": "2026-11-01T00:00:00Z", "graph": empty}},
			message:  "does not start after",
		},
		{
			name:     "same start",
			schedule: []map[string]any{{"start": "2026-11-01T00:00:00Z", "graph": empty}, {"start": "2026-11-01T00:00:00Z", "graph": empty}},
			message:  "does not start after",
		},
		{
			name: "added node",
			schedule: []map[string]any{{"start": "2026-11-01T00:00:00Z", "graph": map[string]any{"deployments": map[string]any{
				"openai-gpt-5.6-sol-promotion": promotedDeployment(t, "openai-gpt-5.6-sol"),
			}}}},
			message: "adds catalog nodes",
		},
		{
			name: "invalid state",
			schedule: []map[string]any{{"start": "2026-11-01T00:00:00Z", "graph": map[string]any{"deployments": map[string]any{
				"openai-gpt-5.6-sol": unpriced,
			}}}},
			message: "missing required pricing meter",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := snapshotFromCatalogBytes(runtimeWithSchedule(t, test.schedule)); err == nil ||
				!strings.Contains(err.Error(), test.message) {
				t.Fatalf("invalid schedule was accepted or failed for another reason: %v", err)
			}
		})
	}
}
