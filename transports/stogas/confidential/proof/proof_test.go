package proof

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func TestMetadataValidation(t *testing.T) {
	input := Input{Metadata: testMetadata()}
	if !ValidMetadata(input.Metadata) {
		t.Fatal("valid metadata rejected")
	}
	for name, mutate := range map[string]func(*Metadata){
		"unpublished catalog":    func(value *Metadata) { value.CatalogVersion = new(uint64) },
		"no catalog":             func(value *Metadata) { value.CatalogVersion = nil },
		"no provider call":       func(value *Metadata) { value.ProviderAttempts = nil },
		"invalid chain hash":     func(value *Metadata) { value.ProviderAttempts[0].CatalogChainHash = "sha256:wrong" },
		"noncanonical timestamp": func(value *Metadata) { value.CreatedAt = "2026-08-24T12:34:56Z" },
		"noncanonical USD": func(value *Metadata) {
			value.Usage.BilledCostUSD = "020"
		},
		"TTFT after request end": func(value *Metadata) {
			ttft := value.Performance.TotalMS + 1
			value.Performance.TTFTMS = &ttft
		},
	} {
		invalid := cloneMetadata(input.Metadata)
		mutate(&invalid)
		if ValidMetadata(invalid) {
			t.Fatalf("%s metadata was accepted", name)
		}
	}

	requestScopedTTFT := cloneMetadata(input.Metadata)
	ttft := requestScopedTTFT.ProviderAttempts[0].LatencyMS + 1
	requestScopedTTFT.Performance.TTFTMS = &ttft
	if !ValidMetadata(requestScopedTTFT) {
		t.Fatal("TTFT may exceed provider duration when gateway work or retries occur first")
	}
}

// The metadata is a selection: every value in it is the record's value under the record's name.
// Only the policy hash stands for a field that the caller may not read. A field added to the
// record stays out until Select names it.
func TestSelectTakesOnlyTheRecordsOwnValues(t *testing.T) {
	status, count, version := 200, uint32(7), uint64(23)
	credential := strings.Repeat("c", 36)
	versions := billing.LoggedPolicyVersions{{PolicyVersion: billing.PolicyVersion{Scope: "key", ID: "key", Revision: 1}, SHA512: strings.Repeat("b", 128)}}
	event := billing.RequestEvent{
		SchemaVersion: billing.RequestLogSchemaVersion, RequestID: "req_1", CreatedAt: "2026-08-24T12:34:56.789Z", LastRequestAt: "2026-08-24T12:34:56.789Z",
		RequestCount: 1, APIKeyID: "key", MemberID: "member", OrganizationID: "organization", Interface: "chat_completions",
		SessionID: "session", TraceID: "trace", EncryptionKeyIDs: []string{strings.Repeat("e", 64)}, Metadata: map[string]string{"user": "private"},
		AppTitle: "app", AppURL: "https://app.example", AgentID: "agent", Transport: "attested_tls", CatalogVersion: &version,
		PolicyVersions: &versions, NodeID: "node", GatewayVersion: "v1.2.3",
		ProviderAttempts: []billing.ProviderAttempt{{
			CatalogChainHash: "sha256:" + strings.Repeat("a", 64), ResolvedCatalogChainHash: "sha256:" + strings.Repeat("d", 64),
			Provider: "chutes", Status: "success", StatusCode: &status, ErrorCode: "none", StartMS: 3, LatencyMS: 9, OutputObserved: true,
			ProviderRequestID: "request", ProviderResponseID: "response", ProviderModel: "model", ProviderInstanceID: "instance",
			ProviderEncryptionKey: strings.Repeat("f", 64),
			ProviderMeasurement:   strings.Repeat("9", 64),
			FinishReason:          "stop", Byok: &credential, AccountOptions: []billing.HeldOption{{}},
		}},
		Performance: billing.RequestPerformance{TotalMS: 20, RateLimitWaitMS: 1, FirstOutputMS: &count, TTFTMS: &count,
			ToolCalls: []billing.ToolCall{{Type: "function"}}, AnsweredCalls: []string{"call"}},
		Usage: billing.RequestUsage{UpstreamCostUSD: "20", BilledCostUSD: "20", Meters: billing.EventMeters{}},
	}
	object := func(value any) map[string]any {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	record, selected := object(event), object(Select(&event))
	if selected["policy_versions_sha512"] != versions.SHA512() {
		t.Fatalf("policy hash = %v", selected["policy_versions_sha512"])
	}
	delete(selected, "policy_versions_sha512")
	// within reports whether every value of part is the whole's value under the same name.
	var within func(part, whole any) bool
	within = func(part, whole any) bool {
		switch part := part.(type) {
		case map[string]any:
			whole, ok := whole.(map[string]any)
			for key, value := range part {
				if held, found := whole[key]; !ok || !found || !within(value, held) {
					return false
				}
			}
			return ok
		case []any:
			whole, ok := whole.([]any)
			if !ok || len(part) != len(whole) {
				return false
			}
			for index := range part {
				if !within(part[index], whole[index]) {
					return false
				}
			}
			return true
		}
		return reflect.DeepEqual(part, whole)
	}
	if !within(selected, record) {
		t.Fatalf("the metadata holds a value that the record does not:\n%v\n%v", selected, record)
	}
	encoded, _ := json.Marshal(Select(&event))
	for _, private := range []string{credential, "account_options", "organization", "member", "session", "private", "https://app.example", "agent", strings.Repeat("e", 64), "tool_calls", "answered_calls"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("the metadata holds %q, which its caller may not read or already sent", private)
		}
	}
	if keys := slices.Sorted(maps.Keys(selected)); !slices.Equal(keys, []string{"catalog_version", "created_at", "gateway_version", "performance", "provider_attempts", "request_id", "transport", "usage"}) {
		t.Fatalf("selected fields = %v", keys)
	}
}

func testMetadata() Metadata {
	ttft := uint32(4)
	return Metadata{
		RequestID:      "req_1",
		CreatedAt:      "2026-08-24T12:34:56.789Z",
		CatalogVersion: new(uint64(7)),
		ProviderAttempts: []ProviderAttempt{{
			CatalogChainHash: "sha256:" + strings.Repeat("a", 64), Provider: "openai", Status: "success", StartMS: 1, LatencyMS: 15,
		}},
		Usage: billing.RequestUsage{
			Meters: map[string]Meter{
				"input_tokens": billing.PricedMeter("10", "input_tokens", "2", "20"),
			},
			UpstreamCostUSD: "20", BilledCostUSD: "20",
		},
		Performance: Performance{
			TotalMS: 20,
			TTFTMS:  &ttft,
		},
	}
}

func cloneMetadata(metadata Metadata) Metadata {
	metadata.ProviderAttempts = slices.Clone(metadata.ProviderAttempts)
	meters := make(map[string]Meter, len(metadata.Usage.Meters))
	for key, meter := range metadata.Usage.Meters {
		meters[key] = meter
	}
	metadata.Usage.Meters = meters
	if metadata.Performance.TTFTMS != nil {
		value := *metadata.Performance.TTFTMS
		metadata.Performance.TTFTMS = &value
	}
	return metadata
}
