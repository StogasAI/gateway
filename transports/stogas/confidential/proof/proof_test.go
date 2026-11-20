package proof

import (
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"strings"
	"testing"
)

func TestMetadataValidation(t *testing.T) {
	input := Input{Metadata: testMetadata()}
	if !ValidMetadata(input.Metadata) {
		t.Fatal("valid metadata rejected")
	}
	for name, mutate := range map[string]func(*Metadata){
		"unpublished catalog":    func(value *Metadata) { value.Catalog.Version = 0 },
		"invalid chain hash":     func(value *Metadata) { value.Catalog.ChainHash = "sha256:wrong" },
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
	ttft := requestScopedTTFT.Performance.ProviderMS + 1
	requestScopedTTFT.Performance.TTFTMS = &ttft
	if !ValidMetadata(requestScopedTTFT) {
		t.Fatal("TTFT may exceed provider duration when gateway work or retries occur first")
	}
}

func testMetadata() Metadata {
	ttft := uint32(4)
	return Metadata{
		RequestID: "req_1",
		CreatedAt: "2026-08-24T12:34:56.789Z",
		Catalog: Catalog{
			ChainHash:    "sha256:" + strings.Repeat("a", 64),
			Version:      7,
			SelectionIDs: testCatalogSelectionIDs(),
		},
		Usage: billing.RequestUsage{
			Meters: map[string]Meter{
				"input_tokens": billing.PricedMeter("10", "input_tokens", "2", "20"),
			},
			UpstreamCostUSD: "20", BilledCostUSD: "20",
		},
		Performance: Performance{
			TotalMS:    20,
			ProviderMS: 15,
			TTFTMS:     &ttft,
		},
	}
}

func testCatalogSelectionIDs() []string {
	return []string{
		"author:openai",
		"model:gpt-5.5",
		"deployment:openai-gpt-5.5",
		"route:openai-responses",
		"provider:openai",
	}
}

func cloneMetadata(metadata Metadata) Metadata {
	metadata.Catalog.SelectionIDs = append([]string(nil), metadata.Catalog.SelectionIDs...)
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
