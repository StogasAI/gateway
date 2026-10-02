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
			value.BilledCostUSD = "020"
		},
		"TTFT after request end": func(value *Metadata) {
			ttft := value.Timing.TotalMS + 1
			value.Timing.TTFTMS = &ttft
		},
	} {
		invalid := cloneMetadata(input.Metadata)
		mutate(&invalid)
		if ValidMetadata(invalid) {
			t.Fatalf("%s metadata was accepted", name)
		}
	}

	requestScopedTTFT := cloneMetadata(input.Metadata)
	ttft := requestScopedTTFT.Timing.ProviderMS + 1
	requestScopedTTFT.Timing.TTFTMS = &ttft
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
		Meters: map[string]Meter{
			"input_tokens": billing.PricedMeter("10", "input_tokens", "2", "20"),
		},
		UpstreamCostUSD: "20", BilledCostUSD: "20",
		Timing: Timing{
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
	meters := make(map[string]Meter, len(metadata.Meters))
	for key, meter := range metadata.Meters {
		meters[key] = meter
	}
	metadata.Meters = meters
	if metadata.Timing.TTFTMS != nil {
		value := *metadata.Timing.TTFTMS
		metadata.Timing.TTFTMS = &value
	}
	return metadata
}
