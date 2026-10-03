package billing

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func BenchmarkCredentialPolicyAlternatives(b *testing.B) {
	models := make([]string, 8000)
	for index := range models {
		models[index] = fmt.Sprintf("model-%08d-abcdefghijkl", index)
	}
	large, err := json.Marshal(map[string]any{"routing": map[string]any{"allowedCatalogNodes": map[string]any{"models": models}}})
	if err != nil {
		b.Fatal(err)
	}
	for _, count := range []int{1, 64, 1000} {
		for name, source := range map[string]json.RawMessage{"empty": json.RawMessage(`null`), "shared-large": large} {
			b.Run(fmt.Sprintf("%s/%d", name, count), func(b *testing.B) {
				alternatives := make([]json.RawMessage, count)
				for index := range alternatives {
					alternatives[index] = source
				}
				b.ReportAllocs()
				for b.Loop() {
					var cache keyConfigCache
					snapshot := credentialPolicySnapshot(b, &cache, "org", json.RawMessage(`null`), map[string][]json.RawMessage{"openai": alternatives})
					for index := range alternatives {
						if _, err := snapshot.PolicyForCredential("openai", index, nil, time.Now(), nil); err != nil {
							b.Fatal(err)
						}
					}
					b.ReportMetric(float64(cache.bytes), "retained-bytes")
					cache.close()
				}
			})
		}
	}
}
