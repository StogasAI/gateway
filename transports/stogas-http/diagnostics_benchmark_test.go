package stogashttp

import (
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
)

func BenchmarkProcessDiagnostics(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = currentProcessDiagnostics(time.Time{})
	}
}

// Measures the two aggregate observations per request, including contention,
// without parsing or provider work hiding the collection cost.
func BenchmarkRequestWorkObservation(b *testing.B) {
	var decoding, preprocessing requestWorkActivity
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			started := time.Now()
			decoding.start()
			decoding.finish(time.Since(started), 1<<20)
			finish := preprocessing.begin(1 << 20)
			finish()
		}
	})
}

// Measures snapshot encoding under a full provider registry, including detail
// that must be omitted. This is allocation work, not a claim about peak RSS.
func BenchmarkPrivateDiagnosticsBounds(b *testing.B) {
	for _, size := range []struct {
		name           string
		entries, bytes int
	}{
		{"ordinary", 8, 80}, {"full_registry", 512, 3000},
	} {
		b.Run(size.name, func(b *testing.B) {
			node := privateNodeDiagnostics{}
			for range size.entries {
				node.ChutesE2EE.Chutes = append(node.ChutesE2EE.Chutes, chutese2ee.ChuteDiagnostic{ChuteID: "known", UpstreamModels: []string{strings.Repeat("x", size.bytes)}})
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				result := boundPrivateDiagnostics(node)
				if _, err := marshalPayload(result); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
