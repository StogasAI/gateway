package stogas

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func BenchmarkTextPresence(b *testing.B) {
	for _, shape := range []struct {
		name, text string
		want       bool
	}{
		{"trailing_padding", "hello" + strings.Repeat(" ", 128<<20), true},
		{"blank", strings.Repeat(" ", 128<<20), false},
	} {
		for _, check := range []struct {
			name string
			run  func(string) bool
		}{
			{"trim_space", func(text string) bool { return strings.TrimSpace(text) != "" }},
			{"presence", hasNonWhitespace},
		} {
			b.Run(shape.name+"/"+check.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if check.run(shape.text) != shape.want {
						b.Fatal("wrong text presence")
					}
				}
			})
		}
	}
}

func BenchmarkOpenAIInputScan(b *testing.B) {
	for _, count := range []int{10_000, 3_000_000} {
		raw := json.RawMessage(`[` + strings.Repeat(`{"role":"user","content":"a"},`, count-1) + `{"role":"user","content":"a"}]`)
		for _, check := range []struct {
			name string
			run  func() error
		}{
			{"cache_breakpoints", func() error {
				found, err := validatePromptCacheBreakpoints(raw, catalog.RouteChat)
				if found != 0 {
					b.Fatalf("found unexpected cache breakpoints: %d", found)
				}
				return err
			}},
		} {
			b.Run(fmt.Sprintf("%d/%s", count, check.name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				for b.Loop() {
					if err := check.run(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
