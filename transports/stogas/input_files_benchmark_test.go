package stogas

import (
	"context"
	"runtime"
	"strconv"
	"sync"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// This benchmark measures concurrent local preparation with independent upload
// bodies. It excludes network buffers, credential/DB work and provider response
// processing, so it cannot establish a complete server memory bound.
func BenchmarkAttachmentPreparation(b *testing.B) {
	for _, size := range []int{1 << 20, 128 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			const parallel = 6
			prefix := `{"model":"gpt-5.5","max_output_tokens":100,"input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,`
			suffix := `"}]}]}`
			payload := (size - len(prefix) - len(suffix)) / 4 * 4
			bytes := len(prefix) + payload + len(suffix)
			b.SetBytes(int64(bytes * parallel))
			b.ReportAllocs()
			for range b.N {
				type retained struct {
					ctx     *schemas.BifrostContext
					request *schemas.BifrostRequest
					state   *State
				}
				live := make([]retained, parallel)
				failures := make(chan error, parallel)
				var workers sync.WaitGroup
				for n := range parallel {
					workers.Go(func() {
						body := make([]byte, bytes)
						copy(body, prefix)
						for i := len(prefix); i < len(prefix)+payload; i++ {
							body[i] = 'A'
						}
						copy(body[len(prefix)+payload:], suffix)
						resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: body})
						if err != nil {
							failures <- err
							return
						}
						state := NewState(resolved, "sk-benchmark", nil, AdapterFor(resolved.Provider))
						if err := state.Adapter.ValidateRequest(state); err != nil {
							failures <- err
							return
						}
						if err := state.Adapter.EstimateHold(state); err != nil {
							failures <- err
							return
						}
						ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
						ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
						request, err := resolved.ToBifrost(ctx)
						if err != nil {
							failures <- err
							return
						}
						if err := PrepareProviderRequest(ctx, state, request); err != nil {
							failures <- err
							return
						}
						resolved.ReleaseInput()
						live[n] = retained{ctx, request, state}
					})
				}
				workers.Wait()
				close(failures)
				for err := range failures {
					b.Fatal(err)
				}
				b.StopTimer()
				runtime.GC()
				var memory runtime.MemStats
				runtime.ReadMemStats(&memory)
				b.ReportMetric(float64(memory.HeapAlloc), "retained-heap-B")
				runtime.KeepAlive(live)
				b.StartTimer()
			}
		})
	}
}
