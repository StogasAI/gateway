package stogashttp

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/valyala/fasthttp"
)

func TestAdmissionDiagnosticsBoundRejectedTrafficAndExcludeAdmittedErrors(t *testing.T) {
	s := &Server{}
	var workers sync.WaitGroup
	for i := range 1000 {
		workers.Go(func() {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.SetMethod("POST")
			ctx.Request.SetRequestURI("/v1/chat/completions")
			ctx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer secret-%d", i))
			s.writeError(ctx, 401, map[string]string{"error": fmt.Sprintf("secret-%d", i)})
			// An encrypted reply has an outer 200; the inner rejection still counts once.
			ctx.SetStatusCode(200)
			s.recordAdmissionRejection(ctx, 500)
		})
	}
	workers.Wait()
	for _, status := range []int{400, 402, 403, 413, 429, 500, 503, 504} {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod("POST")
		ctx.Request.SetRequestURI("/v1/responses")
		s.writeError(ctx, status, nil)
		admitted := &fasthttp.RequestCtx{}
		admitted.Request.Header.SetMethod("POST")
		admitted.Request.SetRequestURI("/v1/responses")
		s.recordAdmission(admitted)
		s.recordAdmission(admitted)
		s.writeError(admitted, status, nil)
	}
	for _, request := range [][2]string{{"GET", "/v1/chat/completions"}, {"OPTIONS", "/v1/responses"}, {"POST", "/ready"}, {"POST", "/random-scan"}} {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(request[0])
		ctx.Request.SetRequestURI(request[1])
		s.writeError(ctx, 401, nil)
	}
	got := s.privateDiagnostics().Requests.Admission
	want := requestAdmissionDiagnostics{Admitted: 8, Authentication: 1000, Billing: 1, Permission: 1, RateLimit: 1, InvalidRequest: 2, Unavailable: 1, Internal: 2}
	if got != want {
		t.Fatalf("admission diagnostics = %#v, want %#v", got, want)
	}
	encoded, err := json.Marshal(got)
	if err != nil || strings.Contains(string(encoded), "secret") {
		t.Fatalf("admission snapshot retained client content: %s, %v", encoded, err)
	}
}
