package stogashttp

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestAdmissionDiagnosticsBoundRejectedTrafficAndExcludeAdmittedErrors(t *testing.T) {
	s := &Server{}
	var workers sync.WaitGroup
	for i := range 1000 {
		workers.Go(func() {
			ctx := newTestRequest(t)
			ctx.request.Method = "POST"
			testRequestURI(ctx, "/v1/chat/completions")
			ctx.request.Header.Set("Authorization", fmt.Sprintf("Bearer secret-%d", i))
			s.writeError(ctx, 401, map[string]string{"error": fmt.Sprintf("secret-%d", i)})
			// An encrypted reply has an outer 200; the inner rejection still counts once.
			ctx.writer.WriteHeader(200)
			s.recordAdmissionRejection(ctx, 500, "internal_error")
		})
	}
	workers.Wait()
	for _, status := range []int{400, 402, 403, 413, 429, 500, 503, 504} {
		ctx := newTestRequest(t)
		ctx.request.Method = "POST"
		testRequestURI(ctx, "/v1/responses")
		s.writeError(ctx, status, nil)
		admitted := newTestRequest(t)
		admitted.request.Method = "POST"
		testRequestURI(admitted, "/v1/responses")
		s.recordAdmission(admitted)
		s.recordAdmission(admitted)
		s.writeError(admitted, status, nil)
	}
	for _, request := range [][2]string{{"GET", "/v1/chat/completions"}, {"OPTIONS", "/v1/responses"}, {"POST", "/ready"}, {"POST", "/random-scan"}} {
		ctx := newTestRequest(t)
		ctx.request.Method = request[0]
		testRequestURI(ctx, request[1])
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
