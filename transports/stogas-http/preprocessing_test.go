package stogashttp

import (
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestPreprocessingActivityConcurrent(t *testing.T) {
	server := &Server{}
	var workers sync.WaitGroup
	for range 100 {
		workers.Go(func() {
			for range 100 {
				finish := server.preprocessing.begin(1024)
				stats := server.preprocessing.diagnostics()
				if stats.Active < 1 {
					t.Errorf("activity invariant broken: %+v", stats)
				}
				finish()
				finish()
			}
		})
	}
	workers.Wait()
	stats := server.preprocessing.diagnostics()
	if stats.Active != 0 || stats.Completed != 10000 || stats.InputBytes != 1024*10000 || stats.InputBytesBuckets[11] != 10000 || stats.TotalWallTimeMicros < stats.MaxWallTimeMicros {
		t.Fatalf("unexpected activity: %+v", stats)
	}
	var timed uint64
	for _, count := range stats.WallTimeMicrosBuckets {
		timed += count
	}
	if timed != stats.Completed {
		t.Fatalf("duration observations were lost or duplicated: %d != %d", timed, stats.Completed)
	}
}

func TestPreprocessingAcceptsBurstAndFinishesFailedResolution(t *testing.T) {
	server := &Server{}
	burst := runtime.GOMAXPROCS(0)*2 + 1
	finishes := make([]func(), burst)
	for i := range finishes {
		finishes[i] = server.preprocessing.begin(0)
	}
	if stats := server.preprocessing.diagnostics(); stats.Active != burst || stats.Peak != burst {
		t.Fatalf("burst not tracked: %+v", stats)
	}
	for _, finish := range finishes {
		_, err := catalog.ResolveRequest(catalog.RequestInput{Path: "/not-a-route"})
		finish()
		finish() // Success and deferred cleanup may release the same lease.
		if !errors.Is(err, catalog.ErrRouteUnavailable) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if server.privateDiagnostics().Requests.Preprocessing.Active != 0 {
		t.Fatal("failed resolution leaked activity")
	}
}

func TestPreprocessingExcludesAuthorization(t *testing.T) {
	for _, request := range []struct{ path, body string }{
		{"/v1/chat/completions", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}]}`},
		{"/v1/responses", `{"model":"gpt-5.5","input":"hello"}`},
	} {
		t.Run(request.path, func(t *testing.T) {
			server := &Server{}
			ctx := newTestRequest(t)
			testRequestBody(ctx, request.body)
			resolution := mustResolvedRequest(t, request.path, request.body)
			finish := server.preprocessing.begin(len(request.body))
			defer finish()
			candidate, failure := server.prepareCandidate(ctx, resolution, apiCredential{Raw: "invalid"}, "", time.Now(), nil, nil, finish)
			if candidate != nil || failure == nil || failure.kind != candidateFailureBilling || !errors.Is(failure.err, billing.ErrInvalidAPIKey) {
				t.Fatalf("did not reach authorization: candidate=%v failure=%+v", candidate, failure)
			}
			if server.preprocessing.diagnostics().Active != 0 {
				t.Fatal("authorization remained in preprocessing activity")
			}
		})
	}
}

func TestRequestWorkBucketBoundaries(t *testing.T) {
	for _, tc := range []struct {
		bytes  uint64
		bucket int
	}{
		{0, 0}, {1, 1}, {2, 2}, {3, 2}, {4, 3},
		{1023, 10}, {1024, 11}, {50 << 20, 26}, {128 << 20, 28},
	} {
		var activity requestWorkActivity
		activity.start()
		activity.finish(time.Duration(tc.bytes)*time.Microsecond, tc.bytes)
		stats := activity.diagnostics()
		if stats.Active != 0 || stats.Completed != 1 || stats.InputBytes != tc.bytes || stats.TotalWallTimeMicros != tc.bytes || stats.MaxWallTimeMicros != tc.bytes {
			t.Fatalf("incorrect totals for %d: %+v", tc.bytes, stats)
		}
		for i := range stats.InputBytesBuckets {
			want := uint64(0)
			if i == tc.bucket {
				want = 1
			}
			if stats.InputBytesBuckets[i] != want || stats.WallTimeMicrosBuckets[i] != want {
				t.Fatalf("value %d: bucket %d = %d/%d, want %d", tc.bytes, i, stats.InputBytesBuckets[i], stats.WallTimeMicrosBuckets[i], want)
			}
		}
	}
	var short requestWorkActivity
	for range 10 {
		short.start()
		short.finish(900*time.Nanosecond, 1)
	}
	if stats := short.diagnostics(); stats.TotalWallTimeMicros != 9 || stats.WallTimeMicrosBuckets[0] != 10 {
		t.Fatalf("rounding individual samples lost cumulative time: %+v", stats)
	}
}

func TestJSONDecodeDiagnosticsIncludeRejectedRequests(t *testing.T) {
	for _, body := range []string{`{"input":"private-marker",`, `{"input":"private-marker","input":"duplicate"}`, `{"input":"private-marker"}`} {
		server := &Server{}
		ctx := newTestRequest(t)
		testRequestBody(ctx, body)
		ctx.credential = &apiCredential{Raw: "private-credential"}
		// Invalid JSON fails decoding; valid JSON proceeds to the unavailable
		// billing service. Both must close the decoding observation exactly once.
		if server.prepareInference(ctx, time.Now()) != nil {
			t.Fatal("request unexpectedly prepared without a runtime")
		}
		stats := server.privateDiagnostics().Requests
		if stats.JSONDecode.Active != 0 || stats.JSONDecode.Completed != 1 || stats.JSONDecode.InputBytes != uint64(len(body)) || stats.Preprocessing.Completed != 0 {
			t.Fatalf("decoding was lost or included later work: %+v", stats)
		}
		encoded, err := json.Marshal(stats)
		if err != nil || strings.Contains(string(encoded), "private-") {
			t.Fatalf("request data entered aggregate diagnostics: err=%v", err)
		}
	}
}
