package chutese2ee

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

func TestLiveChutesE2EE(t *testing.T) {
	if os.Getenv("STOGAS_LIVE_CHUTES_E2EE") != "1" {
		t.Skip("set STOGAS_LIVE_CHUTES_E2EE=1 to run the paid Chutes interoperability test")
	}
	transport, apiKey := newLiveChutesTransport(t)
	targets := liveChutesTargets(t)
	byModel := make(map[string]ModelTarget, len(targets))
	for _, target := range targets {
		byModel[target.Model] = ModelTarget{ChuteID: target.ChuteID, GPUCount: target.GPUCount}
	}
	transport.unaryClient.ReadTimeout = 45 * time.Second
	transport.streamClient.ReadTimeout = 45 * time.Second

	for _, liveTarget := range targets {
		t.Run(liveTarget.Model, func(t *testing.T) {
			target := byModel[liveTarget.Model]
			if err := transport.pools.refill(target); err != nil {
				t.Fatalf("prewarm live Chutes E2EE pool: %v diagnostic=%#v", err, liveChuteDiagnostic(transport.Diagnostics(), liveTarget.ChuteID))
			}

			unary := invokeLiveChutesForTest(t, transport, apiKey, liveTarget.Model, target, false)
			if !json.Valid(unary) || !bytes.Contains(unary, []byte(`"choices"`)) || !bytes.Contains(unary, []byte(`"usage"`)) {
				t.Fatalf("invalid unary response: %s", unary)
			}
			assertLiveChutesResponseContract(t, unary, liveTarget.Model, false)
			stream := invokeLiveChutesForTest(t, transport, apiKey, liveTarget.Model, target, true)
			if !bytes.Contains(stream, []byte("data: [DONE]\n\n")) || !bytes.Contains(stream, []byte(`"choices"`)) {
				t.Fatalf("invalid stream response: %s", stream)
			}
			assertLiveChutesResponseContract(t, stream, liveTarget.Model, true)

			diagnostics := transport.Diagnostics()
			var verified bool
			for _, chute := range diagnostics.Chutes {
				if chute.ChuteID == liveTarget.ChuteID && chute.VerifiedInstances > 0 && len(chute.MeasurementDigests) == 1 {
					verified = true
					break
				}
			}
			if !verified {
				t.Fatalf("missing live attestation diagnostics: %#v", diagnostics)
			}
		})
	}
}

// TestLiveChutesAttestation verifies every instance of each target, as the gateway does before it
// sends a request, and pays for no request. It writes the targets with an instance that failed
// verification, and those that Chutes did not serve, to the JSON report that
// STOGAS_LIVE_CHUTES_ATTESTATION_REPORT names.
func TestLiveChutesAttestation(t *testing.T) {
	reportPath := os.Getenv("STOGAS_LIVE_CHUTES_ATTESTATION_REPORT")
	if reportPath == "" {
		t.Skip("set STOGAS_LIVE_CHUTES_ATTESTATION_REPORT to attest live Chutes instances")
	}
	transport, _ := newLiveChutesTransport(t)
	report := struct {
		Failed      map[string]string `json:"failed"`
		Unavailable map[string]string `json:"unavailable"`
	}{Failed: map[string]string{}, Unavailable: map[string]string{}}
	// One at a time, because the attestor turns away evidence reads beyond its few slots.
	for _, live := range liveChutesTargets(t) {
		unavailable, err := attestLiveChute(t, transport.pools, live)
		switch {
		case err == nil:
		case unavailable:
			report.Unavailable[live.Model] = err.Error()
		default:
			report.Failed[live.Model] = err.Error()
			t.Errorf("%s: %v", live.Model, err)
		}
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// attestLiveChute reports whether Chutes did not serve the chute, or the reason that an instance
// failed verification. An instance without evidence is starting or stopping, so it fails nothing.
// A discovery that answers 404 lists no instance to verify, so Chutes did not serve the chute: on
// November 18, 2026 it answered so for a hot chute for more than ten minutes.
func attestLiveChute(t *testing.T, pools *poolState, live liveChutesTarget) (bool, error) {
	target := ModelTarget{ChuteID: live.ChuteID, GPUCount: live.GPUCount}
	discovered, _, err := pools.discover(target)
	if err != nil {
		var status *httpStatusError
		notFound := errors.As(err, &status) && status.StatusCode == http.StatusNotFound
		return notFound || chutesOutage(err), err
	}
	result, err := pools.attestor.verify(t.Context(), target, discovered, true)
	if err == nil {
		return false, nil
	}
	if result != nil {
		counts := result.FailureCounts
		t.Logf("%s: %d of %d instances verified; failures %v", live.Model, len(result.Instances), len(discovered), counts)
		if counts["tdx"]+counts["gpu"]+counts["measurement_policy"] == 0 &&
			counts["evidence_missing"]+counts["evidence_unavailable"] > 0 {
			if len(result.Instances) > 0 {
				return false, nil
			}
			return true, errors.New("no instance returned evidence")
		}
	}
	// A failed verification joins ErrAttestationFailed with its cause.
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		err = causes[len(causes)-1]
	}
	return chutesOutage(err), err
}

func chutesOutage(err error) bool {
	switch diagnosticErrorClass(err) {
	case "upstream_unavailable", "rate_limited", "timeout":
		return true
	}
	return false
}

// TestChutesMeasurements fails when Chutes publishes a TDX record that the gateway skips, or any
// SEV-SNP measurement, which the gateway cannot verify yet. It reads copies of Chutes' lists, so
// that the caller reports a list that Chutes did not serve as an outage, not as a failure here.
func TestChutesMeasurements(t *testing.T) {
	folder := os.Getenv("STOGAS_CHUTES_MEASUREMENTS")
	if folder == "" {
		t.Skip("set STOGAS_CHUTES_MEASUREMENTS to a folder with copies of Chutes' tdx.json and snp.json measurement lists")
	}
	read := func(name string, target any) {
		body, err := os.ReadFile(filepath.Join(folder, name))
		if err != nil || len(body) > maxMeasurementBody {
			t.Fatalf("read %s: %d bytes, %v", name, len(body), err)
		}
		if err := json.Unmarshal(body, target); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
	}
	var records []json.RawMessage
	read("tdx.json", &records)
	for _, record := range records {
		if _, ok := parseMeasurement(record); !ok {
			t.Errorf("gateway skips TDX measurement %.400s", record)
		}
	}
	if _, err := supportedMeasurements(records); err != nil {
		t.Error(err)
	}
	var snp []json.RawMessage
	read("snp.json", &snp)
	if len(snp) > 0 {
		t.Errorf("Chutes publishes %d SEV-SNP measurements; the gateway cannot verify SEV-SNP instances", len(snp))
	}
}

type liveChutesUsage struct {
	CompletionTokens int `json:"completion_tokens"`
	PromptTokens     int `json:"prompt_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type liveChutesResponse struct {
	Model   string            `json:"model"`
	Usage   *liveChutesUsage  `json:"usage"`
	Choices []json.RawMessage `json:"choices"`
}

func assertLiveChutesResponseContract(t *testing.T, payload []byte, expectedModel string, stream bool) {
	t.Helper()
	var frames [][]byte
	if stream {
		for _, line := range bytes.Split(payload, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if bytes.Equal(data, []byte("[DONE]")) {
				continue
			}
			frames = append(frames, data)
		}
	} else {
		frames = [][]byte{payload}
	}
	if len(frames) == 0 {
		t.Fatal("Chutes response contained no JSON frames")
	}
	var sawModel, sawUsage, sawRunningUsage bool
	completion := 0
	for _, frame := range frames {
		var response liveChutesResponse
		if err := json.Unmarshal(frame, &response); err != nil {
			t.Fatalf("invalid Chutes response frame: %v", err)
		}
		if response.Model != "" {
			sawModel = true
			if response.Model != expectedModel {
				t.Fatalf("served model = %q, want %q", response.Model, expectedModel)
			}
		}
		if response.Usage != nil {
			sawUsage = true
			if response.Usage.PromptTokens < 0 || response.Usage.CompletionTokens < 0 ||
				response.Usage.TotalTokens != response.Usage.PromptTokens+response.Usage.CompletionTokens {
				t.Fatalf("invalid Chutes usage: %+v", response.Usage)
			}
			if response.Usage.CompletionTokens < completion {
				t.Fatalf("Chutes usage fell from %d to %d output tokens", completion, response.Usage.CompletionTokens)
			}
			completion = response.Usage.CompletionTokens
			sawRunningUsage = sawRunningUsage || len(response.Choices) > 0
		}
	}
	if !sawModel {
		t.Fatal("Chutes response omitted the served model")
	}
	if !sawUsage {
		t.Fatal("Chutes response omitted usage")
	}
	// The gateway stops a stream whose client left only after a chunk with output reported the
	// usage so far, which the instance asks its engine for on every encrypted stream.
	if stream && !sawRunningUsage {
		t.Fatal("Chutes stream reported usage only after its output")
	}
}

// TestLiveChutesE2EEClientLeaves leaves an encrypted stream after 40 output tokens, as a client
// that disconnects, and checks that Chutes bills no more than those tokens and the 500 or fewer that
// were on their way. A later call shows when Chutes' usage by chute includes the stream.
func TestLiveChutesE2EEClientLeaves(t *testing.T) {
	if os.Getenv("STOGAS_LIVE_CHUTES_CLIENT_LEAVES") != "1" {
		t.Skip("set STOGAS_LIVE_CHUTES_CLIENT_LEAVES=1 to leave a paid Chutes stream and read what Chutes billed")
	}
	transport, apiKey := newLiveChutesTransport(t)
	live := liveChutesTargets(t)[0]
	target := ModelTarget{ChuteID: live.ChuteID, GPUCount: live.GPUCount}
	before := liveChutesBilled(t, apiKey, live.ChuteID)

	payload, err := json.Marshal(map[string]any{
		"max_tokens": 3000,
		"messages":   []map[string]string{{"content": "Count from 1 to 3000, one number per line.", "role": "user"}},
		"model":      live.Model,
		"stream":     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)
	request.Header.SetMethod(http.MethodPost)
	request.Header.SetContentType("application/json")
	request.Header.Set("Authorization", "Bearer "+apiKey)
	request.SetRequestURI("https://llm.chutes.ai/v1/chat/completions")
	request.SetBodyRaw(payload)
	ctx := schemas.NewBifrostContext(t.Context(), schemas.NoDeadline)
	SetInvocation(ctx, target, 1, nil)
	if retry, err := transport.roundTrip(ctx, request, response); err != nil || retry || response.StatusCode() != http.StatusOK {
		t.Fatalf("live round trip status=%d retry=%t error=%v", response.StatusCode(), retry, err)
	}
	stream := response.BodyStream()
	lines := bufio.NewScanner(stream)
	lines.Buffer(make([]byte, 0, 64*1024), maxEncryptedSSELine)
	seen, frames := 0, 0
	for seen < 40 && frames < 200 && lines.Scan() {
		data, ok := bytes.CutPrefix(lines.Bytes(), []byte("data: "))
		var frame liveChutesResponse
		if !ok || json.Unmarshal(data, &frame) != nil {
			continue
		}
		frames++
		if frame.Usage != nil && len(frame.Choices) > 0 {
			seen = frame.Usage.CompletionTokens
		}
	}
	if seen < 40 {
		t.Fatalf("the stream reported %d output tokens in %d chunks: %v", seen, frames, lines.Err())
	}
	if closer, ok := stream.(io.Closer); ok {
		_ = closer.Close()
	}
	ctx.Cancel()

	control := invokeLiveChutesForTest(t, transport, apiKey, live.Model, target, false)
	var controlled liveChutesResponse
	if err := json.Unmarshal(control, &controlled); err != nil || controlled.Usage == nil {
		t.Fatalf("the control call reported no usage: %s", control)
	}
	billed := liveChutesBilledSince(t, apiKey, live.ChuteID, before)
	calls, output := billed.Count-1, billed.OutputTokens-controlled.Usage.CompletionTokens
	if calls < 0 || calls > 1 || output < 0 || output > seen+500 {
		t.Fatalf("Chutes billed %d calls and %d output tokens for a stream left at %d; another call of %s in the meantime needs a new run",
			calls, output, seen, live.Model)
	}
	t.Logf("%s: left at %d output tokens; Chutes billed %d calls and %d output tokens for it", live.Model, seen, calls, output)
}

type liveChutesUsageBucket struct {
	Bucket       string `json:"bucket"`
	Count        int    `json:"count"`
	OutputTokens int    `json:"output_tokens"`
}

// liveChutesBilled reads what Chutes billed the account for one chute, by hourly bucket.
func liveChutesBilled(t *testing.T, apiKey, chuteID string) map[string]liveChutesUsageBucket {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		productionAPIBaseURL+"/users/me/usage?per_chute=true&limit=3&chute_id="+chuteID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+apiKey)
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var page struct {
		Items []liveChutesUsageBucket `json:"items"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&page) != nil {
		t.Fatalf("Chutes usage: status %d", response.StatusCode)
	}
	buckets := make(map[string]liveChutesUsageBucket, len(page.Items))
	for _, item := range page.Items {
		buckets[item.Bucket] = item
	}
	return buckets
}

// liveChutesBilledSince returns what Chutes billed for the chute after before, once it has billed a
// call and then nothing more for 75 seconds. Chutes adds calls to its usage about every minute.
func liveChutesBilledSince(t *testing.T, apiKey, chuteID string, before map[string]liveChutesUsageBucket) liveChutesUsageBucket {
	t.Helper()
	var last liveChutesUsageBucket
	unchanged := 0
	for range 30 {
		time.Sleep(15 * time.Second)
		var added liveChutesUsageBucket
		for bucket, item := range liveChutesBilled(t, apiKey, chuteID) {
			added.Count += item.Count - before[bucket].Count
			added.OutputTokens += item.OutputTokens - before[bucket].OutputTokens
		}
		if added == last {
			unchanged++
		} else {
			last, unchanged = added, 0
		}
		if last.Count > 0 && unchanged == 5 {
			return last
		}
	}
	t.Fatal("Chutes usage did not settle within seven and a half minutes")
	return liveChutesUsageBucket{}
}

type liveChutesTarget struct {
	Model    string `json:"model"`
	ChuteID  string `json:"chuteId"`
	GPUCount int    `json:"gpuCount"`
}

func liveChutesTargets(t *testing.T) []liveChutesTarget {
	t.Helper()
	if raw := strings.TrimSpace(os.Getenv("STOGAS_LIVE_CHUTES_TARGETS_JSON")); raw != "" {
		var targets []liveChutesTarget
		if err := json.Unmarshal([]byte(raw), &targets); err != nil || len(targets) == 0 || len(targets) > 64 {
			t.Fatal("STOGAS_LIVE_CHUTES_TARGETS_JSON must contain 1 through 64 targets")
		}
		models := make(map[string]struct{}, len(targets))
		for _, target := range targets {
			if strings.TrimSpace(target.Model) != target.Model || target.Model == "" || len(target.Model) > 512 ||
				!canonicalUUID(target.ChuteID) || target.GPUCount < 1 || target.GPUCount > 16 {
				t.Fatalf("invalid live Chutes target for model %q", target.Model)
			}
			if _, duplicate := models[target.Model]; duplicate {
				t.Fatalf("duplicate live Chutes model %q", target.Model)
			}
			models[target.Model] = struct{}{}
		}
		return targets
	}

	model := strings.TrimSpace(os.Getenv("STOGAS_LIVE_CHUTES_MODEL"))
	if model == "" {
		model = "Qwen/Qwen3.6-27B-TEE"
	}
	chuteID := strings.TrimSpace(os.Getenv("STOGAS_LIVE_CHUTES_CHUTE_ID"))
	if chuteID == "" {
		chuteID = "7aa5e899-c0ba-5482-af48-d3f31d635c9f"
	}
	gpuCount := 1
	if raw := strings.TrimSpace(os.Getenv("STOGAS_LIVE_CHUTES_GPU_COUNT")); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 1 || parsed > 16 {
			t.Fatal("STOGAS_LIVE_CHUTES_GPU_COUNT must be an integer from 1 through 16")
		}
		gpuCount = parsed
	}
	return []liveChutesTarget{{Model: model, ChuteID: chuteID, GPUCount: gpuCount}}
}

func newLiveChutesTransport(t *testing.T) (*Transport, string) {
	t.Helper()
	apiKey := strings.TrimSpace(os.Getenv("CHUTES_API_KEY"))
	if apiKey == "" {
		t.Fatal("CHUTES_API_KEY is required")
	}
	transport, err := New(Options{
		APIKey:                  apiKey,
		APIBaseURL:              productionAPIBaseURL,
		RequireProductionOrigin: true,
		RequestTimeout:          10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(transport.Close)
	return transport, apiKey
}

func invokeLiveChutesForTest(t *testing.T, transport *Transport, apiKey, model string, target ModelTarget, stream bool) []byte {
	t.Helper()
	chuteID := target.ChuteID
	payload, err := json.Marshal(map[string]any{
		"max_tokens": 4,
		"messages": []map[string]string{{
			"content": "Reply with only OK.",
			"role":    "user",
		}},
		"model":       model,
		"stream":      stream,
		"temperature": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)
	request.Header.SetMethod(http.MethodPost)
	request.Header.SetContentType("application/json")
	request.Header.Set("Authorization", "Bearer "+apiKey)
	request.SetRequestURI("https://llm.chutes.ai/v1/chat/completions")
	request.SetBodyRaw(payload)
	ctx := schemas.NewBifrostContext(t.Context(), schemas.NoDeadline)
	defer ctx.Cancel()
	SetInvocation(ctx, target, 1, nil)
	if retry, err := transport.roundTrip(ctx, request, response); err != nil || retry {
		t.Fatalf("live round trip retry=%t error=%v diagnostic=%#v", retry, err, liveChuteDiagnostic(transport.Diagnostics(), chuteID))
	}
	if response.StatusCode() != http.StatusOK {
		t.Fatalf("live Chutes status=%d body=%s diagnostic=%#v", response.StatusCode(), response.Body(), liveChuteDiagnostic(transport.Diagnostics(), chuteID))
	}
	if !stream {
		return append([]byte(nil), response.Body()...)
	}
	streamBody := response.BodyStream()
	if closer, ok := streamBody.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}
	body, err := io.ReadAll(streamBody)
	if err != nil {
		t.Fatalf("read live encrypted stream: %v", err)
	}
	return body
}

func liveChuteDiagnostic(snapshot DiagnosticsSnapshot, chuteID string) *ChuteDiagnostic {
	for index := range snapshot.Chutes {
		if snapshot.Chutes[index].ChuteID == chuteID {
			return &snapshot.Chutes[index]
		}
	}
	return nil
}
