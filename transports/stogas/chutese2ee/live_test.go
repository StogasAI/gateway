package chutese2ee

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/valyala/fasthttp"
)

func TestLiveChutesE2EE(t *testing.T) {
	if os.Getenv("STOGAS_LIVE_CHUTES_E2EE") != "1" {
		t.Skip("set STOGAS_LIVE_CHUTES_E2EE=1 to run the paid Chutes interoperability test")
	}
	apiKey := strings.TrimSpace(os.Getenv("CHUTES_API_KEY"))
	if apiKey == "" {
		t.Fatal("CHUTES_API_KEY is required")
	}
	model := strings.TrimSpace(os.Getenv("STOGAS_LIVE_CHUTES_MODEL"))
	if model == "" {
		model = "Qwen/Qwen3-32B-TEE"
	}
	chuteID := strings.TrimSpace(os.Getenv("STOGAS_LIVE_CHUTES_CHUTE_ID"))
	if chuteID == "" {
		chuteID = "ac059e33-eb27-541c-b9a9-24b214036475"
	}
	gpuCount := 8
	if raw := strings.TrimSpace(os.Getenv("STOGAS_LIVE_CHUTES_GPU_COUNT")); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 1 || parsed > 8 {
			t.Fatal("STOGAS_LIVE_CHUTES_GPU_COUNT must be an integer from 1 through 8")
		}
		gpuCount = parsed
	}
	target := ModelTarget{ChuteID: chuteID, GPUCount: gpuCount}
	transport, err := New(Options{
		APIKey:                  apiKey,
		APIBaseURL:              productionAPIBaseURL,
		RequireProductionOrigin: true,
		ResolveModel: func(value string) (ModelTarget, bool) {
			return target, value == model
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	if err := transport.pools.refill(target); err != nil {
		t.Fatalf("prewarm live Chutes E2EE pool: %v diagnostics=%#v", err, transport.Diagnostics())
	}

	unary := invokeLiveChutesForTest(t, transport, apiKey, model, false)
	if !json.Valid(unary) || !bytes.Contains(unary, []byte(`"choices"`)) {
		t.Fatalf("invalid unary response: %s", unary)
	}
	stream := invokeLiveChutesForTest(t, transport, apiKey, model, true)
	if !bytes.Contains(stream, []byte("data: [DONE]\n\n")) || !bytes.Contains(stream, []byte(`"choices"`)) {
		t.Fatalf("invalid stream response: %s", stream)
	}

	diagnostics := transport.Diagnostics()
	if len(diagnostics.Chutes) != 1 || diagnostics.Chutes[0].VerifiedInstances < 1 || len(diagnostics.Chutes[0].MeasurementDigests) != 1 {
		t.Fatalf("missing live attestation diagnostics: %#v", diagnostics)
	}
}

func invokeLiveChutesForTest(t *testing.T, transport *Transport, apiKey, model string, stream bool) []byte {
	t.Helper()
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
	if retry, err := transport.RoundTrip(nil, request, response); err != nil || retry {
		t.Fatalf("live RoundTrip retry=%t error=%v", retry, err)
	}
	if response.StatusCode() != http.StatusOK {
		t.Fatalf("live Chutes status=%d body=%s diagnostics=%#v", response.StatusCode(), response.Body(), transport.Diagnostics())
	}
	if !stream {
		return append([]byte(nil), response.Body()...)
	}
	streamBody := response.BodyStream()
	body, err := io.ReadAll(streamBody)
	if err != nil {
		t.Fatalf("read live encrypted stream: %v", err)
	}
	if closer, ok := streamBody.(io.Closer); ok {
		_ = closer.Close()
	}
	return body
}
