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
	"time"

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
	targets := liveChutesTargets(t)
	byModel := make(map[string]ModelTarget, len(targets))
	for _, target := range targets {
		byModel[target.Model] = ModelTarget{ChuteID: target.ChuteID, GPUCount: target.GPUCount}
	}
	transport, err := New(Options{
		APIKey:                  apiKey,
		APIBaseURL:              productionAPIBaseURL,
		RequireProductionOrigin: true,
		ResolveModel: func(value string) (ModelTarget, bool) {
			target, ok := byModel[value]
			return target, ok
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	transport.unaryClient.ReadTimeout = 45 * time.Second
	transport.streamClient.ReadTimeout = 45 * time.Second

	for _, liveTarget := range targets {
		t.Run(liveTarget.Model, func(t *testing.T) {
			target := byModel[liveTarget.Model]
			if err := transport.pools.refill(target); err != nil {
				t.Fatalf("prewarm live Chutes E2EE pool: %v diagnostic=%#v", err, liveChuteDiagnostic(transport.Diagnostics(), liveTarget.ChuteID))
			}

			unary := invokeLiveChutesForTest(t, transport, apiKey, liveTarget.Model, liveTarget.ChuteID, false)
			if !json.Valid(unary) || !bytes.Contains(unary, []byte(`"choices"`)) || !bytes.Contains(unary, []byte(`"usage"`)) {
				t.Fatalf("invalid unary response: %s", unary)
			}
			assertLiveChutesResponseContract(t, unary, liveTarget.Model, false)
			stream := invokeLiveChutesForTest(t, transport, apiKey, liveTarget.Model, liveTarget.ChuteID, true)
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

type liveChutesUsage struct {
	CompletionTokens int `json:"completion_tokens"`
	PromptTokens     int `json:"prompt_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type liveChutesResponse struct {
	Model string           `json:"model"`
	Usage *liveChutesUsage `json:"usage"`
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
	var sawModel, sawUsage bool
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
		}
	}
	if !sawModel {
		t.Fatal("Chutes response omitted the served model")
	}
	if !sawUsage {
		t.Fatal("Chutes response omitted usage")
	}
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
		model = "Qwen/Qwen3-32B-TEE"
	}
	chuteID := strings.TrimSpace(os.Getenv("STOGAS_LIVE_CHUTES_CHUTE_ID"))
	if chuteID == "" {
		chuteID = "ac059e33-eb27-541c-b9a9-24b214036475"
	}
	gpuCount := 8
	if raw := strings.TrimSpace(os.Getenv("STOGAS_LIVE_CHUTES_GPU_COUNT")); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 1 || parsed > 16 {
			t.Fatal("STOGAS_LIVE_CHUTES_GPU_COUNT must be an integer from 1 through 16")
		}
		gpuCount = parsed
	}
	return []liveChutesTarget{{Model: model, ChuteID: chuteID, GPUCount: gpuCount}}
}

func invokeLiveChutesForTest(t *testing.T, transport *Transport, apiKey, model, chuteID string, stream bool) []byte {
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
		t.Fatalf("live RoundTrip retry=%t error=%v diagnostic=%#v", retry, err, liveChuteDiagnostic(transport.Diagnostics(), chuteID))
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
