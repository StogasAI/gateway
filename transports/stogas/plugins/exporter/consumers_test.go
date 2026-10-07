package exporter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// External consumer tests use disposable, local instances. The target file
// contains name, url, query (trace-ID prefix or {requestID} template),
// encodings and optional format/headers.
// It is private because headers can contain a receiver's API credential.
func TestConsumerStoredTraces(t *testing.T) {
	path := os.Getenv("STOGAS_TEST_EXPORT_TARGETS")
	if path == "" {
		t.Skip("set STOGAS_TEST_EXPORT_TARGETS to local consumer target JSON")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var targets []struct {
		Name, URL, Query, Format string
		Encodings                []string
		Headers                  map[string]string
	}
	if err := json.Unmarshal(raw, &targets); err != nil {
		t.Fatal(err)
	}
	clear(raw)
	if len(targets) == 0 {
		t.Fatal("consumer target file is empty")
	}
	for _, target := range targets {
		if target.Name == "" || target.URL == "" || target.Query == "" || len(target.Encodings) == 0 {
			t.Fatal("consumer target requires name, url, query and encodings")
		}
		for _, encoding := range target.Encodings {
			t.Run(target.Name+"/"+encoding, func(t *testing.T) {
				e := New(context.Background(), Options{Local: true})
				defer e.Close()
				cfg := testConfig(target.URL)
				cfg.Destinations[0].Encoding = encoding
				cfg.Destinations[0].Format = target.Format
				cfg.Destinations[0].Headers = target.Headers
				prefix := fmt.Sprintf("consumer-%s-%s-%d", target.Name, encoding, time.Now().UnixNano())
				// More than one span exercises the consumer's OTLP batch handling.
				var ids []string
				for i := range 3 {
					id := fmt.Sprintf("%s-%d", prefix, i)
					ids = append(ids, id)
					c := e.Start("consumer-test", id, cfg)
					if i == 1 {
						var req schemas.BifrostResponsesRequest
						if err := json.Unmarshal([]byte(`{"input":[{"role":"user","content":"consumer prompt 世界"},{"type":"function_call","call_id":"call_lookup","name":"lookup_weather","arguments":"{\"city\":\"Vilnius\"}"},{"type":"function_call_output","call_id":"call_lookup","output":"{\"degrees\":18}"}]} `), &req); err != nil {
							t.Fatal(err)
						}
						req.Params = &schemas.ResponsesParameters{Instructions: ptr("consumer system instructions"), Temperature: ptr(0.25)}
						c.Input(&schemas.BifrostRequest{ResponsesRequest: &req})
						var resp schemas.BifrostResponsesResponse
						if err := json.Unmarshal([]byte(`{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"consumer response"}]},{"type":"function_call","call_id":"call_next","name":"lookup_weather","arguments":"{\"city\":\"Paris\"}"}]}`), &resp); err != nil {
							t.Fatal(err)
						}
						c.Response(&schemas.BifrostResponse{ResponsesResponse: &resp})
					} else {
						input(c, "consumer prompt 世界")
						delta(c, "consumer ")
						delta(c, "response")
					}
					r := testRecord(id)
					r.StartedAt = time.Now().Add(-time.Second)
					r.EndedAt = time.Now()
					r.FinishReason = "stop"
					c.Finish(r)
				}
				await(t, func() bool { return e.Diagnostics().PendingRecords == 0 })
				if d := e.Diagnostics(); d.Delivered != 3 || d.Dropped != 0 || d.Rejected != 0 {
					t.Fatalf("ingestion: %+v", d)
				}
				for index, id := range ids {
					digest := sha256.Sum256([]byte("consumer-test\x00" + id))
					traceID := hex.EncodeToString(digest[:16])
					client := &http.Client{Timeout: 5 * time.Second}
					var body []byte
					deadline := time.Now().Add(30 * time.Second)
					for time.Now().Before(deadline) {
						req, err := http.NewRequest(http.MethodGet, consumerQuery(target.Query, traceID, id), nil)
						if err != nil {
							t.Fatal(err)
						}
						for k, v := range target.Headers {
							req.Header.Set(k, v)
						}
						req.Header.Set("Accept", "application/json")
						res, err := client.Do(req)
						if err == nil {
							body, _ = io.ReadAll(io.LimitReader(res.Body, 4<<20))
							res.Body.Close()
							if res.StatusCode == 200 && strings.Contains(string(body), id) {
								break
							}
						}
						time.Sleep(100 * time.Millisecond)
					}
					var decoded any
					if json.Unmarshal(body, &decoded) != nil || !strings.Contains(string(body), id) {
						t.Fatalf("trace not queryable (response %d bytes)", len(body))
					}
					// Parse nested JSON strings too: consumers may preserve OTLP attributes or
					// normalize messages into their own input/output objects.
					text := consumerText(decoded)
					for _, expected := range []string{"consumer prompt 世界", "consumer response", "0.001"} {
						if !strings.Contains(text, expected) {
							t.Errorf("stored trace missing %q", expected)
						}
					}
					if index == 1 {
						for _, expected := range []string{"lookup_weather", "Vilnius", "Paris", "degrees 18", "consumer system instructions"} {
							if !strings.Contains(text, expected) {
								t.Errorf("stored tool conversation missing %q", expected)
							}
						}
					}
					assertConsumerFields(t, target.Name, decoded)
					if target.Name == "phoenix" {
						for _, expected := range []string{"LLM", "llm.input_messages.0.message.content", "llm.output_messages.0.message.content", "llm.token_count.prompt"} {
							if !strings.Contains(text, expected) {
								t.Errorf("Phoenix did not map %s", expected)
							}
						}
					}
				}
			})
		}
	}
}
func consumerText(value any) string {
	switch v := value.(type) {
	case map[string]any:
		var text strings.Builder
		for key, value := range v {
			text.WriteString(key)
			text.WriteByte(' ')
			text.WriteString(consumerText(value))
			text.WriteByte('\n')
		}
		return text.String()
	case []any:
		var text strings.Builder
		for _, value := range v {
			text.WriteString(consumerText(value))
			text.WriteByte('\n')
		}
		return text.String()
	case string:
		var nested any
		if json.Unmarshal([]byte(v), &nested) == nil {
			if _, same := nested.(string); !same {
				return consumerText(nested)
			}
		}
		return v
	default:
		return fmt.Sprint(v)
	}
}

func consumerQuery(query, traceID, requestID string) string {
	if strings.Contains(query, "{requestID}") {
		return strings.ReplaceAll(query, "{requestID}", url.QueryEscape(requestID))
	}
	return query + traceID
}

func assertConsumerFields(t *testing.T, name string, value any) {
	t.Helper()
	switch name {
	case "langfuse":
		rows := value.(map[string]any)["data"].([]any)
		if len(rows) != 1 {
			t.Fatalf("Langfuse observations=%d", len(rows))
		}
		row := rows[0].(map[string]any)
		assertConsumerContent(t, row["input"], row["output"])
		if row["type"] != "GENERATION" || row["inputUsage"] != float64(7) || row["outputUsage"] != float64(3) || row["totalCost"] != 0.001 {
			t.Error("Langfuse generation/usage/cost mapping")
		}
	case "opik":
		rows := value.(map[string]any)["content"].([]any)
		if len(rows) != 1 {
			t.Fatalf("Opik traces=%d", len(rows))
		}
		row := rows[0].(map[string]any)
		assertConsumerContent(t, row["input"], row["output"])
		usage := row["usage"].(map[string]any)
		if usage["prompt_tokens"] != float64(7) || usage["completion_tokens"] != float64(3) || row["total_estimated_cost"] != 0.001 {
			t.Error("Opik usage/cost mapping")
		}
	case "phoenix":
		rows := value.(map[string]any)["data"].([]any)
		if len(rows) != 1 {
			t.Fatalf("Phoenix spans=%d", len(rows))
		}
		row := rows[0].(map[string]any)
		attrs := row["attributes"].(map[string]any)
		// Phoenix prepends separate system instructions as message zero.
		inputs, outputs := map[string]any{}, map[string]any{}
		for key, value := range attrs {
			if strings.HasPrefix(key, "llm.input_messages.") {
				inputs[key] = value
			}
			if strings.HasPrefix(key, "llm.output_messages.") {
				outputs[key] = value
			}
		}
		assertConsumerContent(t, inputs, outputs)
		if attrs["llm.token_count.prompt"] != float64(7) || attrs["llm.token_count.completion"] != float64(3) || attrs["llm.cost.total"] != 0.001 {
			t.Error("Phoenix usage/cost mapping")
		}
	case "langwatch":
		row := value.(map[string]any)
		assertConsumerContent(t, row["input"], row["output"])
		metrics := row["metrics"].(map[string]any)
		if metrics["prompt_tokens"] != float64(7) || metrics["completion_tokens"] != float64(3) || metrics["total_cost"] != 0.001 {
			t.Error("LangWatch usage/cost mapping")
		}
	case "mlflow":
		trace := value.(map[string]any)["trace"].(map[string]any)
		assertConsumerContent(t, consumerAttribute(trace, "mlflow.spanInputs"), consumerAttribute(trace, "mlflow.spanOutputs"))
		metadata := trace["trace_info"].(map[string]any)["trace_metadata"].(map[string]any)
		var usage map[string]int
		if json.Unmarshal([]byte(metadata["mlflow.trace.tokenUsage"].(string)), &usage) != nil || usage["input_tokens"] != 7 || usage["output_tokens"] != 3 {
			t.Error("MLflow token usage mapping")
		}
	default:
		for key, expected := range map[string]string{
			"gen_ai.usage.input_tokens":  "7",
			"gen_ai.usage.output_tokens": "3",
			"stogas.cost.usd":            "0.001",
		} {
			attribute, ok := consumerAttribute(value, key).(map[string]any)
			if !ok || (fmt.Sprint(attribute["intValue"]) != expected && fmt.Sprint(attribute["stringValue"]) != expected) {
				t.Errorf("stored OTLP attribute %s missing or incorrect", key)
			}
		}

	}
}

func assertConsumerContent(t *testing.T, input, output any) {
	t.Helper()
	if !strings.Contains(consumerText(input), "consumer prompt 世界") || !strings.Contains(consumerText(output), "consumer response") {
		t.Error("consumer native input/output fields are missing content")
	}
}

// OTLP query APIs preserve typed attributes, sometimes with snake_case values.
func consumerAttribute(value any, key string) any {
	switch v := value.(type) {
	case map[string]any:
		if v["key"] == key {
			return v["value"]
		}
		for _, child := range v {
			if found := consumerAttribute(child, key); found != nil {
				return found
			}
		}
	case []any:
		for _, child := range v {
			if found := consumerAttribute(child, key); found != nil {
				return found
			}
		}
	}
	return nil
}
