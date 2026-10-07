package exporter

import (
	"math"

	"github.com/maximhq/bifrost/core/schemas"
)

// Capture only scalar generation settings. Request metadata, user identifiers,
// arbitrary provider parameters and content-bearing settings stay excluded.
func (c *Capture) captureParameters(request *schemas.BifrostRequest) {
	putFloat := func(key string, value *float64) {
		if value != nil && !math.IsNaN(*value) && !math.IsInf(*value, 0) {
			c.parameters.PutDouble("gen_ai.request."+key, *value)
		}
	}
	putInt := func(key string, value *int) {
		if value != nil {
			c.parameters.PutInt("gen_ai.request."+key, int64(*value))
		}
	}
	if request.ChatRequest != nil && request.ChatRequest.Params != nil {
		p := request.ChatRequest.Params
		putFloat("temperature", p.Temperature)
		putFloat("top_p", p.TopP)
		putFloat("frequency_penalty", p.FrequencyPenalty)
		putFloat("presence_penalty", p.PresencePenalty)
		putInt("max_tokens", p.MaxCompletionTokens)
		putInt("seed", p.Seed)
		putInt("top_k", p.TopK)
	}
	if request.ResponsesRequest != nil && request.ResponsesRequest.Params != nil {
		p := request.ResponsesRequest.Params
		putFloat("temperature", p.Temperature)
		putFloat("top_p", p.TopP)
		putFloat("frequency_penalty", p.FrequencyPenalty)
		putFloat("presence_penalty", p.PresencePenalty)
		putInt("max_tokens", p.MaxOutputTokens)
	}
}
