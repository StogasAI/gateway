package exporter

import (
	"crypto/sha256"
	"math"
	"strconv"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func (c *Capture) trace(r Record, d exportconfig.Destination, limit int) (ptrace.Traces, bool) {
	traces := ptrace.NewTraces()
	resource := traces.ResourceSpans().AppendEmpty()
	resource.Resource().Attributes().PutStr("service.name", "stogas")
	resource.Resource().Attributes().PutStr("service.version", r.Version)
	scope := resource.ScopeSpans().AppendEmpty()
	scope.Scope().SetName("ai.stogas.export")
	span := scope.Spans().AppendEmpty()
	identity := sha256.Sum256([]byte(c.tenant + "\x00" + r.RequestID))
	var traceID pcommon.TraceID
	copy(traceID[:], identity[:16])
	span.SetTraceID(traceID)
	var spanID pcommon.SpanID
	copy(spanID[:], identity[16:24])
	span.SetSpanID(spanID)
	span.SetName("chat " + r.Model)
	span.SetKind(ptrace.SpanKindClient)
	span.SetStartTimestamp(pcommon.NewTimestampFromTime(r.StartedAt))
	ended := r.EndedAt
	if ended.IsZero() {
		ended = time.Now()
	}
	span.SetEndTimestamp(pcommon.NewTimestampFromTime(ended))
	a := span.Attributes()
	c.parameters.CopyTo(a)
	a.PutStr("gen_ai.operation.name", "chat")
	a.PutStr("gen_ai.provider.name", r.Provider)
	a.PutStr("gen_ai.request.model", r.Model)
	if r.ResponseModel != "" {
		a.PutStr("gen_ai.response.model", r.ResponseModel)
	}
	for key, value := range map[string]*int64{
		"gen_ai.usage.input_tokens":                r.InputTokens,
		"gen_ai.usage.output_tokens":               r.OutputTokens,
		"gen_ai.usage.cache_read.input_tokens":     r.CachedInputTokens,
		"gen_ai.usage.cache_creation.input_tokens": r.CacheWriteTokens,
		"gen_ai.usage.reasoning.output_tokens":     r.ReasoningTokens,
	} {
		if value != nil {
			a.PutInt(key, *value)
		}
	}
	if r.TimeToFirstTokenMS != nil {
		a.PutInt("stogas.performance.ttft_ms", int64(*r.TimeToFirstTokenMS))
	}
	if r.FinishReason != "" {
		a.PutEmptySlice("gen_ai.response.finish_reasons").AppendEmpty().SetStr(finishReason(r.FinishReason))
	}
	a.PutStr("stogas.request.id", r.RequestID)
	a.PutStr("stogas.request.type", r.RequestType)
	a.PutStr("stogas.outcome", r.Outcome)
	a.PutStr("stogas.cost.usd", r.CostUSD)
	// OpenInference supplies the cross-consumer USD cost convention missing
	// from GenAI. Keep the decimal above as the authoritative exact amount.
	if cost, err := strconv.ParseFloat(r.CostUSD, 64); err == nil && cost >= 0 && !math.IsInf(cost, 0) && !math.IsNaN(cost) {
		a.PutDouble("llm.cost.total", cost)
		// Opik consumes this established ingestion attribute. It is a consumer
		// compatibility field, not a registered OpenTelemetry GenAI attribute.
		a.PutDouble("gen_ai.usage.cost", cost)
		// LangWatch preserves the other cost attributes but maps this one to its
		// native cost metric. These aliases duplicate only a scalar, never content.
		a.PutDouble("langwatch.span.cost", cost)
	}

	if r.Metadata != "" {
		a.PutStr("stogas.request.metadata", r.Metadata)
	}
	if r.Outcome == "failure" {
		span.Status().SetCode(ptrace.StatusCodeError)
		a.PutStr("error.type", r.ErrorCode)
		if r.ErrorStatus != 0 {
			a.PutInt("stogas.error.status", int64(r.ErrorStatus))
		}
	}
	a.PutBool("stogas.output.incomplete", r.Outcome != "success")
	truncated := false
	if d.InputEnabled() {
		encoded, instructions, t := c.input.encode(limit)
		if instructions != "" {
			a.PutStr("gen_ai.system_instructions", instructions)
		}
		a.PutStr("gen_ai.input.messages", encoded)
		a.PutBool("stogas.input.truncated", t)
		a.PutBool("stogas.input.omitted", c.input.omitted)
		truncated = truncated || t
	}
	if d.OutputEnabled() {
		encoded, _, t := c.output.encode(limit)
		a.PutStr("gen_ai.output.messages", encoded)
		a.PutBool("stogas.output.truncated", t)
		a.PutBool("stogas.output.omitted", c.output.omitted)
		truncated = truncated || t
	}
	return traces, truncated
}
