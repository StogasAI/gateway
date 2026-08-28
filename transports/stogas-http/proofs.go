package stogashttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	"github.com/valyala/fasthttp"
)

const responseProofErrorCode = "stogas_response_proof_failed"

func (s *Server) writeInferenceJSON(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, state *stogas.State, statusCode int, payload any) {
	data, err := marshalPayload(payload)
	if err != nil {
		s.writeError(ctx, fasthttp.StatusInternalServerError, map[string]any{
			"error": map[string]any{"message": "Failed to encode response", "type": "internal_error"},
		})
		return
	}
	if wantsReceipt(bifrostCtx) {
		if s.proofs == nil {
			s.writeProofError(ctx)
			return
		}
		input, err := s.proofInput(ctx, state, data)
		if err != nil {
			s.writeProofError(ctx)
			return
		}
		output, err := s.proofs.Build(bifrostCtx, input)
		if err != nil {
			s.writeProofError(ctx)
			return
		}
		data, err = appendStogasReceipt(data, output.JSON)
		if err != nil {
			s.writeProofError(ctx)
			return
		}
	}
	ctx.SetStatusCode(statusCode)
	ctx.SetContentType("application/json")
	_, _ = ctx.Write(data)
}

func (s *Server) newStreamProof(requestCtx *fasthttp.RequestCtx, ctx *schemas.BifrostContext, state *stogas.State) (*proofhttp.Stream, error) {
	if !wantsReceipt(ctx) {
		return nil, nil
	}
	if s.proofs == nil {
		return nil, errors.New("confidential response proof is unavailable")
	}
	input, err := s.proofInput(requestCtx, state, nil)
	if err != nil {
		return nil, err
	}
	return s.proofs.NewStream(ctx, input)
}

func (s *Server) proofInput(ctx *fasthttp.RequestCtx, state *stogas.State, responseJSON []byte) (proofhttp.Input, error) {
	if state == nil || state.Resolution == nil {
		return proofhttp.Input{}, catalog.ErrUnsupportedRequest
	}
	var transcriptSHA256 string
	if session := encryptedSession(ctx); session != nil {
		transcriptSHA256 = session.TranscriptSHA256()
	}
	return proofhttp.Input{
		RequestBody:  append([]byte(nil), ctx.Request.Body()...),
		ResponseBody: append([]byte(nil), responseJSON...),
		Metadata:     proofMetadata(state, transcriptSHA256),
	}, nil
}

func proofMetadata(state *stogas.State, transcriptSHA256 string) proof.Metadata {
	if state == nil || state.Resolution == nil {
		return proof.Metadata{}
	}
	catalogIdentity := state.Resolution.CatalogIdentity()
	executionDeployment := stogas.ExecutionDeployment(state)
	return proof.Metadata{
		RequestID: state.RequestID,
		CreatedAt: proofCreatedAt(state.FinalEvent),
		NodeID:    state.NodeID,
		Catalog: proof.Catalog{
			Digest:       catalogIdentity.Digest,
			Sequence:     catalogIdentity.Sequence,
			SelectionIDs: state.Resolution.CatalogNodeIDsForDeployment(executionDeployment),
		},
		Pricing:              proofPricing(state.FinalEvent),
		Timing:               proofTiming(state.FinalEvent),
		E2EETranscriptSHA256: transcriptSHA256,
	}
}

func proofPricing(event *billing.RequestEvent) proof.Pricing {
	result := proof.Pricing{Meters: map[string]proof.Meter{}, TotalCostUSDAtoms: "0"}
	if event == nil {
		return result
	}
	result.TotalCostUSDAtoms = event.BilledCostUSDAtoms
	if finalAttempt, ok := event.FinalProviderAttempt(); ok {
		byok := strings.TrimSpace(finalAttempt.UpstreamByok)
		if byok != "" && byok != "stogas" {
			result.BYOKCostUSDAtoms = event.UpstreamCostUSDAtoms
		}
	}
	for key, entry := range event.Pricing {
		result.Meters[key] = proof.Meter{
			Quantity:     entry.Quantity,
			RateKey:      entry.RateKey,
			RateUSDAtoms: entry.RateUSDAtoms,
			USDAtoms:     entry.USDAtoms,
		}
	}
	return result
}

func proofTiming(event *billing.RequestEvent) proof.Timing {
	if event == nil {
		return proof.Timing{}
	}
	result := proof.Timing{
		TotalMS:    event.TotalTimeMS,
		ProviderMS: event.ProviderDurationMS(),
		TTFTMS:     event.TTFTMS,
	}
	return result
}

func proofCreatedAt(event *billing.RequestEvent) string {
	if event == nil {
		return ""
	}
	return event.CreatedAt
}

func appendStogasReceipt(responseJSON, receiptJSON []byte) ([]byte, error) {
	if len(responseJSON) < 2 || responseJSON[0] != '{' || responseJSON[len(responseJSON)-1] != '}' ||
		!json.Valid(responseJSON) || len(receiptJSON) == 0 || len(receiptJSON) > proof.MaxObjectBytes || !json.Valid(receiptJSON) {
		return nil, errors.New("response proof JSON is invalid")
	}
	separator := []byte(`,"stogas":`)
	if bytes.Equal(responseJSON, []byte("{}")) {
		separator = []byte(`"stogas":`)
	}
	result := make([]byte, 0, len(responseJSON)+len(separator)+len(receiptJSON))
	result = append(result, responseJSON[:len(responseJSON)-1]...)
	result = append(result, separator...)
	result = append(result, receiptJSON...)
	return append(result, '}'), nil
}

func (s *Server) writeProofError(ctx *fasthttp.RequestCtx) {
	s.writeError(ctx, fasthttp.StatusInternalServerError, map[string]any{
		"error": map[string]any{
			"code":    responseProofErrorCode,
			"message": "Failed to build confidential response proof",
			"type":    "internal_error",
		},
	})
}
