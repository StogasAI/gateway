package stogashttp

import (
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
	if wantsExtraFields(bifrostCtx) {
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
		applyProofHeaders(ctx, output)
	}
	ctx.SetStatusCode(statusCode)
	ctx.SetContentType("application/json")
	_, _ = ctx.Write(data)
}

func (s *Server) newStreamProof(requestCtx *fasthttp.RequestCtx, ctx *schemas.BifrostContext, state *stogas.State) (*proofhttp.Stream, error) {
	if !wantsExtraFields(ctx) {
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
		NodeID:    state.NodeID,
		Catalog: proof.Catalog{
			Digest:   catalogIdentity.Digest,
			Sequence: catalogIdentity.Sequence,
			NodeIDs:  state.Resolution.CatalogNodeIDsForDeployment(executionDeployment),
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
	if len(event.ProviderAttempts) > 0 {
		byok := strings.TrimSpace(event.ProviderAttempts[0].UpstreamByok)
		if byok != "" && byok != "stogas" {
			result.BYOKCostUSDAtoms = event.UpstreamCostUSDAtoms
		}
	}
	for key, raw := range event.Pricing {
		entry, ok := raw.(map[string]any)
		if !ok {
			result.Meters[key] = proof.Meter{}
			continue
		}
		quantity, _ := entry["quantity"].(string)
		rateKey, _ := entry["rateKey"].(string)
		rateUSDAtoms, _ := entry["rateUsdAtoms"].(string)
		usdAtoms, _ := entry["usdAtoms"].(string)
		result.Meters[key] = proof.Meter{
			Quantity:     quantity,
			RateKey:      rateKey,
			RateUSDAtoms: rateUSDAtoms,
			USDAtoms:     usdAtoms,
		}
	}
	return result
}

func proofTiming(event *billing.RequestEvent) proof.Timing {
	if event == nil {
		return proof.Timing{}
	}
	result := proof.Timing{TotalMS: event.TotalTimeMS}
	if len(event.ProviderAttempts) > 0 {
		result.ProviderMS = event.ProviderAttempts[0].LatencyMS
		result.TimeToFirstOutputMS = event.ProviderAttempts[0].ProviderFirstOutputMS
	}
	return result
}

func applyProofHeaders(ctx *fasthttp.RequestCtx, output *proofhttp.Output) {
	if output == nil {
		return
	}
	for key, value := range output.Headers {
		ctx.Response.Header.Set(key, value)
	}
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
