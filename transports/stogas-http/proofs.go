package stogashttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	"net/http"
)

const responseProofErrorCode = "stogas_response_proof_failed"

func responseProofFailure() *schemas.BifrostError {
	statusCode := http.StatusInternalServerError
	errorType := "internal_error"
	allowFallbacks := false
	return &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &statusCode,
		Type:           &errorType,
		AllowFallbacks: &allowFallbacks,
		Error: &schemas.ErrorField{
			Type:    &errorType,
			Code:    schemas.Ptr(responseProofErrorCode),
			Message: "Failed to build confidential response proof",
		},
	}
}

func responseEncodingFailure() *schemas.BifrostError {
	statusCode := http.StatusInternalServerError
	errorType := "internal_error"
	allowFallbacks := false
	return &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &statusCode,
		Type:           &errorType,
		AllowFallbacks: &allowFallbacks,
		Error:          &schemas.ErrorField{Type: &errorType, Code: schemas.Ptr("response_encoding_failed"), Message: "Failed to encode response"},
	}
}

// PrepareFinalState runs before response metadata captures final pricing and
// timing. If encoding or receipt generation then fails,
// discard that event so settlement records failed Stogas processing while
// retaining the provider's independently observed outcome.
func retainResponseFailure(state *stogas.State, failure *schemas.BifrostError) {
	if state == nil {
		return
	}
	state.ProcessingError = failure
	state.FinalEvent = nil
}

func (s *Server) writeInferenceJSON(ctx *requestContext, bifrostCtx *schemas.BifrostContext, state *stogas.State, statusCode int, payload any) {
	data, err := marshalPayload(payload)
	if err != nil {
		retainResponseFailure(state, responseEncodingFailure())
		s.writeError(ctx, http.StatusInternalServerError, map[string]any{
			"error": map[string]any{"message": "Failed to encode response", "type": "internal_error"},
		})
		return
	}
	if _, borrowed := payload.([]byte); !borrowed {
		defer clear(data)
	}
	if wantsReceipt(bifrostCtx) {
		if s.proofs == nil {
			retainResponseFailure(state, responseProofFailure())
			s.writeProofError(ctx)
			return
		}
		input, err := s.proofInput(ctx, bifrostCtx, state, data)
		if err != nil {
			retainResponseFailure(state, responseProofFailure())
			s.writeProofError(ctx)
			return
		}
		output, err := s.proofs.Build(bifrostCtx, input)
		if err != nil {
			retainResponseFailure(state, responseProofFailure())
			s.writeProofError(ctx)
			return
		}
		data, err = appendStogasReceipt(data, output.JSON)
		defer clear(data)
		if err != nil {
			retainResponseFailure(state, responseProofFailure())
			s.writeProofError(ctx)
			return
		}
	}
	s.writeResponse(ctx, statusCode, "application/json", data)
}

func (s *Server) newStreamProof(requestCtx *requestContext, ctx *schemas.BifrostContext, state *stogas.State) (*proofhttp.Stream, error) {
	if !wantsReceipt(ctx) {
		return nil, nil
	}
	if s.proofs == nil {
		return nil, errors.New("confidential response proof is unavailable")
	}
	input, err := s.proofInput(requestCtx, ctx, state, nil)
	if err != nil {
		return nil, err
	}
	return s.proofs.NewStream(ctx, input)
}

func (s *Server) proofInput(ctx *requestContext, bifrostCtx context.Context, state *stogas.State, responseJSON []byte) (proofhttp.Input, error) {
	if state == nil || state.Resolution == nil {
		return proofhttp.Input{}, catalog.ErrUnsupportedRequest
	}
	digest, err := ctx.receiptRequestDigest()
	if err != nil {
		return proofhttp.Input{}, err
	}
	return proofhttp.Input{
		RequestDigest: digest,
		ResponseBody:  responseJSON,
		Metadata:      proofMetadata(bifrostCtx, state),
	}, nil
}

func proofMetadata(ctx context.Context, state *stogas.State) proof.Metadata {
	if state == nil || state.Resolution == nil {
		return proof.Metadata{}
	}
	catalogIdentity := state.Resolution.CatalogIdentity()
	executionDeployment := stogas.ExecutionDeployment(state)
	metadata := proof.Metadata{
		RequestID: state.RequestID,
		CreatedAt: proofCreatedAt(state.FinalEvent),
		Catalog: proof.Catalog{
			Version:      catalogIdentity.Sequence,
			ChainHash:    executionDeployment.ChainHash,
			SelectionIDs: state.Resolution.CatalogNodeIDsForDeployment(executionDeployment),
		},

		Timing:   proofTiming(state.FinalEvent),
		Provider: chutese2ee.InvocationMetadata(ctx),
		Meters:   billing.EventMeters{}, UpstreamCostUSD: "0", BilledCostUSD: "0",
	}
	if event := state.FinalEvent; event != nil {
		metadata.Meters = event.Meters
		metadata.UpstreamCostUSD, metadata.BilledCostUSD = event.UpstreamCostUSD, event.BilledCostUSD
		metadata.CacheReadSavingsUSD, metadata.CacheWriteOverheadUSD = event.CacheReadSavingsUSD, event.CacheWriteOverheadUSD
	}
	return metadata
}

func proofTiming(event *billing.RequestEvent) proof.Timing {
	if event == nil {
		return proof.Timing{}
	}
	result := proof.Timing{
		TotalMS:    event.Performance.TotalMS,
		ProviderMS: event.Performance.ProviderMS,
		TTFTMS:     event.Performance.TTFTMS,
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

func (s *Server) writeProofError(ctx *requestContext) {
	s.writeBifrostError(ctx, responseProofFailure())
}

// receiptRequestDigest commits to the original received bytes once. Keeping the
// digest lets the handler discard its input body before waiting on the provider.
func (ctx *requestContext) receiptRequestDigest() (*[32]byte, error) {
	if ctx.requestDigest == nil {
		if len(ctx.body) == 0 {
			return nil, errors.New("receipt request content is empty")
		}
		ctx.requestDigest = new(sha256.Sum256(ctx.body))
	}
	return ctx.requestDigest, nil
}
