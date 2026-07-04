package stogashttp

import (
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	"github.com/valyala/fasthttp"
)

func (s *Server) writeInferenceJSON(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, state *stogas.State, statusCode int, payload any) {
	data, err := marshalPayload(payload)
	if err != nil {
		s.writeError(ctx, fasthttp.StatusInternalServerError, map[string]any{
			"error": map[string]any{"message": "Failed to encode response", "type": "internal_error"},
		})
		return
	}
	if s.proofs != nil {
		input, err := s.proofInput(state, data)
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

func (s *Server) newStreamProof(state *stogas.State) (*proofhttp.Stream, error) {
	if s.proofs == nil {
		return nil, nil
	}
	input, err := s.proofInput(state, nil)
	if err != nil {
		return nil, err
	}
	return proofhttp.NewStream(input)
}

func (s *Server) proofInput(state *stogas.State, responseJSON []byte) (proofhttp.Input, error) {
	if state == nil || state.Resolution == nil {
		return proofhttp.Input{}, catalog.ErrUnsupportedRequest
	}
	catalogHash, ok := catalog.PublicCatalogHash()
	if !ok {
		return proofhttp.Input{}, catalog.ErrCatalogUnavailable
	}
	return proofhttp.Input{
		CatalogHash:          catalogHash,
		CatalogNodeIDs:       state.Resolution.CatalogNodeIDs(),
		ProcessedRequestJSON: append([]byte(nil), state.ProcessedRequestJSON...),
		ResponseJSON:         append([]byte(nil), responseJSON...),
	}, nil
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
			"message": "Failed to build confidential response proof",
			"type":    "internal_error",
		},
	})
}
