package utils

import (
	"context"

	schemas "github.com/maximhq/bifrost/core/schemas"
)

// BodySigner signs the final request body bytes after the handler has marshaled them and
// returns auth headers to set on the outgoing request. Handlers invoke it immediately after
// building the body, only when non-nil. The caller decides whether signing applies (e.g. AWS
// SigV4 for Bedrock Mantle when no API key is present); the handler stays auth-scheme-agnostic.
type BodySigner func(jsonData []byte) (map[string]string, *schemas.BifrostError)

// ContextBodySigner returns the signer a caller placed in the context for this request, such
// as AWS SigV4 for a Messages endpoint that AWS hosts, or nil.
func ContextBodySigner(ctx context.Context) BodySigner {
	if ctx == nil {
		return nil
	}
	signer, _ := ctx.Value(schemas.BifrostContextKeyRequestSigner).(schemas.RequestSigner)
	if signer == nil {
		return nil
	}
	return BodySigner(signer)
}
