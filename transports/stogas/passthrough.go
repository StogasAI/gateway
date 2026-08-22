package stogas

import (
	"errors"

	"github.com/maximhq/bifrost/core/schemas"
)

func CanonicalPassthroughCredential(
	provider schemas.ModelProvider,
	apiKey string,
) (string, error) {
	if !validUpstreamAPIKey(apiKey) {
		return "", errors.New("pass-through credential is invalid")
	}
	if provider != schemas.Azure {
		return apiKey, nil
	}
	return "", errors.New("unsupported Azure pass-through credentials; assign a discovered Azure credential to this Stogas API key")
}
