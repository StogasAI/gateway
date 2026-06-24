package catalog

import (
	"errors"
	"net/http"

	"github.com/maximhq/bifrost/transports/stogas/providers"
)

var ErrProviderContainersUnsupported = APIError{
	StatusCode: http.StatusBadRequest,
	Type:       ErrorTypeInvalidRequest,
	Message:    "Provider-hosted containers are not supported by Stogas",
}

func ProviderPolicyError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, providers.ErrProviderContainers):
		return ErrProviderContainersUnsupported
	case errors.Is(err, providers.ErrUnsupportedTool), errors.Is(err, providers.ErrInvalidProviderToolSpec):
		return ErrUnsupportedTool
	case errors.Is(err, providers.ErrUnsupportedParameter):
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Parameter is not supported by Stogas provider policy"}
	case errors.Is(err, providers.ErrUnsupportedInput):
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Input modality is not supported by Stogas billing policy"}
	case errors.Is(err, providers.ErrOutputTokenLimitTooLow):
		return ErrParameterTooLarge
	default:
		return err
	}
}
