package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
)

type operationalLogEvent struct {
	Environment string `json:"environment,omitempty"`
	ErrorType   string `json:"errorType,omitempty"`
	Event       string `json:"event"`
	ReasonCode  string `json:"reasonCode,omitempty"`
	RequestID   string `json:"requestId,omitempty"`
	Severity    string `json:"severity"`
}

func writeOperationalLog(event operationalLogEvent) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	output := os.Stdout
	if event.Severity == "error" {
		output = os.Stderr
	}
	_, _ = fmt.Fprintln(output, string(payload))
}

func safeOperationalErrorType(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "DeadlineExceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "Canceled"
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return "NetworkError"
	}
	return "Error"
}

func infisicalSecretFailureReason(secretName string) string {
	switch secretName {
	case "API_KEY_PEPPER":
		return "api_key_pepper_unavailable"
	case "BYOK_ENCRYPTION_SECRET":
		return "byok_encryption_secret_unavailable"
	case "CHUTES_API_KEY":
		return "chutes_api_key_unavailable"
	case "DATABASE_SCHEMA":
		return "database_schema_unavailable"
	case "DATABASE_URL":
		return "database_url_unavailable"
	case "INFERENCE_TOKEN_PUBLIC_KEY":
		return "inference_token_public_key_unavailable"
	default:
		return "required_secret_unavailable"
	}
}
