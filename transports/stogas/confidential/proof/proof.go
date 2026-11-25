package proof

import (
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/money"
	"strings"
	"time"
)

// MaxObjectBytes bounds the response's `stogas` object. The caller's part of the largest request
// record fits it with its receipt and salts, so no response fails for its metadata's size.
const MaxObjectBytes = 64 * 1024
const createdAtLayout = "2006-01-02T15:04:05.000Z"

type Meter = billing.EventMeter

// Metadata is the part of the request record that the caller of the request may read, under the
// record's own names and with its values: Select takes it from the finished record and from
// nothing else. The record's other fields name the organization's keys, members, policies,
// credentials and plugins, repeat what the caller sent, or are settled only after the response.
// PolicyVersionsSHA512 stands for the record's policy_versions, which the caller may not read.
type Metadata struct {
	RequestID            string               `json:"request_id"`
	CreatedAt            string               `json:"created_at"`
	Transport            string               `json:"transport"`
	CatalogVersion       *uint64              `json:"catalog_version"`
	PolicyVersionsSHA512 string               `json:"policy_versions_sha512,omitempty"`
	ProviderAttempts     []ProviderAttempt    `json:"provider_attempts"`
	Performance          Performance          `json:"performance"`
	Usage                billing.RequestUsage `json:"usage"`
	GatewayVersion       string               `json:"gateway_version"`
}

// ProviderAttempt is the record's provider attempt without the credential that made the call and
// that credential's account options.
type ProviderAttempt struct {
	CatalogChainHash         string `json:"catalog_chain_hash"`
	ResolvedCatalogChainHash string `json:"resolved_catalog_chain_hash,omitempty"`
	Provider                 string `json:"provider"`
	Status                   string `json:"status"`
	StatusCode               *int   `json:"status_code"`
	ErrorCode                string `json:"error_code,omitempty"`
	StartMS                  uint32 `json:"start_ms"`
	LatencyMS                uint32 `json:"latency_ms"`
	OutputObserved           bool   `json:"output_observed"`
	ProviderRequestID        string `json:"provider_request_id"`
	ProviderResponseID       string `json:"provider_response_id"`
	ProviderModel            string `json:"provider_model"`
	ProviderInstanceID       string `json:"provider_instance_id,omitempty"`
	ProviderEncryptionKey    string `json:"provider_encryption_key_sha256,omitempty"`
	ProviderMeasurement      string `json:"provider_measurement_sha256,omitempty"`
	FinishReason             string `json:"finish_reason"`
}

// Performance holds the record's times without its tool calls, which the response itself shows.
type Performance struct {
	TotalMS         uint32  `json:"total_ms"`
	RateLimitWaitMS uint32  `json:"rate_limit_wait_ms"`
	FirstOutputMS   *uint32 `json:"first_output_ms"`
	TTFTMS          *uint32 `json:"ttft_ms"`
}

// Select takes the caller's part of a finished request record.
func Select(event *billing.RequestEvent) Metadata {
	metadata := Metadata{
		RequestID: event.RequestID, CreatedAt: event.CreatedAt, Transport: event.Transport,
		CatalogVersion: event.CatalogVersion, ProviderAttempts: make([]ProviderAttempt, len(event.ProviderAttempts)),
		Performance: Performance{
			TotalMS: event.Performance.TotalMS, RateLimitWaitMS: event.Performance.RateLimitWaitMS,
			FirstOutputMS: event.Performance.FirstOutputMS, TTFTMS: event.Performance.TTFTMS,
		},
		Usage: event.Usage, GatewayVersion: event.GatewayVersion,
	}
	if event.PolicyVersions != nil {
		metadata.PolicyVersionsSHA512 = event.PolicyVersions.SHA512()
	}
	for index, attempt := range event.ProviderAttempts {
		metadata.ProviderAttempts[index] = ProviderAttempt{
			CatalogChainHash: attempt.CatalogChainHash, ResolvedCatalogChainHash: attempt.ResolvedCatalogChainHash,
			Provider: attempt.Provider, Status: attempt.Status, StatusCode: attempt.StatusCode, ErrorCode: attempt.ErrorCode,
			StartMS: attempt.StartMS, LatencyMS: attempt.LatencyMS, OutputObserved: attempt.OutputObserved,
			ProviderRequestID: attempt.ProviderRequestID, ProviderResponseID: attempt.ProviderResponseID,
			ProviderModel: attempt.ProviderModel, ProviderInstanceID: attempt.ProviderInstanceID,
			ProviderEncryptionKey: attempt.ProviderEncryptionKey,
			ProviderMeasurement:   attempt.ProviderMeasurement,
			FinishReason:          attempt.FinishReason,
		}
	}
	return metadata
}

type Input struct {
	// RequestDigest is the SHA-512 of the request body's RFC 8785 form.
	RequestDigest *[64]byte
	ResponseBody  []byte
	Metadata      Metadata
}

// Receipt is the gateway's signature over salted commitments to the request and the
// response, and over the canonical metadata bag. BootSHA256 resolves the hardware-bound
// signer.
type Receipt struct {
	Schema             string `json:"schema"`
	BootSHA256         string `json:"boot_sha256"`
	RequestCommitment  string `json:"request_commitment"`
	ResponseCommitment string `json:"response_commitment"`
	Signature          string `json:"signature"`
}

// Salts are what each commitment hides its content under. Only the caller receives them:
// with them, a commitment proves its content; without them, it reveals nothing about it.
// Logs and exports never hold them.
type Salts struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

// Object is the opt-in metadata covered by the receipt, excluding Receipt and Salts.
type Object struct {
	Metadata
	NodeID  string  `json:"node_id"`
	Receipt Receipt `json:"receipt"`
	Salts   *Salts  `json:"salts,omitempty"`
}

// ValidMetadata reports whether the metadata is that of a request that a provider served, which
// is the only request that gets a receipt.
func ValidMetadata(metadata Metadata) bool {
	if metadata.RequestID == "" || len(metadata.RequestID) > 128 ||
		!validCreatedAt(metadata.CreatedAt) ||
		metadata.CatalogVersion == nil || *metadata.CatalogVersion == 0 || *metadata.CatalogVersion > 9007199254740991 ||
		len(metadata.ProviderAttempts) == 0 ||
		(metadata.PolicyVersionsSHA512 != "" && !isLowerHex(metadata.PolicyVersionsSHA512, 64)) ||
		!validUsage(metadata.Usage) ||
		(metadata.Performance.TTFTMS != nil && *metadata.Performance.TTFTMS > metadata.Performance.TotalMS) {
		return false
	}
	for _, attempt := range metadata.ProviderAttempts {
		digest, ok := strings.CutPrefix(attempt.CatalogChainHash, "sha256:")
		if !ok || !isLowerHex(digest, 32) {
			return false
		}
	}
	return true
}

func validUsage(usage billing.RequestUsage) bool {
	if len(usage.Meters) > 64 || !isUSD(usage.UpstreamCostUSD) || !isUSD(usage.BilledCostUSD) ||
		usage.CacheReadSavingsUSD != nil && !isUSD(*usage.CacheReadSavingsUSD) ||
		usage.CacheWriteOverheadUSD != nil && !isUSD(*usage.CacheWriteOverheadUSD) {
		return false
	}
	_, err := billing.ValidateMeters(usage.Meters)
	return err == nil
}

func validCreatedAt(value string) bool {
	parsed, err := time.Parse(createdAtLayout, value)
	return err == nil && parsed.Format(createdAtLayout) == value
}

func isLowerHex(value string, bytes int) bool {
	if len(value) != bytes*2 {
		return false
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func isUSD(value string) bool {
	amount, err := money.Parse(value)
	return err == nil && amount.Sign() >= 0 && amount.String() == value
}
