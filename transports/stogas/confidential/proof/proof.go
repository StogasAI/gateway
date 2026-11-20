package proof

import (
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/money"
	"strings"
	"time"
)

const MaxObjectBytes = 16 * 1024
const createdAtLayout = "2006-01-02T15:04:05.000Z"

var catalogNodeKinds = [...]string{"author", "model", "deployment", "route", "provider"}

type Meter = billing.EventMeter

type Catalog struct {
	Version      uint64   `json:"version"`
	ChainHash    string   `json:"chain_hash"`
	SelectionIDs []string `json:"selection_ids"`
}

// Performance holds the times that the request record's performance holds, and the provider time
// that the record's attempts give, because the metadata lists no attempts.
type Performance struct {
	TotalMS         uint32  `json:"total_ms"`
	ProviderMS      uint32  `json:"provider_ms"`
	RateLimitWaitMS uint32  `json:"rate_limit_wait_ms"`
	FirstOutputMS   *uint32 `json:"first_output_ms"`
	TTFTMS          *uint32 `json:"ttft_ms"`
}

// Metadata is what the request record says about the request under the record's own names, for
// the caller: the record itself also names the organization's policies, credentials and members,
// which a key's holder may not read.
type Metadata struct {
	RequestID            string               `json:"request_id"`
	CreatedAt            string               `json:"created_at"`
	Catalog              Catalog              `json:"catalog"`
	PolicyVersionsSHA512 string               `json:"policy_versions_sha512,omitempty"`
	Performance          Performance          `json:"performance"`
	Usage                billing.RequestUsage `json:"usage"`
	Provider             map[string]any       `json:"provider,omitempty"`
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

func ValidCatalogSelectionIDs(selectionIDs []string) bool {
	if len(selectionIDs) != len(catalogNodeKinds) {
		return false
	}
	for index, value := range selectionIDs {
		id, ok := strings.CutPrefix(value, catalogNodeKinds[index]+":")
		if !ok || !validIdentifier(id, 128) {
			return false
		}
	}
	return true
}

func ValidMetadata(metadata Metadata) bool {
	if metadata.RequestID == "" || len(metadata.RequestID) > 128 ||
		!validCreatedAt(metadata.CreatedAt) ||
		!ValidCatalog(metadata.Catalog) ||
		(metadata.PolicyVersionsSHA512 != "" && !isLowerHex(metadata.PolicyVersionsSHA512, 64)) ||
		!validUsage(metadata.Usage) ||
		metadata.Performance.ProviderMS > metadata.Performance.TotalMS ||
		(metadata.Performance.TTFTMS != nil && *metadata.Performance.TTFTMS > metadata.Performance.TotalMS) {
		return false
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

func ValidCatalog(catalog Catalog) bool {
	digest, ok := strings.CutPrefix(catalog.ChainHash, "sha256:")
	return catalog.Version > 0 && catalog.Version <= 9007199254740991 &&
		ok && isLowerHex(digest, 32) && ValidCatalogSelectionIDs(catalog.SelectionIDs)
}

func validIdentifier(value string, maxLength int) bool {
	if len(value) == 0 || len(value) > maxLength {
		return false
	}
	for position, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') {
			continue
		}
		if position == 0 || (character != '.' && character != '_' && character != '-') {
			return false
		}
	}
	return true
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
