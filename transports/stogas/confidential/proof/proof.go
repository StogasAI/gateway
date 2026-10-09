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

type Timing struct {
	TotalMS    uint32  `json:"total_ms"`
	ProviderMS uint32  `json:"provider_ms"`
	TTFTMS     *uint32 `json:"ttft_ms,omitempty"`
}

type Metadata struct {
	RequestID             string              `json:"request_id"`
	CreatedAt             string              `json:"created_at"`
	Catalog               Catalog             `json:"catalog"`
	Meters                billing.EventMeters `json:"meters"`
	UpstreamCostUSD       string              `json:"upstream_cost_usd"`
	BilledCostUSD         string              `json:"billed_cost_usd"`
	CacheReadSavingsUSD   *string             `json:"cache_read_savings_usd"`
	CacheWriteOverheadUSD *string             `json:"cache_write_overhead_usd"`
	Timing                Timing              `json:"timing"`
	Provider              map[string]any      `json:"provider,omitempty"`
}

type Input struct {
	RequestDigest *[32]byte
	ResponseBody  []byte
	Metadata      Metadata
}

// Receipt is the gateway's signature over exact content hashes and the canonical
// metadata bag. BootSHA256 resolves the hardware-bound signer.
type Receipt struct {
	Schema         string `json:"schema"`
	BootSHA256     string `json:"boot_sha256"`
	RequestSHA256  string `json:"request_sha256"`
	ResponseSHA256 string `json:"response_sha256"`
	Signature      string `json:"signature"`
}

// Object is the opt-in metadata covered by the receipt, excluding Receipt itself.
type Object struct {
	Metadata
	NodeID  string  `json:"node_id"`
	Receipt Receipt `json:"receipt"`
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
		!validMeterCosts(metadata) ||
		metadata.Timing.ProviderMS > metadata.Timing.TotalMS ||
		(metadata.Timing.TTFTMS != nil && *metadata.Timing.TTFTMS > metadata.Timing.TotalMS) {
		return false
	}
	return true
}

func validMeterCosts(metadata Metadata) bool {
	if len(metadata.Meters) > 64 || !isUSD(metadata.UpstreamCostUSD) || !isUSD(metadata.BilledCostUSD) ||
		metadata.CacheReadSavingsUSD != nil && !isUSD(*metadata.CacheReadSavingsUSD) ||
		metadata.CacheWriteOverheadUSD != nil && !isUSD(*metadata.CacheWriteOverheadUSD) {
		return false
	}
	_, _, err := billing.ValidateMeters(metadata.Meters)
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

func isDecimal(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
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
