package proof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"hash"
	"strings"
)

const (
	DomainV5       = "stogas.response-proof.v5"
	MaxObjectBytes = 8 * 1024
)

var catalogNodeKinds = [...]string{"author", "model", "deployment", "route", "provider"}

type Meter struct {
	Quantity     string `json:"quantity"`
	RateKey      string `json:"rateKey"`
	RateUSDAtoms string `json:"rateUsdAtoms"`
	USDAtoms     string `json:"usdAtoms"`
}

type Catalog struct {
	Digest   string   `json:"digest"`
	Sequence uint64   `json:"sequence"`
	NodeIDs  []string `json:"node_ids"`
}

type Pricing struct {
	Meters            map[string]Meter `json:"meters"`
	TotalCostUSDAtoms string           `json:"total_cost_usd_atoms"`
	BYOKCostUSDAtoms  string           `json:"byok_cost_usd_atoms,omitempty"`
}

type Timing struct {
	TotalMS             uint32  `json:"total_ms"`
	ProviderMS          uint32  `json:"provider_ms"`
	TimeToFirstOutputMS *uint32 `json:"time_to_first_output_ms,omitempty"`
}

type Metadata struct {
	RequestID            string
	NodeID               string
	Catalog              Catalog
	Pricing              Pricing
	Timing               Timing
	E2EETranscriptSHA256 string
}

type Input struct {
	RequestBody  []byte
	ResponseBody []byte
	Metadata     Metadata
}

type StreamingInput struct {
	RequestBody []byte
	Metadata    Metadata
}

type Claims struct {
	RequestSHA256        string `json:"request_sha256"`
	ResponseSHA256       string `json:"response_sha256"`
	E2EETranscriptSHA256 string `json:"e2ee_transcript_sha256,omitempty"`
}

type Payload struct {
	Schema    string  `json:"schema"`
	RequestID string  `json:"request_id"`
	NodeID    string  `json:"node_id"`
	Catalog   Catalog `json:"catalog"`
	Pricing   Pricing `json:"pricing"`
	Timing    Timing  `json:"timing"`
	Proof     Claims  `json:"proof"`
}

type SignedClaims struct {
	Claims
	Signature string `json:"signature"`
}

type Object struct {
	Schema    string       `json:"schema"`
	RequestID string       `json:"request_id"`
	NodeID    string       `json:"node_id"`
	Catalog   Catalog      `json:"catalog"`
	Pricing   Pricing      `json:"pricing"`
	Timing    Timing       `json:"timing"`
	Proof     SignedClaims `json:"proof"`
}

func PayloadFor(input Input) Payload {
	return payloadForHashes(
		input.Metadata,
		sha256Hex(input.RequestBody),
		sha256Hex(input.ResponseBody),
	)
}

func ObjectFor(payload Payload, signature string) Object {
	return Object{
		Schema:    payload.Schema,
		RequestID: payload.RequestID,
		NodeID:    payload.NodeID,
		Catalog:   payload.Catalog,
		Pricing:   payload.Pricing,
		Timing:    payload.Timing,
		Proof: SignedClaims{
			Claims:    payload.Proof,
			Signature: signature,
		},
	}
}

func PayloadFromObject(object Object) Payload {
	return Payload{
		Schema:    object.Schema,
		RequestID: object.RequestID,
		NodeID:    object.NodeID,
		Catalog:   object.Catalog,
		Pricing:   object.Pricing,
		Timing:    object.Timing,
		Proof:     object.Proof.Claims,
	}
}

func ValidCatalogNodeIDs(nodeIDs []string) bool {
	if len(nodeIDs) != len(catalogNodeKinds) {
		return false
	}
	for index, value := range nodeIDs {
		id, ok := strings.CutPrefix(value, catalogNodeKinds[index]+":")
		if !ok || !validIdentifier(id, 128) {
			return false
		}
	}
	return true
}

func ValidMetadata(metadata Metadata) bool {
	if metadata.RequestID == "" || len(metadata.RequestID) > 128 ||
		!isLowerHex(metadata.NodeID, 32) ||
		!validCatalogDigest(metadata.Catalog.Digest) ||
		!ValidCatalogNodeIDs(metadata.Catalog.NodeIDs) ||
		!validPricing(metadata.Pricing) ||
		metadata.Timing.ProviderMS > metadata.Timing.TotalMS ||
		(metadata.Timing.TimeToFirstOutputMS != nil && *metadata.Timing.TimeToFirstOutputMS > metadata.Timing.ProviderMS) ||
		(metadata.E2EETranscriptSHA256 != "" && !isLowerHex(metadata.E2EETranscriptSHA256, 32)) {
		return false
	}
	return true
}

type StreamHasher struct {
	base StreamingInput
	hash hash.Hash
}

func NewStreamHasher(input StreamingInput) *StreamHasher {
	return &StreamHasher{base: input, hash: sha256.New()}
}

func (h *StreamHasher) WriteChunk(chunk []byte) {
	if h == nil || h.hash == nil {
		return
	}
	_, _ = h.hash.Write(chunk)
}

func (h *StreamHasher) SetMetadata(metadata Metadata) {
	if h == nil {
		return
	}
	h.base.Metadata = cloneMetadata(metadata)
}

func (h *StreamHasher) FinalPayload() Payload {
	if h == nil || h.hash == nil {
		return Payload{}
	}
	return payloadForHashes(
		h.base.Metadata,
		sha256Hex(h.base.RequestBody),
		hex.EncodeToString(h.hash.Sum(nil)),
	)
}

func Sign(privateKey ed25519.PrivateKey, payload Payload) (string, error) {
	message, err := signingMessage(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message)), nil
}

func Verify(publicKey ed25519.PublicKey, payload Payload, signatureBase64URL string) bool {
	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64URL)
	if err != nil {
		return false
	}
	message, err := signingMessage(payload)
	return err == nil && ed25519.Verify(publicKey, message, signature)
}

func VerifyInput(publicKey ed25519.PublicKey, input Input, signatureBase64URL string) bool {
	return Verify(publicKey, PayloadFor(input), signatureBase64URL)
}

func VerifyStreamingInput(
	publicKey ed25519.PublicKey,
	input StreamingInput,
	chunks [][]byte,
	signatureBase64URL string,
) bool {
	hasher := NewStreamHasher(input)
	for _, chunk := range chunks {
		hasher.WriteChunk(chunk)
	}
	return Verify(publicKey, hasher.FinalPayload(), signatureBase64URL)
}

func payloadForHashes(metadata Metadata, requestSHA256 string, responseSHA256 string) Payload {
	metadata = cloneMetadata(metadata)
	return Payload{
		Schema:    DomainV5,
		RequestID: metadata.RequestID,
		NodeID:    metadata.NodeID,
		Catalog:   metadata.Catalog,
		Pricing:   metadata.Pricing,
		Timing:    metadata.Timing,
		Proof: Claims{
			RequestSHA256:        requestSHA256,
			ResponseSHA256:       responseSHA256,
			E2EETranscriptSHA256: metadata.E2EETranscriptSHA256,
		},
	}
}

func cloneMetadata(metadata Metadata) Metadata {
	metadata.Catalog.NodeIDs = append([]string(nil), metadata.Catalog.NodeIDs...)
	meters := make(map[string]Meter, len(metadata.Pricing.Meters))
	for key, meter := range metadata.Pricing.Meters {
		meters[key] = meter
	}
	metadata.Pricing.Meters = meters
	if metadata.Timing.TimeToFirstOutputMS != nil {
		value := *metadata.Timing.TimeToFirstOutputMS
		metadata.Timing.TimeToFirstOutputMS = &value
	}
	return metadata
}

func validPricing(pricing Pricing) bool {
	if len(pricing.Meters) > 64 || !isDecimal(pricing.TotalCostUSDAtoms) ||
		(pricing.BYOKCostUSDAtoms != "" && !isDecimal(pricing.BYOKCostUSDAtoms)) {
		return false
	}
	for key, meter := range pricing.Meters {
		if !validIdentifier(key, 128) || !validIdentifier(meter.RateKey, 128) ||
			!isDecimal(meter.Quantity) || !isDecimal(meter.RateUSDAtoms) || !isDecimal(meter.USDAtoms) {
			return false
		}
	}
	return true
}

func validCatalogDigest(value string) bool {
	digest, ok := strings.CutPrefix(value, "sha256:")
	return ok && isLowerHex(digest, 32)
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
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
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

func signingMessage(payload Payload) ([]byte, error) {
	bytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(DomainV5)+1+len(bytes))
	message = append(message, DomainV5...)
	message = append(message, 0)
	return append(message, bytes...), nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
