package proof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"hash"
)

const DomainV4 = "stogas.response-proof.v4"

type Input struct {
	RequestBody          []byte
	ResponseBody         []byte
	CatalogDigest        string
	CatalogNodeIDs       []string
	E2EETranscriptSHA256 string
}

type StreamingInput struct {
	RequestBody          []byte
	CatalogDigest        string
	CatalogNodeIDs       []string
	E2EETranscriptSHA256 string
}

type Payload struct {
	Schema               string   `json:"schema"`
	RequestSHA256        string   `json:"request_sha256"`
	ResponseSHA256       string   `json:"response_sha256"`
	CatalogDigest        string   `json:"catalog_digest"`
	CatalogNodeIDs       []string `json:"catalog_node_ids"`
	E2EETranscriptSHA256 string   `json:"e2ee_transcript_sha256,omitempty"`
}

func PayloadFor(input Input) Payload {
	return Payload{
		Schema:               DomainV4,
		RequestSHA256:        sha256Hex(input.RequestBody),
		ResponseSHA256:       sha256Hex(input.ResponseBody),
		CatalogDigest:        input.CatalogDigest,
		CatalogNodeIDs:       append([]string(nil), input.CatalogNodeIDs...),
		E2EETranscriptSHA256: input.E2EETranscriptSHA256,
	}
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

func (h *StreamHasher) FinalPayload() Payload {
	if h == nil || h.hash == nil {
		return Payload{}
	}
	return Payload{
		Schema:               DomainV4,
		RequestSHA256:        sha256Hex(h.base.RequestBody),
		ResponseSHA256:       hex.EncodeToString(h.hash.Sum(nil)),
		CatalogDigest:        h.base.CatalogDigest,
		CatalogNodeIDs:       append([]string(nil), h.base.CatalogNodeIDs...),
		E2EETranscriptSHA256: h.base.E2EETranscriptSHA256,
	}
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

func signingMessage(payload Payload) ([]byte, error) {
	bytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(DomainV4)+1+len(bytes))
	message = append(message, DomainV4...)
	message = append(message, 0)
	return append(message, bytes...), nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
