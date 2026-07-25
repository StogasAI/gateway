package proof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"hash"
)

const DomainV1 = "stogas.response-proof.v1"

type Input struct {
	RequestID             string
	RequestPath           string
	RequestBody           []byte
	ResponseBody          []byte
	CatalogNodeIDs        []string
	DrandRound            uint64
	E2EETranscriptSHA256 string
}

type StreamingInput struct {
	RequestID             string
	RequestPath           string
	RequestBody           []byte
	CatalogNodeIDs        []string
	DrandRound            uint64
	E2EETranscriptSHA256 string
}

type Payload struct {
	Schema                string   `json:"schema"`
	RequestID             string   `json:"request_id"`
	RequestPath           string   `json:"request_path"`
	RequestSHA256         string   `json:"request_sha256"`
	ResponseSHA256        string   `json:"response_sha256"`
	CatalogNodeIDs        []string `json:"catalog_node_ids"`
	DrandRound            uint64   `json:"drand_round"`
	Streaming             bool     `json:"streaming"`
	E2EETranscriptSHA256 string   `json:"e2ee_transcript_sha256,omitempty"`
}

func Hash(input Input) (string, error) {
	payload := PayloadFor(input)
	return HashPayload(payload)
}

func PayloadFor(input Input) Payload {
	return Payload{
		Schema:                DomainV1,
		RequestID:             input.RequestID,
		RequestPath:           input.RequestPath,
		RequestSHA256:         sha256Hex(input.RequestBody),
		ResponseSHA256:        sha256Hex(input.ResponseBody),
		CatalogNodeIDs:        append([]string(nil), input.CatalogNodeIDs...),
		DrandRound:            input.DrandRound,
		Streaming:             false,
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

func (h *StreamHasher) FinalHash() (string, error) {
	payload, err := h.FinalPayload()
	if err != nil {
		return "", err
	}
	return HashPayload(payload)
}

func (h *StreamHasher) FinalPayload() (Payload, error) {
	if h == nil || h.hash == nil {
		return Payload{}, nil
	}
	payload := Payload{
		Schema:                DomainV1,
		RequestID:             h.base.RequestID,
		RequestPath:           h.base.RequestPath,
		RequestSHA256:         sha256Hex(h.base.RequestBody),
		ResponseSHA256:        hex.EncodeToString(h.hash.Sum(nil)),
		CatalogNodeIDs:        append([]string(nil), h.base.CatalogNodeIDs...),
		DrandRound:            h.base.DrandRound,
		Streaming:             true,
		E2EETranscriptSHA256: h.base.E2EETranscriptSHA256,
	}
	return payload, nil
}

func Sign(privateKey ed25519.PrivateKey, processedHashHex string) string {
	signature := ed25519.Sign(privateKey, []byte(DomainV1+"\x00"+processedHashHex))
	return base64.RawURLEncoding.EncodeToString(signature)
}

func Verify(publicKey ed25519.PublicKey, processedHashHex string, signatureBase64URL string) bool {
	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64URL)
	if err != nil {
		return false
	}
	return ed25519.Verify(publicKey, []byte(DomainV1+"\x00"+processedHashHex), signature)
}

func VerifyInput(publicKey ed25519.PublicKey, input Input, processedHashHex string, signatureBase64URL string) bool {
	expected, err := Hash(input)
	if err != nil || expected != processedHashHex {
		return false
	}
	return Verify(publicKey, processedHashHex, signatureBase64URL)
}

func VerifyStreamingInput(publicKey ed25519.PublicKey, input StreamingInput, chunks [][]byte, processedHashHex string, signatureBase64URL string) bool {
	hasher := NewStreamHasher(input)
	for _, chunk := range chunks {
		hasher.WriteChunk(chunk)
	}
	expected, err := hasher.FinalHash()
	if err != nil || expected != processedHashHex {
		return false
	}
	return Verify(publicKey, processedHashHex, signatureBase64URL)
}

func HashPayload(payload Payload) (string, error) {
	bytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return sha256Hex(bytes), nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
