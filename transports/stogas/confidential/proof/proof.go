package proof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"hash"
)

const DomainV1 = "stogas.processed-proof.v1"

type Input struct {
	ProcessedRequestJSON []byte
	ResponseJSON         []byte
	CatalogNodeIDs       []string
}

type StreamingInput struct {
	ProcessedRequestJSON []byte
	CatalogNodeIDs       []string
}

type Payload struct {
	Domain         string   `json:"domain"`
	RequestSHA256  string   `json:"request_sha256"`
	ResponseSHA256 string   `json:"response_sha256"`
	CatalogNodeIDs []string `json:"catalog_node_ids"`
	Streaming      bool     `json:"streaming"`
}

func Hash(input Input) (string, error) {
	payload := Payload{
		Domain:         DomainV1,
		RequestSHA256:  sha256Hex(input.ProcessedRequestJSON),
		ResponseSHA256: sha256Hex(input.ResponseJSON),
		CatalogNodeIDs: append([]string(nil), input.CatalogNodeIDs...),
		Streaming:      false,
	}
	return hashPayload(payload)
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
	if h == nil || h.hash == nil {
		return "", nil
	}
	payload := Payload{
		Domain:         DomainV1,
		RequestSHA256:  sha256Hex(h.base.ProcessedRequestJSON),
		ResponseSHA256: hex.EncodeToString(h.hash.Sum(nil)),
		CatalogNodeIDs: append([]string(nil), h.base.CatalogNodeIDs...),
		Streaming:      true,
	}
	return hashPayload(payload)
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

func hashPayload(payload Payload) (string, error) {
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
