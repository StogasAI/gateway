package proof

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const ReceiptSchema = "stogas.receipt.v1"

// Receipt authenticates content and the surrounding metadata with one signature.
// BootSHA256 resolves the hardware-bound signer.
type Receipt struct {
	Schema         string `json:"schema"`
	BootSHA256     string `json:"boot_sha256"`
	RequestSHA256  string `json:"request_sha256"`
	ResponseSHA256 string `json:"response_sha256"`
	Signature      string `json:"signature"`
}

// SignReceipt consumes final exact-content digests. Streaming callers omit
// transport keepalives and the metadata container from the response digest.
func SignReceipt(key *mldsa.PrivateKey, boot, request, response [32]byte, metadata any) (Receipt, error) {
	if key == nil || key.PublicKey().Parameters() != mldsa.MLDSA65() {
		return Receipt{}, errors.New("receipt requires an ML-DSA-65 signing key")
	}
	digest, err := metadataDigest(metadata)
	if err != nil {
		return Receipt{}, err
	}
	message := receiptMessage(request, response, digest)
	signature, err := key.Sign(nil, message, &mldsa.Options{})
	if err != nil {
		return Receipt{}, errors.New("receipt signing failed")
	}
	return Receipt{
		Schema: ReceiptSchema, BootSHA256: hex.EncodeToString(boot[:]),
		RequestSHA256: hex.EncodeToString(request[:]), ResponseSHA256: hex.EncodeToString(response[:]),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

// VerifyReceipt requires the public key resolved from this exact verified boot,
// not a public key supplied alongside the receipt by an untrusted response.
func VerifyReceipt(key *mldsa.PublicKey, receipt Receipt, boot, request, response [32]byte, metadata any) bool {
	if key == nil || key.Parameters() != mldsa.MLDSA65() || receipt.Schema != ReceiptSchema ||
		receipt.BootSHA256 != hex.EncodeToString(boot[:]) ||
		receipt.RequestSHA256 != hex.EncodeToString(request[:]) ||
		receipt.ResponseSHA256 != hex.EncodeToString(response[:]) {
		return false
	}
	digest, err := metadataDigest(metadata)
	if err != nil {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	return err == nil && base64.RawURLEncoding.EncodeToString(signature) == receipt.Signature &&
		mldsa.Verify(key, receiptMessage(request, response, digest), signature, nil) == nil
}

func receiptMessage(request, response, metadata [32]byte) []byte {
	message := make([]byte, 0, len(ReceiptSchema)+1+96)
	message = append(message, ReceiptSchema...)
	message = append(message, 0)
	message = append(message, request[:]...)
	message = append(message, response[:]...)
	return append(message, metadata[:]...)
}

// RFC 8785 canonicalizes the entire bag, excluding only its top-level receipt.
func metadataDigest(metadata any) ([32]byte, error) {
	encoded, err := json.Marshal(metadata)
	if err != nil || len(encoded) > MaxObjectBytes {
		return [32]byte{}, errors.New("invalid receipt metadata")
	}
	// Validate duplicate names before decoding into a map.
	if _, err = jsoncanonicalizer.Transform(encoded); err != nil {
		return [32]byte{}, err
	}
	var object map[string]json.RawMessage
	if err = json.Unmarshal(encoded, &object); err != nil || object == nil {
		return [32]byte{}, errors.New("receipt metadata must be an object")
	}
	delete(object, "receipt")
	encoded, err = json.Marshal(object)
	if err != nil {
		return [32]byte{}, err
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}
