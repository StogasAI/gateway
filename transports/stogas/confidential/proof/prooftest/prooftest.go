// Package prooftest checks receipts for the gateway's tests apart from the Rust signer: RFC 8785
// through another implementation, then each side's salted commitment and the signed message.
package prooftest

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/StogasAI/stogas/go/reference"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
)

// VerifyReceipt reports whether the receipt in object binds the request and the response, each
// one JSON object as it was sent, to the node whose boot document hashes to boot.
func VerifyReceipt(public []byte, object proof.Object, boot [32]byte, request, response []byte) bool {
	requestDigest, responseDigest := Digest(request, "encryption_keys"), Digest(response, "stogas")
	return requestDigest != nil && responseDigest != nil && VerifyDigests(public, object, boot, requestDigest, responseDigest)
}

// Digest is the SHA-512 of a JSON object's RFC 8785 form without its excluded top-level
// members, or nil when the content is not one JSON object.
func Digest(content []byte, excluded ...string) *[64]byte {
	var fields map[string]json.RawMessage
	if json.Unmarshal(content, &fields) != nil || fields == nil {
		return nil
	}
	for _, name := range excluded {
		delete(fields, name)
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil {
		return nil
	}
	digest := sha512.Sum512(canonical)
	return &digest
}

// VerifyDigests is VerifyReceipt for content that is already digested, such as a stream's
// assembled response.
func VerifyDigests(public []byte, object proof.Object, boot [32]byte, request, response *[64]byte) bool {
	receipt := object.Receipt
	if object.Salts == nil || receipt.Schema != "stogas.receipt.v2" || receipt.BootSHA256 != hex.EncodeToString(boot[:]) {
		return false
	}
	requestCommitment := commitment("request", object.Salts.Request, request)
	responseCommitment := commitment("response", object.Salts.Response, response)
	if requestCommitment == nil || responseCommitment == nil ||
		receipt.RequestCommitment != hex.EncodeToString(requestCommitment) || receipt.ResponseCommitment != hex.EncodeToString(responseCommitment) {
		return false
	}
	encoded, err := json.Marshal(object)
	var bag map[string]json.RawMessage
	if err != nil || json.Unmarshal(encoded, &bag) != nil {
		return false
	}
	delete(bag, "receipt")
	delete(bag, "salts")
	if encoded, err = json.Marshal(bag); err != nil {
		return false
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil || signatureErr != nil {
		return false
	}
	digest := sha256.Sum256(canonical)
	message := bytes.Join([][]byte{[]byte("stogas.receipt.v2\x00"), requestCommitment, responseCommitment, digest[:]}, nil)
	return reference.VerifySignature(public, message, signature) == nil
}

func commitment(side, salt string, digest *[64]byte) []byte {
	value, err := hex.DecodeString(salt)
	if err != nil || len(value) != 32 || salt != hex.EncodeToString(value) {
		return nil
	}
	sum := sha256.Sum256(bytes.Join([][]byte{[]byte("stogas.receipt.v2.commitment\x00" + side + "\x00"), value, digest[:]}, nil))
	return sum[:]
}
