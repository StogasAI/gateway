// Package batchtest checks signed request log batches for the gateway's tests apart from the
// Rust signer: RFC 8785 through another implementation, then each row's leaf, the RFC 9162 root
// over SHA-512 and the signed message.
package batchtest

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/StogasAI/stogas/go/reference"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Batch is one stored batch line.
type Batch struct {
	Schema     string `json:"schema"`
	NodeID     string `json:"node_id"`
	BootSHA256 string `json:"boot_sha256"`
	Sequence   uint32 `json:"sequence"`
	OpenedAt   string `json:"opened_at"`
	SealedAt   string `json:"sealed_at"`
	LeafCount  uint32 `json:"leaf_count"`
	Root       string `json:"root"`
	Signature  string `json:"signature"`
	Leaves     string `json:"leaves"`
}

// Leaf is a row's leaf: SHA-512 of a zero byte, the row domain and the row's RFC 8785 form.
func Leaf(row []byte) ([64]byte, error) {
	canonical, err := jsoncanonicalizer.Transform(row)
	if err != nil {
		return [64]byte{}, err
	}
	return sha512.Sum512(append([]byte("\x00stogas.log-row.v1\x00"), canonical...)), nil
}

// Root is the RFC 9162 tree hash of one or more leaves.
func Root(leaves [][64]byte) [64]byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	split := 1
	for split*2 < len(leaves) {
		split *= 2
	}
	left, right := Root(leaves[:split]), Root(leaves[split:])
	return sha512.Sum512(bytes.Join([][]byte{{1}, left[:], right[:]}, nil))
}

// Verify checks a stored batch line under the boot's composite public key, and that each row,
// as JSON, names this batch and hashes to the leaf at the index that it names.
func Verify(public []byte, boot [32]byte, line []byte, rows ...[]byte) (Batch, error) {
	var batch Batch
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		return batch, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(batch.Leaves)
	if err != nil || len(raw) == 0 || len(raw)%64 != 0 || len(raw)/64 != int(batch.LeafCount) {
		return batch, errors.New("the leaves do not match the leaf count")
	}
	leaves := make([][64]byte, batch.LeafCount)
	for i := range leaves {
		leaves[i] = [64]byte(raw[i*64:])
	}
	root := Root(leaves)
	opened, openedErr := time.Parse(time.RFC3339Nano, batch.OpenedAt)
	sealed, sealedErr := time.Parse(time.RFC3339Nano, batch.SealedAt)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(batch.Signature)
	switch {
	case batch.Schema != "stogas.log-batch.v1" || batch.BootSHA256 != hex.EncodeToString(boot[:]):
		return batch, errors.New("the batch names another schema or boot")
	case batch.Root != hex.EncodeToString(root[:]):
		return batch, errors.New("the root does not match the leaves")
	case openedErr != nil || sealedErr != nil || signatureErr != nil:
		return batch, errors.New("the batch is malformed")
	case opened.Format("2006-01-02T15:04:05.000Z") != batch.OpenedAt || sealed.Format("2006-01-02T15:04:05.000Z") != batch.SealedAt:
		return batch, errors.New("the batch times are not UTC milliseconds")
	}
	message := []byte("stogas.log-batch.v1\x00")
	message = append(message, boot[:]...)
	message = binary.BigEndian.AppendUint32(message, batch.Sequence)
	message = binary.BigEndian.AppendUint64(message, uint64(opened.UnixMilli()))
	message = binary.BigEndian.AppendUint64(message, uint64(sealed.UnixMilli()))
	message = binary.BigEndian.AppendUint32(message, batch.LeafCount)
	message = append(message, root[:]...)
	if err := reference.VerifySignature(public, message, signature); err != nil {
		return batch, fmt.Errorf("the batch signature fails: %w", err)
	}
	for _, row := range rows {
		var place struct {
			NodeID   string `json:"node_id"`
			LogBatch *struct {
				Sequence uint32 `json:"sequence"`
				Index    uint32 `json:"index"`
			} `json:"log_batch"`
		}
		if err := json.Unmarshal(row, &place); err != nil {
			return batch, err
		}
		if place.NodeID != batch.NodeID || place.LogBatch == nil || place.LogBatch.Sequence != batch.Sequence || place.LogBatch.Index >= batch.LeafCount {
			return batch, fmt.Errorf("the row does not name a place in this batch: %s", row)
		}
		leaf, err := Leaf(row)
		if err != nil {
			return batch, err
		}
		if leaf != leaves[place.LogBatch.Index] {
			return batch, fmt.Errorf("the row is not leaf %d: %s", place.LogBatch.Index, row)
		}
	}
	return batch, nil
}
