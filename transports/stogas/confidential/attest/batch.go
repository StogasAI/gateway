package attest

import (
	"errors"

	verifier "github.com/StogasAI/verifier/go"
)

// MaxBatchLeaves bounds the channels committed by one hardware report.
const MaxBatchLeaves = verifier.MaxQuoteBatchLeaves

type Environment byte

const (
	Production Environment = 1
	Staging    Environment = 2
)

// Leaf commits one channel. Only this package's constructors create it, so
// neither network handlers nor the quote service accept arbitrary report data.
type Leaf struct{ hash [64]byte }

// NativeTLSLeaf binds the boot, the client's challenge and a fresh certificate key.
func NativeTLSLeaf(environment Environment, bootSHA256, challenge, signerSPKISHA256 [32]byte) (Leaf, error) {
	hash, err := verifier.TLSLeaf(byte(environment), bootSHA256, challenge, signerSPKISHA256)
	return Leaf{hash}, err
}

// E2EESessionLeaf binds the boot and the complete setup transcript: the client
// challenge, recipient key, session/node identity, suite and expiry hints.
func E2EESessionLeaf(environment Environment, bootSHA256, transcriptSHA256 [32]byte) (Leaf, error) {
	hash, err := verifier.E2EELeaf(byte(environment), bootSHA256, transcriptSHA256)
	return Leaf{hash}, err
}

var errAbsentLeaf = errors.New("attestation requires a channel leaf")
