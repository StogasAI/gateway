package attest

import verifier "github.com/StogasAI/verifier/go"

// Leave space for the ML-DSA-65 key, certificate signature and TLS framing.
const MaxSessionEvidenceBytes = 58 * 1024

// BootEvidence is the immutable boot object and its separate inclusion material.
// Startup must verify both before creating the public certificate issuer.
type BootEvidence struct {
	Document  []byte
	Inclusion []byte
}

// CheckSize confirms this boot fits beside the longest proof a full batch returns.
func (boot BootEvidence) CheckSize() error {
	_, proofs, err := verifier.QuoteBatch(make([][64]byte, MaxBatchLeaves))
	if err != nil {
		return err
	}
	_, err = verifier.SessionEvidence(make([]byte, snpReportSize), proofs[0], boot.Document, boot.Inclusion, false)
	return err
}

// Evidence encodes this quote's report, proof and boot for one channel. Certificate
// selects the native TLS extension value; encrypted setup carries the bare payload.
func (q *ChannelQuote) Evidence(boot BootEvidence, certificate bool) ([]byte, error) {
	return verifier.SessionEvidence(q.Report, q.Proof, boot.Document, boot.Inclusion, certificate)
}
