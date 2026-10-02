package attest

import (
	"encoding/binary"
	"errors"
)

// Leave space for the ML-DSA-65 key, certificate signature and TLS framing.
const MaxSessionEvidenceBytes = 58 * 1024

// BootEvidence is the immutable boot object and its separate inclusion material.
// Startup must verify both before creating the public certificate issuer.
type BootEvidence struct {
	Document  []byte
	Inclusion []byte
}

// SessionEvidence is the payload shared by TLS certificates and E2EE setup.
// It contains raw bytes, not base64. Current approvals/collateral stay in the
// evidence bundle and are not copied into every certificate.
type SessionEvidence struct {
	Report []byte
	Proof  BatchProof
	Boot   BootEvidence
}

func (e SessionEvidence) MarshalBinary() ([]byte, error) {
	proof, err := e.Proof.MarshalBinary()
	if err != nil || len(e.Report) != snpReportSize || len(e.Boot.Document) == 0 || len(e.Boot.Inclusion) == 0 || len(e.Boot.Document) > MaxSessionEvidenceBytes || len(e.Boot.Inclusion) > MaxSessionEvidenceBytes {
		return nil, errors.New("invalid session evidence")
	}
	size := snpReportSize + 2 + len(proof) + 4 + len(e.Boot.Document) + 4 + len(e.Boot.Inclusion)
	if size > MaxSessionEvidenceBytes {
		return nil, errors.New("session evidence exceeds transport limit")
	}
	payload := make([]byte, 0, size)
	payload = append(payload, e.Report...)
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(proof)))
	payload = append(payload, proof...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(e.Boot.Document)))
	payload = append(payload, e.Boot.Document...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(e.Boot.Inclusion)))
	payload = append(payload, e.Boot.Inclusion...)
	return payload, nil
}
