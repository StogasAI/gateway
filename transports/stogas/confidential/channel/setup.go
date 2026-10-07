package channel

import (
	"context"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
)

const (
	// ClientSetupHeader pins setup dispatch and its complete cryptographic profile.
	ClientSetupHeader      = "STGS\x01\x01"
	setupResponseHeader    = "STGS\x01\x02"
	ClientSetupBytes       = len(ClientSetupHeader) + 1 + 32 + 1216
	serverSetupPrefixBytes = len(setupResponseHeader) + 32 + 4 + 1120 + verifier.ChannelPublicKeyBytes
	MaxServerSetupBytes    = serverSetupPrefixBytes + 32 + 4 + attest.MaxSessionEvidenceBytes
	setupInfoDomain        = "stogas.e2ee.setup.v1\x00"
	transcriptDomain       = "stogas.e2ee.transcript.v1\x00"
	rootDomain             = "stogas.e2ee.root.v1\x00"
	confirmationDomain     = "stogas.e2ee.confirmation.v1\x00"
)

// ServerSetup retains verified immutable boot evidence, not session secrets.
// Aggregate setup memory and deadline admission surround Accept at the listener.
type ServerSetup struct {
	environment attest.Environment
	boot        attest.BootEvidence
	bootHash    [32]byte
	idleSeconds uint32
	batcher     *attest.Batcher
}

func NewServerSetup(environment attest.Environment, boot attest.BootEvidence, idle time.Duration, batcher *attest.Batcher) (*ServerSetup, error) {
	if environment != attest.Production && environment != attest.Staging || batcher == nil || idle < time.Second || idle%time.Second != 0 || idle/time.Second > math.MaxUint32 {
		return nil, errors.New("invalid encrypted session setup configuration")
	}
	// A busy batch must fit the same evidence bound as native certificates.
	_, err := (attest.SessionEvidence{Report: make([]byte, 1184), Proof: attest.BatchProof{LeafCount: attest.MaxBatchLeaves, Siblings: make([][64]byte, attest.MaxProofHashes)}, Boot: boot}).MarshalBinary()
	if err != nil {
		return nil, err
	}
	boot = attest.BootEvidence{Document: slices.Clone(boot.Document), Inclusion: slices.Clone(boot.Inclusion)}
	return &ServerSetup{environment: environment, boot: boot, bootHash: sha256.Sum256(boot.Document), idleSeconds: uint32(idle / time.Second), batcher: batcher}, nil
}

// Accept creates the exchange locally, then quotes that exact exchange through
// the typed batcher. A caller must publish the returned session before sending
// its response and remove/close it if response publication fails. The client
// verifies evidence and possession confirmation before sending credentials.
func (s *ServerSetup) Accept(ctx context.Context, hello []byte) (*ServerSession, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if len(hello) != ClientSetupBytes || string(hello[:len(ClientSetupHeader)]) != ClientSetupHeader || hello[len(ClientSetupHeader)] != byte(s.environment) {
		return nil, nil, ErrRecord
	}
	key, err := hpke.MLKEM768X25519().NewPublicKey(hello[len(ClientSetupHeader)+1+32:])
	if err != nil {
		return nil, nil, ErrRecord
	}
	// HPKE info uses only the client hello to avoid a circular dependency on enc.
	// Both exports and attestation bind the complete server response prefix too.
	infoHash := sha256.Sum256(hello)
	info := append([]byte(setupInfoDomain), infoHash[:]...)
	enc, sender, err := hpke.NewSender(key, hpke.HKDFSHA256(), hpke.ExportOnly(), info)
	if err != nil {
		return nil, nil, err
	}
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, nil, err
	}
	initialPrivate, initialPublic, err := verifier.GenerateChannelKey()
	if err != nil {
		return nil, nil, err
	}
	defer clear(initialPrivate[:])
	prefix := make([]byte, 0, serverSetupPrefixBytes)
	prefix = append(prefix, setupResponseHeader...)
	prefix = append(prefix, id[:]...)
	prefix = binary.BigEndian.AppendUint32(prefix, s.idleSeconds)
	prefix = append(prefix, enc...)
	prefix = append(prefix, initialPublic[:]...)
	transcript := sha256.New()
	transcript.Write([]byte(transcriptDomain))
	transcript.Write(hello)
	transcript.Write(prefix)
	transcript.Write(s.bootHash[:])
	transcriptHash := [32]byte(transcript.Sum(nil))
	root, err := sender.Export(rootDomain+string(transcriptHash[:]), 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(root)
	confirmation, err := sender.Export(confirmationDomain+string(transcriptHash[:]), 32)
	if err != nil {
		return nil, nil, err
	}
	quote, err := s.batcher.Quote(ctx, attest.E2EESessionBinding{Environment: s.environment, BootEvidenceSHA256: s.bootHash, TranscriptSHA256: transcriptHash})
	if err != nil {
		return nil, nil, err
	}
	defer quote.Close()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	evidence, err := (attest.SessionEvidence{Report: quote.Report, Proof: quote.Proof, Boot: s.boot}).MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	response := make([]byte, 0, len(prefix)+32+4+len(evidence))
	response = append(response, prefix...)
	response = append(response, confirmation...)
	response = binary.BigEndian.AppendUint32(response, uint32(len(evidence)))
	response = append(response, evidence...)
	session, err := newServerSession([32]byte(root), id, initialPrivate)
	if err != nil {
		return nil, nil, err
	}
	return session, response, nil
}

func (s *ServerSession) ID() [32]byte { return s.id }
