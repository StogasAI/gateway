package channel

import (
	"context"
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
	if err := boot.CheckSize(); err != nil {
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
	prepared, err := verifier.PrepareChannelSetup(byte(s.environment), s.idleSeconds, s.bootHash, hello)
	if err != nil {
		return nil, nil, err
	}
	owned := true
	defer func() {
		if owned {
			prepared.Session.Close()
		}
	}()
	leaf, err := attest.E2EESessionLeaf(s.environment, s.bootHash, prepared.Transcript)
	if err != nil {
		return nil, nil, err
	}
	quote, err := s.batcher.Quote(ctx, leaf)
	if err != nil {
		return nil, nil, err
	}
	defer quote.Close()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	evidence, err := quote.Evidence(s.boot, false)
	if err != nil {
		return nil, nil, err
	}
	response := make([]byte, 0, len(prepared.ResponsePrefix)+4+len(evidence))
	response = append(response, prepared.ResponsePrefix...)
	response = binary.BigEndian.AppendUint32(response, uint32(len(evidence)))
	response = append(response, evidence...)
	owned = false
	return &ServerSession{core: prepared.Session, id: prepared.ID}, response, nil
}

func (s *ServerSession) ID() [32]byte { return s.id }
