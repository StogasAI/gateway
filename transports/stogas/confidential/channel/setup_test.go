package channel

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	ref "github.com/StogasAI/verifier/go/reference"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
)

// This independent Go HPKE consumer pins the public setup contract.
const (
	setupInfoDomain    = "stogas.e2ee.setup.v1\x00"
	transcriptDomain   = "stogas.e2ee.transcript.v1\x00"
	rootDomain         = "stogas.e2ee.root.v1\x00"
	confirmationDomain = "stogas.e2ee.confirmation.v1\x00"
)

type setupReporter struct {
	calls atomic.Int64
	block <-chan struct{}
}

func (s *setupReporter) Quote(_ context.Context, data [64]byte) ([]byte, error) {
	s.calls.Add(1)
	if s.block != nil {
		<-s.block
	}
	report := make([]byte, 1184)
	binary.LittleEndian.PutUint32(report, 3)
	binary.LittleEndian.PutUint32(report[0x34:], 1)
	copy(report[0x50:0x90], data[:])
	return attest.EncodeEnvelope(attest.Envelope{Provider: attest.ProviderSEVGuest, Report: base64.RawURLEncoding.EncodeToString(report)})
}

type setupFixture struct {
	Seed     string `json:"seed_hex"`
	Hello    string `json:"hello_hex"`
	Response string `json:"response_hex"`
	Root     string `json:"root_hex"`
}

func setupVector(t *testing.T) (setupFixture, []byte) {
	t.Helper()
	var vector setupFixture
	encoded, err := os.ReadFile("testdata/setup.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	hello, err := hex.DecodeString(vector.Hello)
	if err != nil {
		t.Fatal(err)
	}
	return vector, hello
}

func newSetup(t *testing.T, reporter *setupReporter) *ServerSetup {
	t.Helper()
	batcher, err := attest.NewBatcher(reporter, func() (func(), bool) { return func() {}, true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := batcher.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	setup, err := NewServerSetup(attest.Production, attest.BootEvidence{Document: []byte(`{"fixture":"synthetic boot record"}`), Inclusion: []byte(`{"fixture":"synthetic inclusion"}`)}, 600*time.Second, batcher)
	if err != nil {
		t.Fatal(err)
	}
	return setup
}

func setupRecipient(t *testing.T, seed, hello, response, boot []byte) (*hpke.Recipient, [32]byte) {
	t.Helper()
	key, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	infoHash := sha256.Sum256(hello)
	info := append([]byte(setupInfoDomain), infoHash[:]...)
	recipient, err := hpke.NewRecipient(response[42:serverSetupPrefixBytes-referencePublicBytes], key, hpke.HKDFSHA256(), hpke.ExportOnly(), info)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	hash.Write([]byte(transcriptDomain))
	hash.Write(hello)
	hash.Write(response[:serverSetupPrefixBytes])
	bootHash := sha256.Sum256(boot)
	hash.Write(bootHash[:])
	return recipient, [32]byte(hash.Sum(nil))
}

func TestSetupEstablishesReusableUniqueSession(t *testing.T) {
	vector, hello := setupVector(t)
	seed, _ := hex.DecodeString(vector.Seed)
	reporter := &setupReporter{}
	setup := newSetup(t, reporter)
	var lastID [32]byte
	for range 2 {
		session, response, err := setup.Accept(context.Background(), hello)
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if session.ID() == lastID || len(response) > MaxServerSetupBytes {
			t.Fatal("reused identity or oversized setup")
		}
		lastID = session.ID()
		if !bytes.Equal(response[:6], []byte(setupResponseHeader)) || binary.BigEndian.Uint32(response[38:42]) != 600 {
			t.Fatal("wrong setup metadata")
		}
		recipient, transcript := setupRecipient(t, seed, hello, response, setup.boot.Document)
		confirmation, err := recipient.Export(confirmationDomain+string(transcript[:]), 32)
		if err != nil || !bytes.Equal(confirmation, response[serverSetupPrefixBytes:serverSetupPrefixBytes+32]) {
			t.Fatalf("possession confirmation: %v", err)
		}
		root, err := recipient.Export(rootDomain+string(transcript[:]), 32)
		if err != nil {
			t.Fatal(err)
		}
		// The quoted evidence must commit this exact transcript and boot.
		evidence, err := ref.ParseSessionEvidence(response[serverSetupPrefixBytes+32+4:])
		if err != nil || !bytes.Equal(evidence.Document, setup.boot.Document) {
			t.Fatal("setup evidence differs", err)
		}
		leaf := ref.E2EELeaf(byte(attest.Production), sha256.Sum256(setup.boot.Document), transcript)
		if err := ref.VerifyBatchProof(leaf, evidence.Proof, [64]byte(evidence.Report[0x50:0x90])); err != nil {
			t.Fatal(err)
		}
		for _, number := range []uint64{0, 2, 1} {
			encoder := newRecords(requestMessageFor([32]byte(root), number, [referencePublicBytes]byte(response[serverSetupPrefixBytes-referencePublicBytes:serverSetupPrefixBytes])), session.ID(), number, requestDirection)
			request, metadata, err := session.AcceptStart(number, sealRecord(t, encoder, Metadata, []byte("credentials")))
			if err != nil || string(metadata) != "credentials" {
				t.Fatalf("request establishment: %v", err)
			}
			request.Close()
		}
	}
	if reporter.calls.Load() != 2 {
		t.Fatalf("quotes generated for requests: %d", reporter.calls.Load())
	}
}

func TestRequestPrefixBindsFullIdentityAndNumber(t *testing.T) {
	id := [32]byte{1, 2, 3}
	prefix := append([]byte(requestHeader), id[:]...)
	prefix = binary.BigEndian.AppendUint64(prefix, 0x1000000000000042)
	actual, number, err := ParseRequestPrefix(prefix)
	if err != nil || actual != id || number != 0x1000000000000042 {
		t.Fatalf("prefix identity/number: %v", err)
	}
	for index := range len(requestHeader) {
		changed := slices.Clone(prefix)
		changed[index] ^= 1
		if _, _, err := ParseRequestPrefix(changed); err == nil {
			t.Fatal("accepted another operation/profile")
		}
	}
	for _, invalid := range [][]byte{nil, prefix[:len(prefix)-1], append(slices.Clone(prefix), 0)} {
		if _, _, err := ParseRequestPrefix(invalid); err == nil {
			t.Fatal("accepted malformed prefix")
		}
	}
}

func TestSetupRejectsInvalidHelloBeforeQuote(t *testing.T) {
	_, hello := setupVector(t)
	reporter := &setupReporter{}
	setup := newSetup(t, reporter)
	for _, index := range []int{0, 4, 5, 6, ClientSetupBytes - 32} {
		changed := slices.Clone(hello)
		if index == ClientSetupBytes-32 {
			clear(changed[index:])
		} else {
			changed[index] ^= 1
		}
		if session, _, err := setup.Accept(context.Background(), changed); err == nil || session != nil {
			t.Fatalf("accepted invalid hello %d", index)
		}
	}
	for _, malformed := range [][]byte{nil, hello[:len(hello)-1], append(slices.Clone(hello), 0)} {
		if session, _, err := setup.Accept(context.Background(), malformed); err == nil || session != nil {
			t.Fatal("accepted wrong hello size")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if session, _, err := setup.Accept(ctx, hello); !errors.Is(err, context.Canceled) || session != nil {
		t.Fatal("accepted canceled setup")
	}
	if reporter.calls.Load() != 0 {
		t.Fatal("invalid hello reached report hardware")
	}
}

func TestCanceledSetupNeverPublishesSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, hello := setupVector(t)
		block := make(chan struct{})
		reporter := &setupReporter{block: block}
		setup := newSetup(t, reporter)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			session, response, err := setup.Accept(ctx, hello)
			if session != nil || response != nil {
				result <- errors.New("canceled setup published state")
			} else {
				result <- err
			}
		}()
		synctest.Wait()
		if reporter.calls.Load() != 1 {
			t.Fatal("report did not start")
		}
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		close(block)
	})
}
