package channel

// Independent Go first-turn peer for the Rust embedding boundary.
// The verifier's own conformance suite covers later alternating turns.
import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	verifier "github.com/StogasAI/verifier/go"
	ref "github.com/StogasAI/verifier/go/reference"
	"testing"
)

type direction byte

const (
	requestDirection  direction = 1
	responseDirection direction = 2
)
const referencePublicBytes = ref.PublicBytes

type referenceMessage struct {
	secret [32]byte
	header []byte
}
type referenceChainState = ref.Peer

func referenceChainFor(root [32]byte, public [referencePublicBytes]byte) referenceChainState {
	return *ref.New(root[:], &ref.Keys{Public: public}, true)
}
func referenceChain(client *ref.Session) referenceChainState {
	return referenceChainFor(client.Root, client.Initial)
}
func referenceStep(chain *referenceChainState, number uint64) (referenceMessage, referenceChainState) {
	if number != chain.Sent+1 {
		panic("unordered reference send")
	}
	next := *chain
	message := next.Send(number-1, bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32))
	return referenceMessage{[32]byte(message.Secret), message.Header}, next
}
func requestMessageFor(root [32]byte, number uint64, public [referencePublicBytes]byte) referenceMessage {
	chain := referenceChainFor(root, public)
	var message referenceMessage
	for i := uint64(0); i <= number; i++ {
		message, chain = referenceStep(&chain, i+1)
	}
	return message
}
func requestMessage(client *ref.Session, number uint64) referenceMessage {
	return requestMessageFor(client.Root, number, client.Initial)
}

// The first send fixes the client's turn keys; the response nonce is its request number.
func referenceResponseSecret(root [32]byte, public [referencePublicBytes]byte, header []byte, number uint64) [32]byte {
	chain := referenceChainFor(root, public)
	_, chain = referenceStep(&chain, 1)
	return [32]byte(chain.Receive(ref.Message{Header: header, Request: number}))
}

// testServerSession establishes a session through the production setup entry
// point. The independent Go client derives the root that the Rust core keeps.
func testServerSession(t testing.TB) (*ServerSession, *ref.Session) {
	t.Helper()
	client, err := ref.NewSetup(1, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bootHash := sha256.Sum256([]byte("gateway channel test"))
	prepared, err := verifier.PrepareChannelSetup(1, 600, bootHash, client.Hello)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := client.Complete(prepared.ResponsePrefix, bootHash)
	if err != nil {
		prepared.Session.Close()
		t.Fatal(err)
	}
	return &ServerSession{core: prepared.Session, id: prepared.ID}, setup
}

type records struct {
	keys          *ref.RecordKeys
	sequence      uint64
	header        []byte
	root          *[32]byte
	initialPublic [referencePublicBytes]byte
	id            [32]byte
	number        uint64
	direction     direction
	finished      bool
}

func (r *records) install(secret [32]byte) {
	r.keys = ref.NewRecordKeys(secret[:], r.id[:], r.number, byte(r.direction))
}
func newRecords(message referenceMessage, id [32]byte, number uint64, direction direction) *records {
	r := &records{id: id, number: number, direction: direction, header: message.header}
	r.install(message.secret)
	return r
}
func responseRecords(client *ref.Session, number uint64) *records {
	return responseRecordsFor(client.Root, client.ID, client.Initial, number)
}
func responseRecordsFor(root, id [32]byte, initialPublic [referencePublicBytes]byte, number uint64) *records {
	r := newRecords(referenceMessage{}, id, number, responseDirection)
	r.root, r.initialPublic = &root, initialPublic
	return r
}
func (r *records) seal(kind Kind, content []byte) ([]byte, error) {
	prefix := make([]byte, 4)
	if r.sequence == 0 {
		prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(r.header)))
		prefix = append(prefix, r.header...)
	}
	binary.BigEndian.PutUint32(prefix, uint32(len(prefix)+1+len(content)+16))
	aead, nonce := r.keys.Next()
	result := aead.Seal(prefix, nonce[:], append([]byte{byte(kind)}, content...), prefix)
	r.sequence++
	return result, nil
}
func (r *records) open(encoded []byte) (Kind, []byte, error) {
	if len(encoded) < 21 {
		return 0, nil, ErrRecord
	}
	offset := 4
	if r.sequence == 0 {
		if len(encoded) < 6+ref.HeaderBytes+17 {
			return 0, nil, ErrRecord
		}
		offset = 6 + int(binary.BigEndian.Uint16(encoded[4:6]))
		if offset+17 > len(encoded) {
			return 0, nil, ErrRecord
		}
		if r.root != nil {
			r.install(referenceResponseSecret(*r.root, r.initialPublic, encoded[6:offset], r.number))
			r.root = nil
		}
	}
	aead, nonce := r.keys.Next()
	plain, err := aead.Open(nil, nonce[:], encoded[offset:], encoded[:offset])
	if err != nil {
		return 0, nil, ErrAuthentication
	}
	r.sequence++
	kind := Kind(plain[0])
	r.finished = kind == Finished
	return kind, plain[1:], nil
}
func (r *records) complete() error {
	if !r.finished {
		return ErrTruncated
	}
	return nil
}
func (r *records) fail(err error) error { r.keys = nil; return err }
func sealRecord(t testing.TB, encoder *records, kind Kind, data []byte) []byte {
	t.Helper()
	encoded, err := encoder.seal(kind, data)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
