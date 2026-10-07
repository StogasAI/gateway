package channel

// Independent CIRCL/Go first-turn peer for the Rust embedding boundary.
// The verifier's own conformance suite covers later alternating turns.
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	ref "github.com/StogasAI/verifier/go/testutil/channeltest"
	"testing"
)

type direction byte

const (
	requestDirection  direction = 1
	responseDirection direction = 2
)
const referencePublicBytes = ref.PublicBytes

func referencePrivate(value byte) [32]byte                     { return [32]byte(bytes.Repeat([]byte{value}, 32)) }
func referencePublic(seed [32]byte) [referencePublicBytes]byte { return ref.KeyPair(seed[:]).Public }

type referenceMessage struct {
	secret [32]byte
	header []byte
}
type referenceChainState = ref.Peer

func referenceChainFor(root [32]byte, public [referencePublicBytes]byte) referenceChainState {
	return *ref.New(root[:], &ref.Keys{Public: public}, true)
}
func referenceChain(root [32]byte, direction direction) referenceChainState {
	if direction != requestDirection {
		panic("client sends requests only")
	}
	return referenceChainFor(root, referencePublic(referencePrivate(3)))
}
func referenceStep(chain *referenceChainState, number uint64) (referenceMessage, referenceChainState) {
	if number != chain.Sent+1 {
		panic("unordered reference send")
	}
	next := *chain
	seed, coins := referencePrivate(7), referencePrivate(9)
	message := next.Send(seed[:], coins[:])
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
func requestMessage(root [32]byte, number uint64) referenceMessage {
	return requestMessageFor(root, number, referencePublic(referencePrivate(3)))
}
func referenceResponseSecret(root [32]byte, public [referencePublicBytes]byte, header []byte) [32]byte {
	chain := referenceChainFor(root, public)
	_, chain = referenceStep(&chain, 1)
	return [32]byte(chain.Receive(ref.Message{Header: header}))
}
func testServerSession(root, id [32]byte) *ServerSession {
	session, err := newServerSession(root, id, referencePrivate(3))
	if err != nil {
		panic(err)
	}
	return session
}

type records struct {
	aead          cipher.AEAD
	nonce         [12]byte
	sequence      uint64
	header        []byte
	root          *[32]byte
	initialPublic [referencePublicBytes]byte
	id            [32]byte
	number        uint64
	direction     direction
	finished      bool
}

func (r *records) install(secret [32]byte) error {
	info := append([]byte("stogas.e2ee.record.v1\x00"), r.id[:]...)
	info = binary.BigEndian.AppendUint64(info, r.number)
	info = append(info, byte(r.direction))
	m, err := hkdf.Expand(sha256.New, secret[:], string(info), 44)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(m[:32])
	if err != nil {
		return err
	}
	r.aead, err = cipher.NewGCM(block)
	copy(r.nonce[:], m[32:])
	return err
}
func newRecords(message referenceMessage, id [32]byte, number uint64, direction direction) (*records, error) {
	r := &records{id: id, number: number, direction: direction, header: message.header}
	return r, r.install(message.secret)
}
func responseRecords(root, id [32]byte, number uint64) (*records, error) {
	return responseRecordsFor(root, id, referencePublic(referencePrivate(3)), number)
}
func responseRecordsFor(root, id [32]byte, initialPublic [referencePublicBytes]byte, number uint64) (*records, error) {
	r, err := newRecords(referenceMessage{}, id, number, responseDirection)
	r.root, r.initialPublic = &root, initialPublic
	return r, err
}
func (r *records) recordNonce() [12]byte {
	n := r.nonce
	for i, b := range binary.BigEndian.AppendUint64(nil, r.sequence) {
		n[4+i] ^= b
	}
	return n
}
func (r *records) seal(kind Kind, content []byte) ([]byte, error) {
	prefix := make([]byte, 4)
	if r.sequence == 0 {
		prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(r.header)))
		prefix = append(prefix, r.header...)
	}
	binary.BigEndian.PutUint32(prefix, uint32(len(prefix)+1+len(content)+16))
	nonce := r.recordNonce()
	result := r.aead.Seal(prefix, nonce[:], append([]byte{byte(kind)}, content...), prefix)
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
			if err := r.install(referenceResponseSecret(*r.root, r.initialPublic, encoded[6:offset])); err != nil {
				return 0, nil, err
			}
			r.root = nil
		}
	}
	nonce := r.recordNonce()
	plain, err := r.aead.Open(nil, nonce[:], encoded[offset:], encoded[:offset])
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
func (r *records) fail(err error) error { r.aead = nil; return err }
func sealRecord(t testing.TB, encoder *records, kind Kind, data []byte) []byte {
	t.Helper()
	encoded, err := encoder.seal(kind, data)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
