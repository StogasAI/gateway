package channel

// Independent Go test peer for epoch-zero carriage and store tests. It sends no
// ML-KEM updates. Full recovery, erasure, grammar and key ownership tests live
// with the Rust implementation; this peer tests the embedding boundary.
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

type direction byte

const (
	requestDirection  direction = 1
	responseDirection direction = 2
)
const referenceProtocol = "stogas.e2ee.spqr.v3_MLKEM768_HKDFSHA256"
const referenceTriple = "stogas.e2ee.triple.v3_X25519_MLKEM768_HKDFSHA256"
const referenceDouble = "stogas.e2ee.double.v3_X25519_HKDFSHA256:Root"

func referencePrivate(value byte) [32]byte {
	var key [32]byte
	for i := range key {
		key[i] = value
	}
	return key
}
func referencePublic(private [32]byte) [32]byte {
	key, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		panic(err)
	}
	return [32]byte(key.PublicKey().Bytes())
}
func referenceDH(public [32]byte) []byte {
	private := referencePrivate(7)
	key, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		panic(err)
	}
	peer, err := ecdh.X25519().NewPublicKey(public[:])
	if err != nil {
		panic(err)
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		panic(err)
	}
	return shared
}
func referenceHKDF(secret, salt []byte, info string, count int) []byte {
	material, err := hkdf.Key(sha256.New, secret, salt, info, count)
	if err != nil {
		panic(err)
	}
	return material
}
func referenceInitial(root, initialPublic [32]byte) (classicalRoot, classicalChain [32]byte, quantum []byte) {
	split := referenceHKDF(root[:], nil, referenceTriple+":Initialization", 64)
	classical := referenceHKDF(referenceDH(initialPublic), split[:32], referenceDouble, 64)
	return [32]byte(classical[:32]), [32]byte(classical[32:]), referenceHKDF(split[32:], nil, referenceProtocol+":Chain Start", 96)
}
func referenceClassicalStep(chain *[32]byte) [32]byte {
	mac := hmac.New(sha256.New, chain[:])
	mac.Write([]byte{1})
	message := [32]byte(mac.Sum(nil))
	mac.Reset()
	mac.Write([]byte{2})
	copy(chain[:], mac.Sum(nil))
	return message
}
func referenceQuantumStep(chain *[32]byte, number uint64) [32]byte {
	info := binary.BigEndian.AppendUint64([]byte(referenceProtocol+":Chain Step"), number)
	material := referenceHKDF(chain[:], nil, string(info), 64)
	copy(chain[:], material[:32])
	return [32]byte(material[32:])
}
func referenceCombine(classical, quantum [32]byte) [32]byte {
	return [32]byte(referenceHKDF(classical[:], quantum[:], referenceTriple, 32))
}

type referenceChainState struct{ classical, quantum [32]byte }

func referenceChainFor(root, initialPublic [32]byte) referenceChainState {
	_, classical, quantum := referenceInitial(root, initialPublic)
	return referenceChainState{classical: classical, quantum: [32]byte(quantum[32:64])}
}
func referenceChain(root [32]byte, direction direction) referenceChainState {
	if direction != requestDirection {
		panic("reference sending chain is client-only")
	}
	return referenceChainFor(root, referencePublic(referencePrivate(3)))
}
func referenceStep(chain *referenceChainState, number uint64) (message [32]byte, next referenceChainState) {
	next = *chain
	message = referenceCombine(referenceClassicalStep(&next.classical), referenceQuantumStep(&next.quantum, number))
	return
}
func requestSecretFor(root [32]byte, number uint64, initialPublic [32]byte) [32]byte {
	chain := referenceChainFor(root, initialPublic)
	var secret [32]byte
	for i := uint64(0); i <= number; i++ {
		secret, chain = referenceStep(&chain, i+1)
	}
	return secret
}
func requestSecret(root [32]byte, number uint64) [32]byte {
	return requestSecretFor(root, number, referencePublic(referencePrivate(3)))
}
func referenceResponseSecret(root, initialPublic [32]byte, header []byte) [32]byte {
	classicalRoot, _, quantum := referenceInitial(root, initialPublic)
	material := referenceHKDF(referenceDH([32]byte(header[:32])), classicalRoot[:], referenceDouble, 64)
	classicalChain := [32]byte(material[32:])
	quantumChain := [32]byte(quantum[64:])
	var classicalKey, quantumKey [32]byte
	for i := uint64(0); i <= binary.BigEndian.Uint64(header[40:48]); i++ {
		classicalKey = referenceClassicalStep(&classicalChain)
	}
	for i := uint64(1); i <= binary.BigEndian.Uint64(header[56:64]); i++ {
		quantumKey = referenceQuantumStep(&quantumChain, i)
	}
	return referenceCombine(classicalKey, quantumKey)
}
func testServerSession(root, id [32]byte) *ServerSession {
	session, err := newServerSession(root, id, referencePrivate(3), 1152)
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
	initialPublic [32]byte
	id            [32]byte
	number        uint64
	direction     direction
	finished      bool
}

func (r *records) install(secret [32]byte) error {
	info := append([]byte("stogas.e2ee.record.v3\x00"), r.id[:]...)
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
func newRecords(secret, id [32]byte, number uint64, direction direction) (*records, error) {
	public := referencePublic(referencePrivate(7))
	header := append([]byte(nil), public[:]...)
	header = binary.BigEndian.AppendUint64(header, 0)
	header = binary.BigEndian.AppendUint64(header, number)
	header = binary.BigEndian.AppendUint64(header, 0)
	header = binary.BigEndian.AppendUint64(header, number+1)
	header = binary.BigEndian.AppendUint64(header, 1)
	header = append(header, 0)
	r := &records{id: id, number: number, direction: direction, header: header}
	return r, r.install(secret)
}
func responseRecords(root, id [32]byte, number uint64) (*records, error) {
	return responseRecordsFor(root, id, referencePublic(referencePrivate(3)), number)
}
func responseRecordsFor(root, id, initialPublic [32]byte, number uint64) (*records, error) {
	r, err := newRecords([32]byte{}, id, number, responseDirection)
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
		if len(encoded) < 96 {
			return 0, nil, ErrRecord
		}
		offset = 6 + int(binary.BigEndian.Uint16(encoded[4:6]))
		if offset+17 > len(encoded) {
			return 0, nil, ErrRecord
		}
		if r.root != nil {
			n := binary.BigEndian.Uint64(encoded[62:70])
			if n == 0 || n > 1<<20 || binary.BigEndian.Uint64(encoded[46:54]) > 1<<20 || binary.BigEndian.Uint64(encoded[70:78]) != 1 {
				return 0, nil, ErrRecord
			}
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
