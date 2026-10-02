package attest

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	MaxBatchLeaves    = 1024
	MaxProofHashes    = 10
	batchDomain       = "stogas.quote-batch.v1\x00"
	tlsBindingDomain  = "stogas.native-tls.v1\x00"
	e2eeBindingDomain = "stogas.e2ee-session.v1\x00"
)

type Environment byte

const (
	Production Environment = 1
	Staging    Environment = 2
)

// Binding is sealed to the locally constructed channel bindings in this package.
// Neither the gateway's network handlers nor the quote service accept arbitrary report data.
type Binding interface {
	leafHash() ([64]byte, error)
}

func hashBinding(binding Binding) ([64]byte, error) {
	switch binding.(type) {
	case NativeTLSBinding, E2EESessionBinding:
		return binding.leafHash()
	default:
		return [64]byte{}, errors.New("attestation requires a concrete channel binding")
	}
}

type NativeTLSBinding struct {
	Environment        Environment
	Challenge          [32]byte
	BootEvidenceSHA256 [32]byte
	SignerSPKISHA256   [32]byte
}

func (b NativeTLSBinding) leafHash() ([64]byte, error) {
	return bindingHash(tlsBindingDomain, b.Environment, b.BootEvidenceSHA256[:], b.Challenge[:], b.SignerSPKISHA256[:])
}

type E2EESessionBinding struct {
	Environment        Environment
	BootEvidenceSHA256 [32]byte
	// Hash of the complete canonical setup transcript, including the client challenge,
	// ephemeral recipient key, session/node identity, suite and authenticated expiry hints.
	TranscriptSHA256 [32]byte
}

func (b E2EESessionBinding) leafHash() ([64]byte, error) {
	return bindingHash(e2eeBindingDomain, b.Environment, b.BootEvidenceSHA256[:], b.TranscriptSHA256[:])
}

func bindingHash(domain string, environment Environment, fields ...[]byte) ([64]byte, error) {
	if environment != Production && environment != Staging {
		return [64]byte{}, errors.New("unsupported attestation environment")
	}
	h := sha512.New()
	h.Write([]byte{0})
	h.Write([]byte(domain))
	h.Write([]byte{byte(environment)})
	for _, field := range fields {
		h.Write(field)
	}
	var result [64]byte
	h.Sum(result[:0])
	return result, nil
}

// BatchTree uses the RFC 9162 tree shape and distinct leaf/internal prefixes with SHA-512.
// Its shape is fixed by the committed count; it has no duplicated or invented padding leaves.
type BatchTree struct {
	leaves int
	root   *batchBranch
}

type batchBranch struct {
	hash        [64]byte
	left, right *batchBranch
	leftLeaves  int
}

func BuildBatch(bindings []Binding) (*BatchTree, error) {
	if len(bindings) == 0 || len(bindings) > MaxBatchLeaves {
		return nil, errors.New("attestation batch size is invalid")
	}
	hashes := make([][64]byte, len(bindings))
	for i, binding := range bindings {
		if binding == nil {
			return nil, errors.New("attestation binding is absent")
		}
		var err error
		hashes[i], err = hashBinding(binding)
		if err != nil {
			return nil, err
		}
	}
	branches := make([]batchBranch, 2*len(bindings)-1)
	return &BatchTree{leaves: len(bindings), root: buildBranch(hashes, branches)}, nil
}

func buildBranch(hashes [][64]byte, branches []batchBranch) *batchBranch {
	branch := &branches[0]
	if len(hashes) == 1 {
		branch.hash = hashes[0]
		return branch
	}
	k := 1 << (bits.Len(uint(len(hashes)-1)) - 1)
	left, right := buildBranch(hashes[:k], branches[1:2*k]), buildBranch(hashes[k:], branches[2*k:])
	*branch = batchBranch{hash: parentHash(left.hash, right.hash), left: left, right: right, leftLeaves: k}
	return branch
}

func parentHash(left, right [64]byte) [64]byte {
	var input [129]byte
	input[0] = 1
	copy(input[1:65], left[:])
	copy(input[65:], right[:])
	return sha512.Sum512(input[:])
}

func batchReportData(count uint16, root [64]byte) [64]byte {
	var input [len(batchDomain) + 2 + 64]byte
	copy(input[:], batchDomain)
	binary.BigEndian.PutUint16(input[len(batchDomain):], count)
	copy(input[len(batchDomain)+2:], root[:])
	return sha512.Sum512(input[:])
}

func (t *BatchTree) ReportData() [64]byte { return batchReportData(uint16(t.leaves), t.root.hash) }

type BatchProof struct {
	LeafCount uint16
	LeafIndex uint16
	Siblings  [][64]byte
}

func (t *BatchTree) Proof(index int) (BatchProof, error) {
	if index < 0 || index >= t.leaves {
		return BatchProof{}, errors.New("attestation leaf index is invalid")
	}
	p := BatchProof{LeafCount: uint16(t.leaves), LeafIndex: uint16(index), Siblings: make([][64]byte, 0, bits.Len(uint(t.leaves-1)))}
	appendProof(t.root, index, &p.Siblings)
	return p, nil
}

func appendProof(branch *batchBranch, index int, siblings *[][64]byte) {
	if branch.left == nil {
		return
	}
	if index < branch.leftLeaves {
		appendProof(branch.left, index, siblings)
		*siblings = append(*siblings, branch.right.hash)
	} else {
		appendProof(branch.right, index-branch.leftLeaves, siblings)
		*siblings = append(*siblings, branch.left.hash)
	}
}

func (p BatchProof) validShape() bool {
	if p.LeafCount == 0 || p.LeafCount > MaxBatchLeaves || p.LeafIndex >= p.LeafCount || len(p.Siblings) > MaxProofHashes {
		return false
	}
	count, index, depth := int(p.LeafCount), int(p.LeafIndex), 0
	for count > 1 {
		k := 1 << (bits.Len(uint(count-1)) - 1)
		if index < k {
			count = k
		} else {
			index -= k
			count -= k
		}
		depth++
	}
	return depth == len(p.Siblings)
}

// Verify checks only inclusion in the supplied report data. The caller must verify the report,
// hardware policy, live challenge, boot evidence and local key ownership separately.
func (p BatchProof) Verify(binding Binding, reportData [64]byte) error {
	if !p.validShape() || binding == nil {
		return errors.New("invalid attestation proof")
	}
	root, err := hashBinding(binding)
	if err != nil {
		return err
	}
	index, last := uint64(p.LeafIndex), uint64(p.LeafCount)-1
	for _, sibling := range p.Siblings {
		if index&1 != 0 || index == last {
			root = parentHash(sibling, root)
			for index != 0 && index&1 == 0 {
				index >>= 1
				last >>= 1
			}
		} else {
			root = parentHash(root, sibling)
		}
		index >>= 1
		last >>= 1
	}
	if last != 0 || batchReportData(p.LeafCount, root) != reportData {
		return errors.New("attestation proof does not bind this channel")
	}
	return nil
}

// The enclosing record supplies length: uint16 leaf count, uint16 index, then 64-byte siblings.
func (p BatchProof) MarshalBinary() ([]byte, error) {
	if !p.validShape() {
		return nil, errors.New("invalid attestation proof")
	}
	encoded := make([]byte, 4+len(p.Siblings)*64)
	binary.BigEndian.PutUint16(encoded, p.LeafCount)
	binary.BigEndian.PutUint16(encoded[2:], p.LeafIndex)
	for i, hash := range p.Siblings {
		copy(encoded[4+i*64:], hash[:])
	}
	return encoded, nil
}

func ParseBatchProof(encoded []byte) (BatchProof, error) {
	if len(encoded) < 4 || len(encoded) > 4+MaxProofHashes*64 || (len(encoded)-4)%64 != 0 {
		return BatchProof{}, errors.New("invalid attestation proof length")
	}
	p := BatchProof{LeafCount: binary.BigEndian.Uint16(encoded), LeafIndex: binary.BigEndian.Uint16(encoded[2:]), Siblings: make([][64]byte, (len(encoded)-4)/64)}
	if !p.validShape() {
		return BatchProof{}, errors.New("invalid attestation proof shape")
	}
	for i := range p.Siblings {
		copy(p.Siblings[i][:], encoded[4+i*64:4+(i+1)*64])
	}
	return p, nil
}
