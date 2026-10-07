package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type batchVector struct {
	Count      int    `json:"count"`
	Index      int    `json:"index"`
	Proof      string `json:"proof"`
	ReportData string `json:"report_data"`
}

func batchVectors(t *testing.T) []batchVector {
	t.Helper()
	encoded, err := os.ReadFile("testdata/batch-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []batchVector
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func testBinding(i int) Binding {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], uint16(i))
	challenge := sha256.Sum256(encoded[:])
	var boot, spki [32]byte
	for j := range boot {
		boot[j] = 17
		spki[j] = 34
	}
	if i%2 == 0 {
		return NativeTLSBinding{Environment: Production, Challenge: challenge, BootEvidenceSHA256: boot, SignerSPKISHA256: spki}
	}
	return E2EESessionBinding{Environment: Production, BootEvidenceSHA256: boot, TranscriptSHA256: challenge}
}

func testBindings(n int) []Binding {
	bindings := make([]Binding, n)
	for i := range bindings {
		bindings[i] = testBinding(i)
	}
	return bindings
}

func TestBatchProofCrossLanguageVectors(t *testing.T) {
	for _, vector := range batchVectors(t) {
		t.Run(fmt.Sprintf("%d/%d", vector.Count, vector.Index), func(t *testing.T) {
			tree, err := BuildBatch(testBindings(vector.Count))
			if err != nil {
				t.Fatal(err)
			}
			report := tree.ReportData()
			if hex.EncodeToString(report[:]) != vector.ReportData {
				t.Fatal("report commitment differs")
			}
			proof, err := tree.Proof(vector.Index)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := proof.MarshalBinary()
			if err != nil || hex.EncodeToString(encoded) != vector.Proof {
				t.Fatal("proof differs", err)
			}
			decoded, err := ParseBatchProof(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if err := decoded.Verify(testBinding(vector.Index), report); err != nil {
				t.Fatal(err)
			}
			for i := range encoded {
				changed := bytes.Clone(encoded)
				changed[i] ^= 1
				mutated, err := ParseBatchProof(changed)
				if err == nil && mutated.Verify(testBinding(vector.Index), report) == nil {
					t.Fatalf("accepted changed proof byte %d", i)
				}
			}
			changedReport := report
			changedReport[0] ^= 1
			if decoded.Verify(testBinding(vector.Index), changedReport) == nil {
				t.Fatal("accepted changed report")
			}
			if decoded.Verify(testBinding(vector.Index+1), report) == nil {
				t.Fatal("accepted another channel")
			}
		})
	}
}

func TestBatchProofAllTreeSizesAndPositions(t *testing.T) {
	for n := 1; n <= MaxBatchLeaves; n++ {
		bindings := testBindings(n)
		tree, err := BuildBatch(bindings)
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range []int{0, n / 2, n - 1} {
			proof, err := tree.Proof(i)
			if err != nil {
				t.Fatal(err)
			}
			if len(proof.Siblings) > MaxProofHashes {
				t.Fatal("proof exceeded protocol bound")
			}
			if err := proof.Verify(bindings[i], tree.ReportData()); err != nil {
				t.Fatalf("%d/%d: %v", n, i, err)
			}
		}
	}
}

func TestBatchProofBindsEveryChannelField(t *testing.T) {
	original := testBinding(0).(NativeTLSBinding)
	tree, _ := BuildBatch([]Binding{original})
	proof, _ := tree.Proof(0)
	for _, field := range []string{"environment", "boot", "challenge", "signer"} {
		changed := original
		switch field {
		case "environment":
			changed.Environment = Staging
		case "boot":
			changed.BootEvidenceSHA256[0] ^= 1
		case "challenge":
			changed.Challenge[0] ^= 1
		case "signer":
			changed.SignerSPKISHA256[0] ^= 1
		}
		if proof.Verify(changed, tree.ReportData()) == nil {
			t.Fatal("accepted changed", field)
		}
	}
	e2ee := testBinding(1).(E2EESessionBinding)
	tree, _ = BuildBatch([]Binding{e2ee})
	proof, _ = tree.Proof(0)
	for _, field := range []string{"environment", "boot", "transcript"} {
		changed := e2ee
		switch field {
		case "environment":
			changed.Environment = Staging
		case "boot":
			changed.BootEvidenceSHA256[0] ^= 1
		case "transcript":
			changed.TranscriptSHA256[0] ^= 1
		}
		if proof.Verify(changed, tree.ReportData()) == nil {
			t.Fatal("accepted changed", field)
		}
	}
}

func TestBatchProofRejectsInvalidBoundsAndShapes(t *testing.T) {
	for _, bindings := range [][]Binding{nil, make([]Binding, MaxBatchLeaves+1), {nil}, {(*NativeTLSBinding)(nil)}, {NativeTLSBinding{Environment: 0}}} {
		if _, err := BuildBatch(bindings); err == nil {
			t.Fatal("accepted invalid bindings")
		}
	}
	for _, encoded := range [][]byte{nil, {0, 1, 0}, {0, 0, 0, 0}, {0, 1, 0, 1}, {4, 1, 0, 0}, {0, 2, 0, 0}, make([]byte, 4+MaxProofHashes*64+1)} {
		if _, err := ParseBatchProof(encoded); err == nil {
			t.Fatal("accepted invalid proof")
		}
	}
	tree, _ := BuildBatch(testBindings(2))
	for _, i := range []int{-1, 2} {
		if _, err := tree.Proof(i); err == nil {
			t.Fatal("accepted invalid index")
		}
	}
	proof, _ := tree.Proof(0)
	proof.Siblings = append(proof.Siblings, [64]byte{})
	if _, err := proof.MarshalBinary(); err == nil {
		t.Fatal("accepted extra sibling")
	}
	if proof.Verify(testBinding(0), tree.ReportData()) == nil {
		t.Fatal("accepted extra sibling")
	}
}

func BenchmarkBuildBatch(b *testing.B) {
	for _, count := range []int{1, 64, 1024} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			bindings := testBindings(count)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := BuildBatch(bindings); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Include every caller's encoded inclusion proof, not just the shared tree.
// Hardware report generation and channel setup are outside this measurement.
func BenchmarkBuildBatchProofs(b *testing.B) {
	for _, count := range []int{1, 64, 1024} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			bindings := testBindings(count)
			b.ReportAllocs()
			for b.Loop() {
				tree, err := BuildBatch(bindings)
				if err != nil {
					b.Fatal(err)
				}
				_ = tree.ReportData()
				for index := range count {
					proof, err := tree.Proof(index)
					if err != nil {
						b.Fatal(err)
					}
					if _, err := proof.MarshalBinary(); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(count), "ns/leaf")
		})
	}
}
