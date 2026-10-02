package channel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
)

// Historical symmetric-chain baseline for the published transport cost comparison.
func BenchmarkRatchetStep(b *testing.B) {
	chain := [32]byte{1}
	b.ReportAllocs()
	for range b.N {
		mac := hmac.New(sha256.New, chain[:])
		mac.Write([]byte{1})
		message := mac.Sum(nil)
		mac.Reset()
		mac.Write([]byte{2})
		next := [32]byte(mac.Sum(nil))
		clear(chain[:])
		chain = next
		clear(message[:])
	}
}

func benchmarkRoot(root [32]byte, secret []byte) (next, chain [32]byte) {
	material, err := hkdf.Key(sha256.New, secret, root[:], "benchmark Signal KDF_RK", 64)
	if err != nil {
		panic(err)
	}
	copy(next[:], material[:32])
	copy(chain[:], material[32:])
	clear(material)
	return
}

// The exact two-DH/two-root-KDF receiving step from Signal's classical
// DHRatchet, with alternating endpoints and checked chain agreement. This is
// a CPU cost model, not a network protocol: skipped chains, headers, AEAD and
// concurrency are deliberately excluded. One turn advertises a 32-byte key.
func BenchmarkDoubleRatchetDHTurn(b *testing.B) {
	type state struct {
		key        *ecdh.PrivateKey
		root, send [32]byte
	}
	key := func() *ecdh.PrivateKey {
		value, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		return value
	}
	a, c := state{key: key()}, state{key: key()}
	shared, err := a.key.ECDH(c.key.PublicKey())
	if err != nil {
		b.Fatal(err)
	}
	a.root, a.send = benchmarkRoot(a.root, shared)
	clear(shared)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		shared, err := c.key.ECDH(a.key.PublicKey())
		if err != nil {
			b.Fatal(err)
		}
		var received [32]byte
		c.root, received = benchmarkRoot(c.root, shared)
		clear(shared)
		if received != a.send {
			b.Fatal("ratchet endpoint chains differ")
		}
		clear(received[:])
		c.key = key()
		shared, err = c.key.ECDH(a.key.PublicKey())
		if err != nil {
			b.Fatal(err)
		}
		c.root, c.send = benchmarkRoot(c.root, shared)
		clear(shared)
		a, c = c, a
	}
	b.ReportMetric(32, "crypto-wire-B/turn")
}

// Fresh hybrid recipient key generation, encapsulation, decapsulation, export
// and mixing into both endpoint roots. This measures a PQ recovery building
// block, NOT a complete post-quantum double ratchet or a proposed wire format.
func BenchmarkHybridRecoveryExchange(b *testing.B) {
	root := [32]byte{1}
	var wireBytes int
	b.ReportAllocs()
	for range b.N {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			b.Fatal(err)
		}
		private, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
		clear(seed)
		if err != nil {
			b.Fatal(err)
		}
		public := private.PublicKey()
		enc, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.ExportOnly(), []byte("benchmark recovery"))
		if err != nil {
			b.Fatal(err)
		}
		receiver, err := hpke.NewRecipient(enc, private, hpke.HKDFSHA256(), hpke.ExportOnly(), []byte("benchmark recovery"))
		if err != nil {
			b.Fatal(err)
		}
		left, err := sender.Export("root contribution", 32)
		if err != nil {
			b.Fatal(err)
		}
		right, err := receiver.Export("root contribution", 32)
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(left, right) {
			b.Fatal("hybrid secrets differ")
		}
		next, chain := benchmarkRoot(root, left)
		other, otherChain := benchmarkRoot(root, right)
		if next != other || chain != otherChain {
			b.Fatal("root mixing differs")
		}
		root = next
		clear(chain[:])
		clear(other[:])
		clear(otherChain[:])
		clear(left)
		clear(right)
		wireBytes = len(public.Bytes()) + len(enc)
	}
	b.ReportMetric(float64(wireBytes), "crypto-wire-B/exchange")
}

func BenchmarkPayloadAES256GCM(b *testing.B) {
	for _, size := range []int{256, 4096, MaxRecordPlaintext, 1 << 20} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			block, _ := aes.NewCipher(make([]byte, 32))
			aead, _ := cipher.NewGCM(block)
			plaintext := make([]byte, size)
			output := make([]byte, 0, size+aead.Overhead())
			var nonce [12]byte
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				for j := range 8 {
					nonce[j] = byte(uint64(i) >> (j * 8))
				}
				sealed := aead.Seal(output[:0], nonce[:], plaintext, nil)
				if _, err := aead.Open(sealed[:0], nonce[:], sealed, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
