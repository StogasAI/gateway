package channel

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	ref "github.com/StogasAI/verifier/go/reference"
)

func firstRecord(t *testing.T, client *ref.Session, number uint64) []byte {
	t.Helper()
	encoder := newRecords(requestMessage(client, number), client.ID, number, requestDirection)
	return sealRecord(t, encoder, Metadata, []byte("credentials"))
}

func TestRatchetAuthenticationIsTransactionalAndBounded(t *testing.T) {
	session, client := testServerSession(t)
	defer session.Close()
	for _, number := range []uint64{ReplayWindow, 1 << 50, ^uint64(0)} {
		if request, _, err := session.AcceptStart(number, make([]byte, RecordOverhead)); request != nil || !errors.Is(err, ErrRecordLimit) {
			t.Fatalf("unbounded jump admitted: %d %v", number, err)
		}
	}
	first := firstRecord(t, client, ReplayWindow-1)
	corrupt := slices.Clone(first)
	corrupt[len(corrupt)-1] ^= 1
	if _, _, err := session.AcceptStart(ReplayWindow-1, corrupt); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	request, _, err := session.AcceptStart(ReplayWindow-1, first)
	if err != nil {
		t.Fatal(err)
	}
	request.Close()
	zero := firstRecord(t, client, 0)
	corrupt = slices.Clone(zero)
	corrupt[len(corrupt)-1] ^= 1
	if _, _, err := session.AcceptStart(0, corrupt); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	request, _, err = session.AcceptStart(0, zero)
	if err != nil {
		t.Fatal(err)
	}
	request.Close()

}

func TestRatchetSkippedExpiryDoesNotExpireAdmittedWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		session, client := testServerSession(t)
		defer session.Close()
		request, _, err := session.AcceptStart(3, firstRecord(t, client, 3))
		if err != nil {
			t.Fatal(err)
		}
		defer request.Close()
		time.Sleep(SkippedKeyLifetime - time.Nanosecond)
		delayed, _, err := session.AcceptStart(1, firstRecord(t, client, 1))
		if err != nil {
			t.Fatal("expired early", err)
		}
		delayed.Close()
		later, _, err := session.AcceptStart(5, firstRecord(t, client, 5))
		if err != nil {
			t.Fatal(err)
		}
		later.Close()
		time.Sleep(time.Nanosecond)
		if _, _, err = session.AcceptStart(0, firstRecord(t, client, 0)); !errors.Is(err, ErrReplay) {
			t.Fatal("accepted expired number", err)
		}
		live := firstRecord(t, client, 4)
		live[len(live)-1] ^= 1
		if _, _, err = session.AcceptStart(4, live); !errors.Is(err, ErrAuthentication) {
			t.Fatal("new delayed key expired early", err)
		}
		time.Sleep(time.Hour)
		session.expire(time.Now())
		if _, _, err = session.AcceptStart(4, firstRecord(t, client, 4)); !errors.Is(err, ErrReplay) {
			t.Fatal("maintenance retained expired key", err)
		}
		// Neither a delayed upload nor a long response inherits the missing-start TTL.
		encoder := newRecords(requestMessage(client, 3), client.ID, 3, requestDirection)
		_ = sealRecord(t, encoder, Metadata, []byte("credentials"))
		if _, _, err = request.Open(sealRecord(t, encoder, Data, []byte("late upload"))); err != nil {
			t.Fatal(err)
		}
		if _, _, err = request.Open(sealRecord(t, encoder, Finished, nil)); err != nil {
			t.Fatal(err)
		}
		if err = request.Complete(); err != nil {
			t.Fatal(err)
		}
		response, err := request.Seal(Metadata, []byte("status=200"))
		if err != nil {
			t.Fatal(err)
		}
		decoder := responseRecords(client, 3)
		if _, data, err := decoder.open(response); err != nil || !bytes.Equal(data, []byte("status=200")) {
			t.Fatal("active response expired", err)
		}
	})
}

func TestRatchetReorderedStartsMatchReference(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		session, client := testServerSession(t)
		defer session.Close()
		random := rand.New(rand.NewPCG(16, 42))
		const count = ReplayWindow * 3
		// Generate once; retaining roots and all test keys is never production behavior.
		encoded := make([][]byte, count)
		chain := referenceChain(client)
		for number := range encoded {
			key, next := referenceStep(&chain, uint64(number)+1)
			chain = next
			encoder := newRecords(key, client.ID, uint64(number), requestDirection)
			encoded[number] = sealRecord(t, encoder, Metadata, []byte("m"))
		}
		seen := make(map[uint64]bool)
		expiry := make(map[uint64]time.Time)
		var next uint64
		for index := 0; index < 6000; index++ {
			if index%97 == 0 {
				time.Sleep(19 * time.Second)
			}
			number := random.Uint64N(count)
			now := time.Now()
			allowed := !seen[number]
			if number >= next {
				allowed = allowed && number-next < ReplayWindow
			} else {
				allowed = allowed && next-number <= ReplayWindow && now.Before(expiry[number])
			}
			forged := index%5 == 0
			first := slices.Clone(encoded[number])
			if forged {
				first[len(first)-1] ^= 1
			}
			request, _, err := session.AcceptStart(number, first)
			if (err == nil) != (allowed && !forged) {
				t.Fatalf("step %d number %d next %d allowed %t forged %t: %v", index, number, next, allowed, forged, err)
			}
			if err == nil {
				request.Close()
				seen[number] = true
				if number >= next {
					for n := next; n < number; n++ {
						expiry[n] = now.Add(SkippedKeyLifetime)
					}
					next = number + 1
				}
			}

		}
	})
}

func BenchmarkRatchetWarmStart(b *testing.B) {
	session, client := testServerSession(b)
	defer session.Close()
	chain := referenceChain(client)
	b.ReportAllocs()
	b.ResetTimer()
	for number := 0; number < b.N; number++ {
		key, next := referenceStep(&chain, uint64(number)+1)
		chain = next
		encoder := newRecords(key, client.ID, uint64(number), requestDirection)
		encoded, _ := encoder.seal(Metadata, []byte("m"))
		request, _, err := session.AcceptStart(uint64(number), encoded)
		if err != nil {
			b.Fatal(err)
		}
		request.Close()
	}
}
func BenchmarkRatchetMaximumUnauthenticatedGap(b *testing.B) {
	for _, gap := range []uint64{0, 32, 256, ReplayWindow - 1} {
		for _, size := range []int{1, MaxRecordPlaintext - 2 - MaxRatchetHeaderBytes} {
			b.Run(fmt.Sprintf("gap=%d/plaintext=%d", gap, size), func(b *testing.B) {
				benchmarkUnauthenticatedStart(b, gap, size)
			})
		}
	}
}

func benchmarkUnauthenticatedStart(b *testing.B, gap uint64, size int) {
	session, client := testServerSession(b)
	defer session.Close()
	encoder := newRecords(requestMessage(client, gap), client.ID, gap, requestDirection)
	forged, err := encoder.seal(Metadata, make([]byte, size))
	if err != nil {
		b.Fatal(err)
	}
	forged[len(forged)-1] ^= 1
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, _, err := session.AcceptStart(gap, forged); err != ErrAuthentication {
			b.Fatal(err)
		}
	}
}

// Same record/cipher work as warm admission, without the two endpoint chain
// steps or session lock, to make the incremental ratchet cost measurable.
func BenchmarkRecordAdmissionBaseline(b *testing.B) {
	key, id := [32]byte{1}, [32]byte{2}
	b.ReportAllocs()
	for number := 0; number < b.N; number++ {
		client := newRecords(referenceMessage{secret: key, header: make([]byte, MaxRatchetHeaderBytes)}, id, uint64(number), requestDirection)
		encoded, _ := client.seal(Metadata, []byte("m"))
		incoming := newRecords(referenceMessage{secret: key, header: make([]byte, MaxRatchetHeaderBytes)}, id, uint64(number), requestDirection)
		if _, _, err := incoming.open(encoded); err != nil {
			b.Fatal(err)
		}
		outgoing := newRecords(referenceMessage{secret: key, header: make([]byte, MaxRatchetHeaderBytes)}, id, uint64(number), responseDirection)
		incoming.fail(ErrClosed)
		outgoing.fail(ErrClosed)
	}
}
