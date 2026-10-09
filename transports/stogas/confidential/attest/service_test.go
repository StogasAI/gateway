package attest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	ref "github.com/StogasAI/verifier/go/reference"
)

type quoteFunc func(context.Context, [64]byte) ([]byte, error)

func (f quoteFunc) Quote(ctx context.Context, data [64]byte) ([]byte, error) { return f(ctx, data) }

func testReport(data [64]byte) []byte {
	report := make([]byte, snpReportSize)
	binary.LittleEndian.PutUint32(report[:4], 3)
	binary.LittleEndian.PutUint32(report[0x34:0x38], snpReportSigAlgo)
	copy(report[0x50:0x90], data[:])
	encoded, _ := EncodeEnvelope(Envelope{Provider: ProviderSEVGuest, Report: base64.RawURLEncoding.EncodeToString(report)})
	return encoded
}

type testReservations struct {
	used  atomic.Int64
	peak  atomic.Int64
	limit int64
}

func (r *testReservations) acquire() (func(), bool) {
	for {
		used := r.used.Load()
		if used >= r.limit {
			return nil, false
		}
		if r.used.CompareAndSwap(used, used+1) {
			for peak := r.peak.Load(); used+1 > peak; peak = r.peak.Load() {
				if r.peak.CompareAndSwap(peak, used+1) {
					break
				}
			}
			var released atomic.Bool
			return func() {
				if released.Swap(true) {
					panic("reservation released twice")
				}
				r.used.Add(-1)
			}, true
		}
	}
}

func startQuote(b *Batcher, ctx context.Context, leaf Leaf) <-chan quoteOutcome {
	result := make(chan quoteOutcome, 1)
	go func() {
		quote, err := b.Quote(ctx, leaf)
		result <- quoteOutcome{quote, err}
	}()
	return result
}

func testTranscript(i int) [32]byte {
	return sha256.Sum256(binary.BigEndian.AppendUint32(nil, uint32(i)))
}

func testLeaf(i int) Leaf {
	leaf, err := E2EESessionLeaf(Production, [32]byte{17}, testTranscript(i))
	if err != nil {
		panic(err)
	}
	return leaf
}

func newTestBatcher(t *testing.T, backend Attester, reservations *testReservations) *Batcher {
	t.Helper()
	b, err := NewBatcher(backend, reservations.acquire)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The independent reference decoder checks that each waiter received its own leaf's proof.
func verifyChannel(t *testing.T, outcome quoteOutcome, i int) *ChannelQuote {
	t.Helper()
	if outcome.err != nil || outcome.quote == nil {
		t.Fatal("quote failed", outcome.err)
	}
	quote := outcome.quote
	if err := ref.VerifyBatchProof(ref.E2EELeaf(byte(Production), [32]byte{17}, testTranscript(i)), quote.Proof, [64]byte(quote.Report[0x50:0x90])); err != nil {
		t.Fatal(err)
	}
	return quote
}

func leafCount(quote *ChannelQuote) uint16 { return binary.BigEndian.Uint16(quote.Proof) }

func TestBatcherBatchesWaitersAcrossModesWithoutDelayingIdleWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int64
		started := make(chan struct{}, 3)
		allow := make(chan struct{})
		resources := &testReservations{limit: 100}
		b := newTestBatcher(t, quoteFunc(func(_ context.Context, data [64]byte) ([]byte, error) {
			calls.Add(1)
			started <- struct{}{}
			<-allow
			return testReport(data), nil
		}), resources)
		first := startQuote(b, context.Background(), testLeaf(0))
		<-started
		results := make([]<-chan quoteOutcome, 64)
		for i := range results {
			results[i] = startQuote(b, context.Background(), testLeaf(i+1))
		}
		synctest.Wait()
		if b.Diagnostics().Pending != 64 || calls.Load() != 1 {
			t.Fatal(b.Diagnostics(), calls.Load())
		}
		allow <- struct{}{}
		q := verifyChannel(t, <-first, 0)
		if leafCount(q) != 1 {
			t.Fatal("idle work waited for a batch")
		}
		q.Close()
		<-started
		allow <- struct{}{}
		var previous *ChannelQuote
		for i, result := range results {
			quote := verifyChannel(t, <-result, i+1)
			if leafCount(quote) != 64 {
				t.Fatal("waiters were not combined")
			}
			// A result may be retained/mutated by its owner without poisoning peers.
			if previous != nil && previous.Report[0] == quote.Report[0] {
				t.Fatal("test mutation did not remain isolated")
			}
			quote.Report[0] = 99
			previous = quote
			quote.Close()
			quote.Close()
		}
		if err := b.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if resources.used.Load() != 0 || calls.Load() != 2 || b.Diagnostics().Completed != 65 {
			t.Fatal(resources.used.Load(), b.Diagnostics())
		}
	})
}

func TestBatcherCancellationRetainsActualHardwareOwnership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, allow := make(chan struct{}), make(chan struct{})
		resources := &testReservations{limit: 2}
		b := newTestBatcher(t, quoteFunc(func(_ context.Context, data [64]byte) ([]byte, error) {
			close(started)
			<-allow // models an ioctl that does not stop when its context is canceled
			return testReport(data), nil
		}), resources)
		ctx, cancel := context.WithCancel(context.Background())
		active := startQuote(b, ctx, testLeaf(0))
		<-started
		queuedCtx, cancelQueued := context.WithCancel(context.Background())
		queued := startQuote(b, queuedCtx, testLeaf(1))
		synctest.Wait()
		if _, err := b.Quote(context.Background(), testLeaf(2)); !errors.Is(err, ErrQuoteCapacity) {
			t.Fatal(err)
		}
		cancelQueued()
		if result := <-queued; !errors.Is(result.err, context.Canceled) {
			t.Fatal(result.err)
		}
		if resources.used.Load() != 1 || b.Diagnostics().Pending != 0 {
			t.Fatal("queued ownership leaked")
		}
		cancel()
		if result := <-active; !errors.Is(result.err, context.Canceled) {
			t.Fatal(result.err)
		}
		if resources.used.Load() != 1 || b.Diagnostics().Active != 1 {
			t.Fatal("active hardware released early")
		}
		deadline, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := b.Close(deadline); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if resources.used.Load() != 1 {
			t.Fatal("shutdown timeout released active hardware")
		}
		if _, err := b.Quote(context.Background(), testLeaf(3)); !errors.Is(err, ErrQuoteClosed) {
			t.Fatal(err)
		}
		close(allow)
		if err := b.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if resources.used.Load() != 0 || b.Diagnostics().Canceled != 2 || b.Diagnostics().Rejected != 1 {
			t.Fatal(resources.used.Load(), b.Diagnostics())
		}
	})
}

func TestBatcherNeverExceedsProtocolBoundAndShutdownReleasesQueuedWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, allow := make(chan struct{}, 4), make(chan struct{})
		resources := &testReservations{limit: 2 * MaxBatchLeaves}
		b := newTestBatcher(t, quoteFunc(func(_ context.Context, data [64]byte) ([]byte, error) {
			started <- struct{}{}
			<-allow
			return testReport(data), nil
		}), resources)
		first := startQuote(b, context.Background(), testLeaf(0))
		<-started
		results := make([]<-chan quoteOutcome, MaxBatchLeaves+3)
		for i := range results {
			results[i] = startQuote(b, context.Background(), testLeaf(i+1))
		}
		synctest.Wait()
		allow <- struct{}{}
		verifyChannel(t, <-first, 0).Close()
		<-started
		if got := b.Diagnostics(); got.Active != MaxBatchLeaves || got.Pending != 3 {
			t.Fatal(got)
		}
		closed := make(chan error, 1)
		go func() { closed <- b.Close(context.Background()) }()
		synctest.Wait()
		for _, result := range results {
			if outcome := <-result; !errors.Is(outcome.err, ErrQuoteClosed) {
				t.Fatal(outcome.err)
			}
		}
		if resources.used.Load() != MaxBatchLeaves {
			t.Fatal("active ownership was not retained", resources.used.Load())
		}
		allow <- struct{}{}
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if resources.used.Load() != 0 || b.Diagnostics().Active != 0 || b.Diagnostics().Pending != 0 {
			t.Fatal(resources.used.Load(), b.Diagnostics())
		}
	})
}

func TestBatcherRejectsMalformedLocalReportsAndRecovers(t *testing.T) {
	for _, mutate := range []struct {
		name   string
		change func(*Envelope)
	}{
		{"wrong-schema", func(e *Envelope) { e.Schema = "other" }},
		{"wrong-provider", func(e *Envelope) { e.Provider = "other" }},
		{"bad-base64", func(e *Envelope) { e.Report = "%%%" }},
		{"truncated", func(e *Envelope) { e.Report = e.Report[:20] }},
		{"wrong-binding", func(e *Envelope) {
			bytes, _ := base64.RawURLEncoding.DecodeString(e.Report)
			bytes[0x50] ^= 1
			e.Report = base64.RawURLEncoding.EncodeToString(bytes)
		}},
		{"wrong-vmpl", func(e *Envelope) {
			bytes, _ := base64.RawURLEncoding.DecodeString(e.Report)
			bytes[0x30] = 1
			e.Report = base64.RawURLEncoding.EncodeToString(bytes)
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			resources := &testReservations{limit: 2}
			var calls int
			b := newTestBatcher(t, quoteFunc(func(_ context.Context, data [64]byte) ([]byte, error) {
				calls++
				encoded := testReport(data)
				if calls == 1 {
					var envelope Envelope
					_ = json.Unmarshal(encoded, &envelope)
					mutate.change(&envelope)
					return json.Marshal(envelope)
				}
				return encoded, nil
			}), resources)
			if quote, err := b.Quote(context.Background(), testLeaf(0)); quote != nil || !errors.Is(err, ErrQuoteReport) {
				t.Fatal(err)
			}
			// A failure does not poison the worker or retain ownership after its batch.
			quote, err := b.Quote(context.Background(), testLeaf(1))
			verifyChannel(t, quoteOutcome{quote, err}, 1).Close()
			if err := b.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if resources.used.Load() != 0 {
				t.Fatal("failed report leaked")
			}
		})
	}
}

func TestBatcherRejectsInvalidWorkBeforeAdmission(t *testing.T) {
	resources := &testReservations{limit: 1}
	b := newTestBatcher(t, quoteFunc(func(context.Context, [64]byte) ([]byte, error) { t.Error("backend should not run"); return nil, nil }), resources)
	if _, err := b.Quote(context.Background(), Leaf{}); err == nil {
		t.Fatal("accepted invalid binding")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Quote(ctx, testLeaf(0)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if resources.peak.Load() != 0 {
		t.Fatal("invalid work acquired memory")
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewBatcher(nil, resources.acquire); err == nil {
		t.Fatal("accepted absent backend")
	}
	if _, err := NewBatcher(quoteFunc(nil), nil); err == nil {
		t.Fatal("accepted absent admission")
	}
}

func TestBatchWorkspaceStaysChargedWhenAnEarlyResultCloses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		resources := &testReservations{limit: 2}
		b := &Batcher{ctx: context.Background(), attester: quoteFunc(func(_ context.Context, data [64]byte) ([]byte, error) { return testReport(data), nil }), stats: QuoteDiagnostics{Active: 2}}
		jobs := make([]*quoteJob, 2)
		for i := range jobs {
			release, ok := resources.acquire()
			if !ok {
				t.Fatal("test reservation failed")
			}
			jobs[i] = &quoteJob{ctx: context.Background(), leaf: testLeaf(i), release: release, result: make(chan quoteOutcome)}
			jobs[i].owners.Store(1)
		}
		done := make(chan struct{})
		go func() { defer close(done); b.generate(jobs) }()
		verifyChannel(t, <-jobs[0].result, 0).Close()
		// The second consumer has not received its result yet; the shared tree
		// and batch arrays still belong to the worker, including the first job's share.
		synctest.Wait()
		if resources.used.Load() != 2 {
			t.Fatal("shared batch storage released early", resources.used.Load())
		}
		verifyChannel(t, <-jobs[1].result, 1).Close()
		<-done
		if resources.used.Load() != 0 {
			t.Fatal("batch storage leaked")
		}
	})
}

// BenchmarkQuoteBatch measures leaf hashing, tree/report-data construction and
// every encoded proof through the Rust producer, excluding hardware reports.
func BenchmarkQuoteBatch(b *testing.B) {
	for _, size := range []int{1, 64, MaxBatchLeaves} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				leaves := make([][64]byte, size)
				for i := range leaves {
					leaves[i] = testLeaf(i).hash
				}
				if _, _, err := verifier.QuoteBatch(leaves); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
