package channel

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func storeFixture(t *testing.T, reporter *setupReporter) (*Store, *atomic.Int64) {
	t.Helper()
	retained := new(atomic.Int64)
	store, err := NewStore(newSetup(t, reporter), func() (func(), bool) {
		if !retained.CompareAndSwap(0, 1) {
			return nil, false
		}
		return func() { retained.Add(-1) }, true
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store, retained
}

func openStoredSession(t *testing.T, store *Store) ([32]byte, [32]byte, [referencePublicBytes]byte) {
	t.Helper()
	vector, hello := setupVector(t)
	id, response, err := store.Open(context.Background(), hello)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(vector.Seed)
	recipient, transcript := setupRecipient(t, seed, hello, response, store.setup.boot.Document)
	root, err := recipient.Export(rootDomain+string(transcript[:]), 32)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(root)
	return id, [32]byte(root), [referencePublicBytes]byte(response[serverSetupPrefixBytes-referencePublicBytes : serverSetupPrefixBytes])
}

func storedStart(t *testing.T, root, id [32]byte, initialPublic [referencePublicBytes]byte, number uint64) []byte {
	t.Helper()
	encoder := newRecords(requestMessageFor(root, number, initialPublic), id, number, requestDirection)
	defer encoder.fail(ErrClosed)
	return sealRecord(t, encoder, Metadata, []byte("credential"))
}

func TestStoreCapacityAndRemovalRetainActiveOwnership(t *testing.T) {
	reporter := &setupReporter{}
	store, retained := storeFixture(t, reporter)
	id, root, initialPublic := openStoredSession(t, store)
	defer clear(root[:])
	_, hello := setupVector(t)
	if _, _, err := store.Open(context.Background(), hello); !errors.Is(err, ErrSessionCapacity) || reporter.calls.Load() != 1 {
		t.Fatalf("capacity rejection spent quote work: %v", err)
	}
	request, _, err := store.AcceptStart(id, 1, storedStart(t, root, id, initialPublic, 1))
	if err != nil {
		t.Fatal(err)
	}
	store.Remove(id)
	store.Remove(id)
	if got := store.Diagnostics(); got.Open != 0 || got.Retained != 1 || got.Active != 1 || retained.Load() != 1 {
		t.Fatalf("removal released active state: %+v", got)
	}
	if _, _, err := store.AcceptStart(id, 2, storedStart(t, root, id, initialPublic, 2)); !errors.Is(err, ErrClosed) {
		t.Fatalf("removed session admitted a new start: %v", err)
	}
	if _, err := request.Seal(Metadata, []byte("response")); err != nil {
		t.Fatalf("removal interrupted the admitted response: %v", err)
	}
	request.Close()
	request.Close()
	if got := store.Diagnostics(); got.Retained != 0 || got.Active != 0 || retained.Load() != 0 {
		t.Fatalf("request cleanup did not release exactly once: %+v", got)
	}
	id, _, _ = openStoredSession(t, store)
	store.Close()
	store.Close()
	if retained.Load() != 0 || store.Diagnostics().Open != 0 {
		t.Fatal("store close retained idle state")
	}
	if _, _, err := store.Open(context.Background(), hello); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed store reopened: %v", err)
	}
}

func TestStoreIdleExpiryCountsOnlyAuthenticatedActivity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store, retained := storeFixture(t, &setupReporter{})
		id, root, initialPublic := openStoredSession(t, store)
		defer clear(root[:])
		idle := time.Duration(store.setup.idleSeconds) * time.Second
		time.Sleep(idle - time.Second)
		invalid := storedStart(t, root, id, initialPublic, 1)
		invalid[len(invalid)-1] ^= 1
		if _, _, err := store.AcceptStart(id, 1, invalid); !errors.Is(err, ErrAuthentication) {
			t.Fatal(err)
		}
		store.ExpireIdle()
		if store.Diagnostics().Open != 1 {
			t.Fatal("session expired before its idle deadline")
		}
		time.Sleep(time.Second)
		// Lookup also enforces expiry before the maintenance loop runs.
		if _, _, err := store.AcceptStart(id, 2, storedStart(t, root, id, initialPublic, 2)); !errors.Is(err, ErrClosed) {
			t.Fatalf("invalid traffic extended idle life: %v", err)
		}
		if retained.Load() != 0 || store.Diagnostics().Expired != 1 {
			t.Fatal("expired session retained its memory")
		}
		id, root, initialPublic = openStoredSession(t, store)
		request, _, err := store.AcceptStart(id, 0, storedStart(t, root, id, initialPublic, 0))
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * idle)
		store.ExpireIdle()
		if store.Diagnostics().Open != 1 {
			t.Fatal("active inference was counted as idle")
		}
		request.Close()
		time.Sleep(idle - time.Second)
		if _, _, err := store.AcceptStart(id, 0, storedStart(t, root, id, initialPublic, 0)); !errors.Is(err, ErrReplay) {
			t.Fatalf("duplicate became usable: %v", err)
		}
		time.Sleep(time.Second)
		store.ExpireIdle()
		if retained.Load() != 0 || store.Diagnostics().Expired != 2 {
			t.Fatal("duplicate traffic extended idle life")
		}
	})
}

func TestStoreCloseDuringSetupCannotPublishSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		block := make(chan struct{})
		reporter := &setupReporter{block: block}
		store, retained := storeFixture(t, reporter)
		_, hello := setupVector(t)
		result := make(chan error, 1)
		go func() {
			_, _, err := store.Open(context.Background(), hello)
			result <- err
		}()
		synctest.Wait()
		store.Close()
		if retained.Load() != 1 || reporter.calls.Load() != 1 {
			t.Fatal("unfinished setup lost its reservation")
		}
		close(block)
		if err := <-result; !errors.Is(err, ErrClosed) || retained.Load() != 0 || store.Diagnostics().Created != 0 {
			t.Fatalf("setup survived closing the store: %v", err)
		}
	})
}

func TestStoreFailedSetupReleasesReservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		block := make(chan struct{})
		reporter := &setupReporter{block: block}
		store, retained := storeFixture(t, reporter)
		if _, _, err := store.Open(context.Background(), []byte("invalid")); !errors.Is(err, ErrRecord) || retained.Load() != 0 || reporter.calls.Load() != 0 {
			t.Fatalf("malformed setup retained resources: %v", err)
		}
		_, hello := setupVector(t)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { _, _, err := store.Open(ctx, hello); result <- err }()
		synctest.Wait()
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) || retained.Load() != 0 || store.Diagnostics().Open != 0 {
			t.Fatalf("canceled setup retained session state: %v", err)
		}
		// The batcher still owns the dispatched report; its separate reservation
		// ends only when hardware returns. No session can be published afterward.
		close(block)
		if _, _, err := store.Open(ctx, hello); !errors.Is(err, context.Canceled) || retained.Load() != 0 {
			t.Fatalf("already canceled setup allocated state: %v", err)
		}
	})
}

func TestStoreConcurrentStartsAndCloseReleaseAllState(t *testing.T) {
	store, retained := storeFixture(t, &setupReporter{})
	id, root, initialPublic := openStoredSession(t, store)
	defer clear(root[:])
	start := make(chan struct{})
	var workers sync.WaitGroup
	for number := range uint64(64) {
		encoded := storedStart(t, root, id, initialPublic, number)
		workers.Go(func() {
			<-start
			request, metadata, err := store.AcceptStart(id, number, encoded)
			if err == nil {
				request.Close()
			} else if !errors.Is(err, ErrClosed) || request != nil || metadata != nil {
				t.Errorf("invalid concurrent outcome: %v", err)
			}
		})
	}
	workers.Go(func() { <-start; store.Close() })
	close(start)
	workers.Wait()
	if got := store.Diagnostics(); retained.Load() != 0 || got.Open != 0 || got.Retained != 0 || got.Active != 0 {
		t.Fatalf("concurrent cleanup leaked ownership: %+v", got)
	}
}

func TestStoreMaintenanceErasesSkippedKeysWithoutRetiringActiveSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store, _ := storeFixture(t, &setupReporter{})
		id, root, initialPublic := openStoredSession(t, store)
		request, _, err := store.AcceptStart(id, 2, storedStart(t, root, id, initialPublic, 2))
		if err != nil {
			t.Fatal(err)
		}
		defer request.Close()
		time.Sleep(SkippedKeyLifetime)
		store.ExpireIdle()
		if _, _, err = store.AcceptStart(id, 0, storedStart(t, root, id, initialPublic, 0)); !errors.Is(err, ErrReplay) {
			t.Fatal("maintenance retained expired key", err)
		}
		if got := store.Diagnostics(); got.Active != 1 || got.Open != 1 {
			t.Fatalf("skipped expiry changed active lifetime: %+v", got)
		}
		if _, err = request.Seal(Metadata, []byte("response")); err != nil {
			t.Fatal(err)
		}
	})
}
