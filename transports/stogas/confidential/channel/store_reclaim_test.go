package channel

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestStoreRetiresClosedCryptoStateWithoutClosingAdmittedStreams(t *testing.T) {
	var retained atomic.Int64
	store, err := NewStore(newSetup(t, &setupReporter{}), func() (func(), bool) {
		retained.Add(1)
		return func() { retained.Add(-1) }, true
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, root, public := openStoredSession(t, store)
	request, _, err := store.AcceptStart(id, 0, storedStart(t, root, id, public, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	// The Rust owner reports Closed after exhausting its cryptographic budget.
	// Exercise that real boundary without a test-only limit or millions of calls.
	store.sessions[id].session.core.Close()
	if _, _, err := store.AcceptStart(id, 1, storedStart(t, root, id, public, 1)); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if stats := store.Diagnostics(); stats.Open != 0 || stats.Retained != 1 || stats.Active != 1 || retained.Load() != 1 {
		t.Fatalf("retirement released an admitted stream's reservation: %+v", stats)
	}
	if _, err := request.Seal(Metadata, []byte("response")); err != nil {
		t.Fatal(err)
	}
	request.Close()
	if retained.Load() != 0 || store.Diagnostics().Retained != 0 {
		t.Fatal("closed cryptographic session leaked its reservation")
	}
}

func TestStoreReclaimOrdersIdleSessionsAndProtectsOwnedState(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var retained atomic.Int64
		store, err := NewStore(newSetup(t, &setupReporter{}), func() (func(), bool) {
			retained.Add(1)
			return func() { retained.Add(-1) }, true
		})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		expired, _, _ := openStoredSession(t, store)
		time.Sleep(time.Duration(store.setup.idleSeconds) * time.Second)
		old, oldRoot, oldPublic := openStoredSession(t, store)
		active, root, initialPublic := openStoredSession(t, store)
		request, _, err := store.AcceptStart(active, 0, storedStart(t, root, active, initialPublic, 0))
		if err != nil {
			t.Fatal(err)
		}
		request2, _, err := store.AcceptStart(active, 1, storedStart(t, root, active, initialPublic, 1))
		if err != nil {
			t.Fatal(err)
		}
		defer request.Close()
		defer request2.Close()
		pinned, _, _ := openStoredSession(t, store)
		// Model the interval between pinning and first-record authentication.
		store.sessions[pinned].pins++
		time.Sleep(time.Minute)
		fresh, _, _ := openStoredSession(t, store)
		invalid := storedStart(t, oldRoot, old, oldPublic, 0)
		invalid[len(invalid)-1] ^= 1
		if _, _, err := store.AcceptStart(old, 0, invalid); !errors.Is(err, ErrAuthentication) {
			t.Fatal(err)
		}
		if store.ReclaimIdle(0) != 0 || store.ReclaimIdle(1) != 1 || store.sessions[expired] != nil || store.sessions[old] == nil {
			t.Fatal("expired sessions must be reclaimed before unused live sessions")
		}
		if store.ReclaimIdle(10) != 1 || store.sessions[old] != nil || store.sessions[active] == nil || store.sessions[pinned] == nil || store.sessions[fresh] == nil {
			t.Fatal("pressure must preserve active, authenticating and recently used sessions")
		}
		if _, err := request.Seal(Metadata, []byte("response")); err != nil {
			t.Fatal(err)
		}
		request.Close()
		if store.sessions[active].idle != nil {
			t.Fatal("one remaining request still owns the session")
		}
		request2.Close()
		if store.ReclaimIdle(10) != 0 {
			t.Fatal("completion must give the session its full reuse grace")
		}
		store.sessions[pinned].pins--
		if store.ReclaimIdle(10) != 1 {
			t.Fatal("failed authentication must not refresh an idle session")
		}
		time.Sleep(time.Minute)
		if store.ReclaimIdle(10) != 2 || retained.Load() != 0 || store.idle.Len() != 0 {
			t.Fatal("idle cleanup leaked memory or duplicate list entries")
		}
		if stats := store.Diagnostics(); stats.Expired != 1 || stats.Evicted != 4 || stats.Active != 0 || stats.Retained != 0 {
			t.Fatalf("unexpected pressure diagnostics: %+v", stats)
		}
	})
}

func TestStoreReclaimDoesNotWaitForAnotherLifecycleOperation(t *testing.T) {
	store, _ := storeFixture(t, &setupReporter{})
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.ReclaimIdle(1) != 0 {
		t.Fatal("reclamation must not wait or reenter the store")
	}
}

func TestStoreReclamationRacingWithStartsNeverDestroysAnAdmittedRequest(t *testing.T) {
	for range 10 {
		store, retained := storeFixture(t, &setupReporter{})
		id, root, initialPublic := openStoredSession(t, store)
		store.sessions[id].lastUsed = time.Now().Add(-time.Minute)
		start := make(chan struct{})
		var workers sync.WaitGroup
		for number := range uint64(16) {
			wire := storedStart(t, root, id, initialPublic, number)
			workers.Go(func() {
				<-start
				request, _, err := store.AcceptStart(id, number, wire)
				if errors.Is(err, ErrClosed) {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				if _, err = request.Seal(Metadata, []byte("response")); err != nil {
					t.Error("pressure destroyed active keys", err)
				}
				request.Close()
			})
		}
		workers.Go(func() { <-start; store.ReclaimIdle(1) })
		close(start)
		workers.Wait()
		store.Close()
		if retained.Load() != 0 || store.Diagnostics().Active != 0 {
			t.Fatal("racing pressure leaked ownership")
		}
	}
}
