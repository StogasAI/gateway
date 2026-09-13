package chutese2ee

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"
)

func newCredentialTestTransport(t *testing.T) *Transport {
	t.Helper()
	transport, err := New(Options{
		APIKey:        "managed-key",
		APIBaseURL:    "http://provider.invalid",
		StreamTimeout: 10 * time.Minute,
		ResolveModel:  func(string) (ModelTarget, bool) { return testModelTarget, true },
	})
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func TestCredentialCleanupWithoutTrafficProtectsActiveRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newCredentialTestTransport(t)
		defer transport.Close()
		synctest.Wait()
		idle, releaseIdle, err := transport.acquireCredential("idle-key")
		if err != nil {
			t.Fatal(err)
		}
		active, releaseActive, err := transport.acquireCredential("active-key")
		if err != nil {
			t.Fatal(err)
		}
		releaseIdle()
		time.Sleep(credentialIdleLifetime - time.Second)
		synctest.Wait()
		if idle.api.apiKey == "" {
			t.Fatal("credential expired before idle lifetime")
		}
		releaseIdle() // Repeated release must not extend the idle lifetime.
		time.Sleep(time.Second)
		synctest.Wait()
		if idle.api.apiKey != "" {
			t.Fatal("idle secret retained without new traffic")
		}
		if active.api.apiKey == "" {
			t.Fatal("active credential expired")
		}
		if got := transport.Diagnostics().BYOKCredentialPools; got != 1 {
			t.Fatalf("credential pools = %d, want 1", got)
		}
		releaseActive()
		time.Sleep(credentialIdleLifetime + credentialCleanupInterval)
		synctest.Wait()
		if active.api.apiKey != "" {
			t.Fatal("released secret retained past idle lifetime")
		}
		if transport.managedCredential.api.apiKey == "" {
			t.Fatal("managed credential expired")
		}
	})
}

func TestCredentialLookupReplacesExpiredStateBeforeCleanup(t *testing.T) {
	transport := newCredentialTestTransport(t)
	defer transport.Close()
	old, release, err := transport.acquireCredential("customer-key")
	if err != nil {
		t.Fatal(err)
	}
	release()
	transport.credentialsMu.Lock()
	old.lastUsed = time.Now().Add(-credentialIdleLifetime)
	transport.credentialsMu.Unlock()
	current, releaseCurrent, err := transport.acquireCredential("customer-key")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseCurrent()
	if current == old || old.api.apiKey != "" {
		t.Fatal("expired credential was reused or its secret retained")
	}
}

func TestCredentialCapacityEvictsOnlyInactiveState(t *testing.T) {
	transport := newCredentialTestTransport(t)
	defer transport.Close()
	releases := make([]func(), 0, maximumCredentialPools)
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	var first *credentialState
	for index := range maximumCredentialPools {
		credential, release, err := transport.acquireCredential(fmt.Sprintf("customer-%d", index))
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			first = credential
		}
		releases = append(releases, release)
	}
	if _, _, err := transport.acquireCredential("overflow-key"); err != errCredentialUnavailable {
		t.Fatalf("full active cache returned %v", err)
	}
	releases[0]()
	_, release, err := transport.acquireCredential("overflow-key")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if first.api.apiKey != "" {
		t.Fatal("evicted credential secret retained")
	}
	if got := transport.Diagnostics().BYOKCredentialPools; got != maximumCredentialPools {
		t.Fatalf("credential pools = %d, want %d", got, maximumCredentialPools)
	}
}

func TestCredentialCloseWaitsForReleaseAndStopsCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newCredentialTestTransport(t)
		credential, release, err := transport.acquireCredential("active-key")
		if err != nil {
			t.Fatal(err)
		}
		closed := make(chan struct{})
		go func() { transport.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("close did not wait for active request")
		default:
		}
		if _, _, err := transport.acquireCredential("new-key"); err != errCredentialUnavailable {
			t.Fatalf("acquire during close returned %v", err)
		}
		release()
		<-closed
		<-transport.credentialCleanupDone
		transport.Close()
		if credential.api.apiKey != "" {
			t.Fatal("close retained provider secret")
		}
	})
}
