package azureauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

func TestCacheBoundsIsolationAndExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var loads atomic.Int64
		c := newCache(context.Background(), func(context.Context, Credential) (azcore.AccessToken, error) {
			return azcore.AccessToken{Token: fmt.Sprint(loads.Add(1)), ExpiresOn: time.Now().Add(time.Hour)}, nil
		})
		defer c.Close()
		base := Credential{TenantID: "tenant", ClientID: "client", Secret: "secret", Scope: "scope"}
		first, err := c.Token(context.Background(), base)
		if err != nil {
			t.Fatal(err)
		}
		if token, err := c.Token(context.Background(), base); err != nil || token != first {
			t.Fatal("cache miss")
		}
		for _, changed := range []Credential{
			{TenantID: "other", ClientID: base.ClientID, Secret: base.Secret, Scope: base.Scope},
			{TenantID: base.TenantID, ClientID: "other", Secret: base.Secret, Scope: base.Scope},
			{TenantID: base.TenantID, ClientID: base.ClientID, Secret: "other", Scope: base.Scope},
			{TenantID: base.TenantID, ClientID: base.ClientID, Secret: base.Secret, Scope: "other"},
		} {
			if token, err := c.Token(context.Background(), changed); err != nil || token == first {
				t.Fatal("credential boundary crossed")
			}
		}
		for i := 0; i < maximumTokens+100; i++ {
			credential := base
			credential.Secret = fmt.Sprint(i)
			if _, err := c.Token(context.Background(), credential); err != nil {
				t.Fatal(err)
			}
		}
		if stats := c.Diagnostics(); stats.Entries != maximumTokens || stats.Evicted != 105 || stats.Hits != 1 {
			t.Fatalf("bounds: %+v", stats)
		}
		time.Sleep(idleLifetime + cleanupInterval)
		synctest.Wait()
		if c.Diagnostics().Entries != 0 {
			t.Fatal("idle tokens retained")
		}
		c.Close()
		if _, err := c.Token(context.Background(), base); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	})
}

func TestCacheLoadBoundsCancellationAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		c := newCache(context.Background(), func(ctx context.Context, _ Credential) (azcore.AccessToken, error) {
			select {
			case <-gate:
				return azcore.AccessToken{Token: "token", ExpiresOn: time.Now().Add(time.Hour)}, nil
			case <-ctx.Done():
				return azcore.AccessToken{}, ErrUnavailable
			}
		})
		defer c.Close()
		ctx, cancel := context.WithCancel(context.Background())
		first := make(chan error, 1)
		go func() { _, err := c.Token(ctx, Credential{Secret: "0"}); first <- err }()
		synctest.Wait()
		second := make(chan error, 1)
		go func() { _, err := c.Token(context.Background(), Credential{Secret: "0"}); second <- err }()
		for i := 1; i < maximumLoads; i++ {
			go func() { _, _ = c.Token(context.Background(), Credential{Secret: fmt.Sprint(i)}) }()
		}
		synctest.Wait()
		if _, err := c.Token(context.Background(), Credential{Secret: "overflow"}); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		cancel()
		if err := <-first; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		close(gate)
		if err := <-second; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if stats := c.Diagnostics(); stats.Loads != maximumLoads || stats.Coalesced != 1 || stats.Rejected != 1 || stats.InFlight != 0 {
			t.Fatalf("stats: %+v", stats)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		c := newCache(context.Background(), func(ctx context.Context, _ Credential) (azcore.AccessToken, error) {
			<-ctx.Done()
			return azcore.AccessToken{}, ctx.Err()
		})
		go func() { _, _ = c.Token(context.Background(), Credential{}) }()
		synctest.Wait()
		c.Close()
		if c.Diagnostics().InFlight != 0 {
			t.Fatal("load survived close")
		}
	})
}

func TestCacheRejectsInvalidTokensAndDoesNotCacheErrors(t *testing.T) {
	for _, token := range []azcore.AccessToken{
		{Token: "", ExpiresOn: time.Now().Add(time.Hour)},
		{Token: strings.Repeat("x", maximumTokenBytes+1), ExpiresOn: time.Now().Add(time.Hour)},
		{Token: "expired", ExpiresOn: time.Now()},
		{Token: "near-expiry", ExpiresOn: time.Now().Add(expiryMargin)},
	} {
		c := newCache(context.Background(), func(context.Context, Credential) (azcore.AccessToken, error) { return token, nil })
		if _, err := c.Token(context.Background(), Credential{}); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		if c.Diagnostics().Entries != 0 {
			t.Fatal("invalid token cached")
		}
		c.Close()
	}
	c := newCache(context.Background(), func(context.Context, Credential) (azcore.AccessToken, error) {
		return azcore.AccessToken{}, ErrCredential
	})
	defer c.Close()
	for i := 0; i < 2; i++ {
		if _, err := c.Token(context.Background(), Credential{}); !errors.Is(err, ErrCredential) {
			t.Fatal(err)
		}
	}
	if c.Diagnostics().Loads != 2 {
		t.Fatal("error cached")
	}
}

func TestBoundedTransport(t *testing.T) {
	for _, size := range []int{16, maximumResponseBytes, maximumResponseBytes + 1} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", size))) }))
		request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		response, err := (boundedTransport{server.Client()}).Do(request)
		server.Close()
		if size > maximumResponseBytes {
			if !errors.Is(err, ErrUnavailable) {
				t.Fatal(err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
		}
	}
}
