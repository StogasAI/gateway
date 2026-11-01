package accesstoken

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
)

func TestCacheBoundsIsolationAndExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var loads atomic.Int64
		c := New(context.Background(), func(context.Context, []string) (Token, error) {
			return Token{Value: fmt.Sprint(loads.Add(1)), ExpiresAt: time.Now().Add(time.Hour)}, nil
		}, nil)
		defer c.Close()
		base := []string{"tenant", "client", "secret", "scope"}
		first, err := c.Token(context.Background(), base...)
		if err != nil {
			t.Fatal(err)
		}
		if token, err := c.Token(context.Background(), base...); err != nil || token != first {
			t.Fatal("cache miss")
		}
		for index := range base {
			changed := append([]string(nil), base...)
			changed[index] = "other"
			if token, err := c.Token(context.Background(), changed...); err != nil || token == first {
				t.Fatal("credential boundary crossed")
			}
		}
		// Length framing keeps parts from running together.
		if token, err := c.Token(context.Background(), "tenantclient", "", "secret", "scope"); err != nil || token == first {
			t.Fatal("credential boundary crossed")
		}
		for i := 0; i < maximumTokens+100; i++ {
			if _, err := c.Token(context.Background(), "tenant", "client", fmt.Sprint(i), "scope"); err != nil {
				t.Fatal(err)
			}
		}
		if stats := c.Diagnostics(); stats.Entries != maximumTokens || stats.Evicted != 106 || stats.Hits != 1 {
			t.Fatalf("bounds: %+v", stats)
		}
		time.Sleep(idleLifetime + cleanupInterval)
		synctest.Wait()
		if c.Diagnostics().Entries != 0 {
			t.Fatal("idle tokens retained")
		}
		c.Close()
		if _, err := c.Token(context.Background(), base...); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	})
}

func TestCacheLoadBoundsCancellationAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		c := New(context.Background(), func(ctx context.Context, _ []string) (Token, error) {
			select {
			case <-gate:
				return Token{Value: "token", ExpiresAt: time.Now().Add(time.Hour)}, nil
			case <-ctx.Done():
				return Token{}, ErrUnavailable
			}
		}, nil)
		defer c.Close()
		ctx, cancel := context.WithCancel(context.Background())
		first := make(chan error, 1)
		go func() { _, err := c.Token(ctx, "0"); first <- err }()
		synctest.Wait()
		second := make(chan error, 1)
		go func() { _, err := c.Token(context.Background(), "0"); second <- err }()
		for i := 1; i < maximumLoads; i++ {
			go func() { _, _ = c.Token(context.Background(), fmt.Sprint(i)) }()
		}
		synctest.Wait()
		if _, err := c.Token(context.Background(), "overflow"); !errors.Is(err, ErrUnavailable) {
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
		c := New(context.Background(), func(ctx context.Context, _ []string) (Token, error) {
			<-ctx.Done()
			return Token{}, ctx.Err()
		}, nil)
		go func() { _, _ = c.Token(context.Background()) }()
		synctest.Wait()
		c.Close()
		if c.Diagnostics().InFlight != 0 {
			t.Fatal("load survived close")
		}
	})
}

func TestCacheRejectsInvalidTokensAndDoesNotCacheErrors(t *testing.T) {
	for _, token := range []Token{
		{Value: "", ExpiresAt: time.Now().Add(time.Hour)},
		{Value: strings.Repeat("x", maximumTokenBytes+1), ExpiresAt: time.Now().Add(time.Hour)},
		{Value: "expired", ExpiresAt: time.Now()},
		{Value: "near-expiry", ExpiresAt: time.Now().Add(expiryMargin)},
	} {
		c := New(context.Background(), func(context.Context, []string) (Token, error) { return token, nil }, nil)
		if _, err := c.Token(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		if c.Diagnostics().Entries != 0 {
			t.Fatal("invalid token cached")
		}
		c.Close()
	}
	c := New(context.Background(), func(context.Context, []string) (Token, error) {
		return Token{}, ErrCredential
	}, nil)
	defer c.Close()
	for i := 0; i < 2; i++ {
		if _, err := c.Token(context.Background()); !errors.Is(err, ErrCredential) {
			t.Fatal(err)
		}
	}
	if c.Diagnostics().Loads != 2 {
		t.Fatal("error cached")
	}
}

func TestBoundedTransport(t *testing.T) {
	for _, size := range []int{16, MaximumResponseBytes, MaximumResponseBytes + 1} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", size))) }))
		request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		response, err := (BoundedTransport{server.Client()}).Do(request)
		server.Close()
		if size > MaximumResponseBytes {
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

// A retry must not wait on an HTTP/2 connection that stopped answering.
func TestSignInClientChecksItsHTTP2Connections(t *testing.T) {
	for _, postQuantum := range []bool{false, true} {
		client, transport := NewClient(postQuantum)
		if transport.HTTP2 == nil || transport.HTTP2.SendPingTimeout == 0 || client.CheckRedirect == nil {
			t.Fatal("the sign-in client does not check its HTTP/2 connections or follows redirects")
		}
		if postQuantum != (transport.TLSClientConfig.VerifyConnection != nil) {
			t.Fatal("post-quantum TLS is not enforced as configured")
		}
	}
}
