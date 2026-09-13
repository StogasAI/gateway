// Package azureauth owns bounded, process-local Azure access tokens. Client
// secrets are used only for a cache miss and are never retained in cache entries.
package azureauth

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	maximumTokens        = 2048
	maximumLoads         = 8
	idleLifetime         = 5 * time.Minute
	cleanupInterval      = 15 * time.Second
	loadTimeout          = 15 * time.Second
	expiryMargin         = time.Minute
	maximumTokenBytes    = 16 << 10
	maximumResponseBytes = 1 << 20
)

var (
	ErrCredential  = errors.New("Azure credential rejected")
	ErrUnavailable = errors.New("Azure authentication unavailable")
)

type Credential struct {
	TenantID string
	ClientID string
	Secret   string
	Scope    string
}

type Diagnostics struct {
	Entries      int    `json:"entries"`
	Capacity     int    `json:"capacity"`
	InFlight     int    `json:"inFlight"`
	LoadCapacity int    `json:"loadCapacity"`
	Hits         uint64 `json:"hits"`
	Misses       uint64 `json:"misses"`
	Coalesced    uint64 `json:"coalesced"`
	Loads        uint64 `json:"loads"`
	Failures     uint64 `json:"failures"`
	Expired      uint64 `json:"expired"`
	Evicted      uint64 `json:"evicted"`
	Rejected     uint64 `json:"rejected"`
}

type fingerprint [sha256.Size]byte
type tokenEntry struct {
	key      fingerprint
	token    azcore.AccessToken
	lastUsed time.Time
}
type tokenLoad struct {
	done  chan struct{}
	token string
	err   error
}

type Cache struct {
	mu        sync.Mutex
	entries   map[fingerprint]*list.Element
	lru       list.List
	flights   map[fingerprint]*tokenLoad
	stats     Diagnostics
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closed    bool
	load      func(context.Context, Credential) (azcore.AccessToken, error)
	transport *http.Transport
}

func New(ctx context.Context) *Cache {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.MaxConnsPerHost = maximumLoads
	transport.MaxIdleConns = maximumLoads
	transport.MaxIdleConnsPerHost = maximumLoads
	transport.IdleConnTimeout = 30 * time.Second
	client := &http.Client{Transport: transport, Timeout: loadTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return ErrUnavailable
	}}
	c := newCache(ctx, func(ctx context.Context, credential Credential) (azcore.AccessToken, error) {
		auth, err := azidentity.NewClientSecretCredential(credential.TenantID, credential.ClientID, credential.Secret, &azidentity.ClientSecretCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Transport: boundedTransport{client},
				Retry:     policy.RetryOptions{MaxRetries: -1},
			},
		})
		if err != nil {
			return azcore.AccessToken{}, ErrCredential
		}
		token, err := auth.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{credential.Scope}})
		if err != nil {
			var rejected *azidentity.AuthenticationFailedError
			if errors.As(err, &rejected) && rejected.RawResponse != nil {
				switch rejected.RawResponse.StatusCode {
				case 400, 401, 403:
					return azcore.AccessToken{}, ErrCredential
				}
			}
			return azcore.AccessToken{}, ErrUnavailable
		}
		return token, nil
	})
	c.transport = transport
	return c
}

func newCache(ctx context.Context, loader func(context.Context, Credential) (azcore.AccessToken, error)) *Cache {
	ctx, cancel := context.WithCancel(ctx)
	c := &Cache{ctx: ctx, cancel: cancel, load: loader, entries: make(map[fingerprint]*list.Element), flights: make(map[fingerprint]*tokenLoad)}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.mu.Lock()
				for _, element := range c.entries {
					if expired(element.Value.(*tokenEntry), time.Now()) {
						c.remove(element)
						c.stats.Expired++
					}
				}
				c.mu.Unlock()
			}
		}
	}()
	return c
}

func (c *Cache) Token(ctx context.Context, credential Credential) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if c == nil {
		return "", ErrUnavailable
	}
	key := credentialFingerprint(credential)
	c.mu.Lock()
	if c.closed || c.ctx.Err() != nil {
		c.mu.Unlock()
		return "", ErrUnavailable
	}
	if element := c.entries[key]; element != nil {
		entry := element.Value.(*tokenEntry)
		if !expired(entry, time.Now()) {
			entry.lastUsed = time.Now()
			c.lru.MoveToFront(element)
			c.stats.Hits++
			token := entry.token.Token
			c.mu.Unlock()
			return token, nil
		}
		c.remove(element)
		c.stats.Expired++
	}
	c.stats.Misses++
	flight := c.flights[key]
	if flight != nil {
		c.stats.Coalesced++
	} else {
		if len(c.flights) >= maximumLoads {
			c.stats.Rejected++
			c.mu.Unlock()
			return "", ErrUnavailable
		}
		flight = &tokenLoad{done: make(chan struct{})}
		c.flights[key] = flight
		c.stats.Loads++
		c.wg.Add(1)
		go c.fetchToken(key, credential, flight)
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-flight.done:
		return flight.token, flight.err
	}
}

func (c *Cache) fetchToken(key fingerprint, credential Credential, flight *tokenLoad) {
	defer c.wg.Done()
	ctx, cancel := context.WithTimeout(c.ctx, loadTimeout)
	defer cancel()
	token, err := c.load(ctx, credential)
	now := time.Now()
	if err == nil && (token.Token == "" || len(token.Token) > maximumTokenBytes || !now.Add(expiryMargin).Before(token.ExpiresOn)) {
		err = ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil {
		err = ErrUnavailable
	}
	if err == nil {
		if len(c.entries) >= maximumTokens {
			c.remove(c.lru.Back())
			c.stats.Evicted++
		}
		entry := &tokenEntry{key: key, token: token, lastUsed: now}
		c.entries[key] = c.lru.PushFront(entry)
		flight.token = token.Token
	} else {
		c.stats.Failures++
		flight.err = err
	}
	delete(c.flights, key)
	close(flight.done)
}

func (c *Cache) remove(element *list.Element) {
	entry := element.Value.(*tokenEntry)
	delete(c.entries, entry.key)
	entry.token = azcore.AccessToken{}
	c.lru.Remove(element)
}

func expired(entry *tokenEntry, now time.Time) bool {
	return now.Sub(entry.lastUsed) >= idleLifetime || !now.Add(expiryMargin).Before(entry.token.ExpiresOn)
}

func (c *Cache) Diagnostics() Diagnostics {
	if c == nil {
		return Diagnostics{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	result := c.stats
	result.Entries, result.Capacity = len(c.entries), maximumTokens
	result.InFlight, result.LoadCapacity = len(c.flights), maximumLoads
	return result
}

func (c *Cache) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.cancel()
	for _, element := range c.entries {
		c.remove(element)
	}
	c.mu.Unlock()
	c.wg.Wait()
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

func credentialFingerprint(credential Credential) fingerprint {
	digest := sha256.New()
	for _, value := range []string{credential.TenantID, credential.ClientID, credential.Secret, credential.Scope} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(value))
	}
	var key fingerprint
	copy(key[:], digest.Sum(nil))
	return key
}

type boundedTransport struct{ client *http.Client }

func (t boundedTransport) Do(request *http.Request) (*http.Response, error) {
	response, err := t.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil || len(body) > maximumResponseBytes {
		return nil, ErrUnavailable
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}
