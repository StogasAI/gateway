// Package accesstoken keeps bounded, process-local upstream access tokens. A
// credential's secrets reach the loader only on a cache miss and are never
// retained in cache entries.
package accesstoken

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/http2health"
)

const (
	maximumTokens     = 2048
	maximumLoads      = 8
	idleLifetime      = 5 * time.Minute
	cleanupInterval   = 15 * time.Second
	loadTimeout       = 15 * time.Second
	expiryMargin      = time.Minute
	maximumTokenBytes = 16 << 10
	// MaximumResponseBytes bounds a sign-in response.
	MaximumResponseBytes = 1 << 20
)

var (
	// ErrCredential means the identity provider rejected the credential.
	ErrCredential = errors.New("upstream credential rejected")
	// ErrUnavailable means no token could be obtained for another reason.
	ErrUnavailable = errors.New("upstream sign-in unavailable")
)

// Token is an access token and the time it stops working.
type Token struct {
	Value     string
	ExpiresAt time.Time
}

// Loader exchanges one credential, given as its parts in a fixed order, for a
// token.
type Loader func(ctx context.Context, credential []string) (Token, error)

// Usable reports whether a token that a sign-in returned at now may be used:
// present, bounded, and valid for more than a minute.
func Usable(token Token, now time.Time) bool {
	return token.Value != "" && len(token.Value) <= maximumTokenBytes && now.Add(expiryMargin).Before(token.ExpiresAt)
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
	token    Token
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
	load      Loader
	transport *http.Transport
}

// NewClient returns the sign-in client a loader uses: bounded, without
// redirects, and checking its HTTP/2 connections. requirePostQuantumTLS
// accepts only TLS 1.3 with X25519MLKEM768.
func NewClient(requirePostQuantumTLS bool) (*http.Client, *http.Transport) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if requirePostQuantumTLS {
		transport.TLSClientConfig = &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
			VerifyConnection: func(state tls.ConnectionState) error {
				if state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 {
					return fmt.Errorf("sign-in TLS did not negotiate TLS 1.3 with X25519MLKEM768")
				}
				return nil
			},
		}
	}
	transport.MaxConnsPerHost = maximumLoads
	transport.MaxIdleConns = maximumLoads
	transport.MaxIdleConnsPerHost = maximumLoads
	transport.IdleConnTimeout = 30 * time.Second
	transport.HTTP2 = http2health.Config()
	client := &http.Client{Transport: transport, Timeout: loadTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return ErrUnavailable
	}}
	return client, transport
}

// New starts a cache that obtains tokens with load. transport, when set, is the
// sign-in transport whose idle connections close with the cache.
func New(ctx context.Context, load Loader, transport *http.Transport) *Cache {
	ctx, cancel := context.WithCancel(ctx)
	c := &Cache{ctx: ctx, cancel: cancel, load: load, transport: transport, entries: make(map[fingerprint]*list.Element), flights: make(map[fingerprint]*tokenLoad)}
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

// Token returns a token for the credential whose parts are given, loading one
// on a miss. Every part, secrets included, distinguishes cache entries.
func (c *Cache) Token(ctx context.Context, credential ...string) (string, error) {
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
			token := entry.token.Value
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

func (c *Cache) fetchToken(key fingerprint, credential []string, flight *tokenLoad) {
	defer c.wg.Done()
	ctx, cancel := context.WithTimeout(c.ctx, loadTimeout)
	defer cancel()
	token, err := c.load(ctx, credential)
	now := time.Now()
	if err == nil && !Usable(token, now) {
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
		flight.token = token.Value
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
	entry.token = Token{}
	c.lru.Remove(element)
}

func expired(entry *tokenEntry, now time.Time) bool {
	return now.Sub(entry.lastUsed) >= idleLifetime || !now.Add(expiryMargin).Before(entry.token.ExpiresAt)
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

func credentialFingerprint(credential []string) fingerprint {
	digest := sha256.New()
	for _, value := range credential {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(value))
	}
	var key fingerprint
	copy(key[:], digest.Sum(nil))
	return key
}

// ReadBounded reads a sign-in response body up to MaximumResponseBytes.
func ReadBounded(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, MaximumResponseBytes+1))
	if err != nil || len(data) > MaximumResponseBytes {
		return nil, ErrUnavailable
	}
	return data, nil
}

// BoundedTransport buffers each response up to MaximumResponseBytes, for SDKs
// that read sign-in responses themselves.
type BoundedTransport struct{ Client *http.Client }

func (t BoundedTransport) Do(request *http.Request) (*http.Response, error) {
	response, err := t.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ReadBounded(response.Body)
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}
