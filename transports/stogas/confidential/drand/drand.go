package drand

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
)

const DefaultQuicknetLatestURL = "https://api.drand.sh/v2/beacons/quicknet/rounds/latest"

type Fetcher interface {
	Fetch(ctx context.Context) (reportdata.Drand, error)
}

type FetcherFunc func(ctx context.Context) (reportdata.Drand, error)

func (f FetcherFunc) Fetch(ctx context.Context) (reportdata.Drand, error) {
	return f(ctx)
}

type SignatureVerifier interface {
	Verify(ctx context.Context, beacon reportdata.Drand) error
}

type SignatureVerifierFunc func(ctx context.Context, beacon reportdata.Drand) error

func (f SignatureVerifierFunc) Verify(ctx context.Context, beacon reportdata.Drand) error {
	return f(ctx, beacon)
}

type HTTPFetcher struct {
	client *http.Client
	url    string
}

func NewHTTPFetcher(client *http.Client, url string) *HTTPFetcher {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.TrimSpace(url) == "" {
		url = DefaultQuicknetLatestURL
	}
	return &HTTPFetcher{client: client, url: url}
}

func (f *HTTPFetcher) Fetch(ctx context.Context) (reportdata.Drand, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return reportdata.Drand{}, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := f.client.Do(req)
	if err != nil {
		return reportdata.Drand{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return reportdata.Drand{}, fmt.Errorf("drand fetch failed with status %d", res.StatusCode)
	}
	var body struct {
		Randomness string `json:"randomness"`
		Round      uint64 `json:"round"`
		Signature  string `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil {
		return reportdata.Drand{}, err
	}
	randomness := body.Randomness
	if randomness == "" {
		randomness, err = RandomnessFromSignature(body.Signature)
		if err != nil {
			return reportdata.Drand{}, err
		}
	}
	return reportdata.Drand{
		Network:    reportdata.DrandNetworkQuicknet,
		ChainHash:  reportdata.QuicknetChainHash,
		Round:      body.Round,
		Randomness: randomness,
		Signature:  body.Signature,
	}, nil
}

type Source struct {
	fetcher  Fetcher
	verifier SignatureVerifier

	mu      sync.RWMutex
	current *reportdata.Drand
	lastErr error
}

func NewSource(fetcher Fetcher, verifier SignatureVerifier) (*Source, error) {
	if fetcher == nil {
		return nil, errors.New("drand fetcher is required")
	}
	if verifier == nil {
		return nil, errors.New("drand signature verifier is required")
	}
	return &Source{fetcher: fetcher, verifier: verifier}, nil
}

func (s *Source) Current(ctx context.Context) (reportdata.Drand, error) {
	s.mu.RLock()
	current := clone(s.current)
	lastErr := s.lastErr
	s.mu.RUnlock()
	if current != nil {
		return *current, nil
	}
	if err := s.Refresh(ctx); err != nil {
		return reportdata.Drand{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		if s.lastErr != nil {
			return reportdata.Drand{}, s.lastErr
		}
		return reportdata.Drand{}, lastErr
	}
	return *clone(s.current), nil
}

func (s *Source) Refresh(ctx context.Context) error {
	beacon, err := s.fetcher.Fetch(ctx)
	if err != nil {
		s.recordErr(err)
		return err
	}
	if err := Validate(beacon); err != nil {
		s.recordErr(err)
		return err
	}

	s.mu.RLock()
	current := clone(s.current)
	s.mu.RUnlock()
	if current != nil && beacon.Round < current.Round {
		err := fmt.Errorf("drand round replayed older than last accepted round")
		s.recordErr(err)
		return err
	}

	if err := s.verifier.Verify(ctx, beacon); err != nil {
		err = fmt.Errorf("drand signature verification failed: %w", err)
		s.recordErr(err)
		return err
	}

	s.mu.Lock()
	next := beacon
	s.current = &next
	s.lastErr = nil
	s.mu.Unlock()
	return nil
}

func (s *Source) LastError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastErr
}

func Validate(beacon reportdata.Drand) error {
	if beacon.Network != reportdata.DrandNetworkQuicknet {
		return fmt.Errorf("unsupported drand network %q", beacon.Network)
	}
	if beacon.ChainHash != reportdata.QuicknetChainHash {
		return errors.New("unexpected drand quicknet chain hash")
	}
	if beacon.Round == 0 {
		return errors.New("drand round is required")
	}
	if err := validHex("drand.randomness", beacon.Randomness); err != nil {
		return err
	}
	if err := validHex("drand.signature", beacon.Signature); err != nil {
		return err
	}
	return nil
}

func RandomnessFromSignature(signatureHex string) (string, error) {
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return "", fmt.Errorf("drand.signature must be hex: %w", err)
	}
	sum := sha256.Sum256(signature)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Source) recordErr(err error) {
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
}

func clone(beacon *reportdata.Drand) *reportdata.Drand {
	if beacon == nil {
		return nil
	}
	out := *beacon
	return &out
}

func validHex(name string, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s must be hex: %w", name, err)
	}
	return nil
}
