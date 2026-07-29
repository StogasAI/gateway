package catalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	defaultPollInterval = 5 * time.Minute
	manifestSizeLimit   = 64 * 1024
)

var catalogSignatureDomain = []byte("stogas catalog release v2\n")

//go:embed trust/catalog-signing-keys.json
var trustedKeyJSON []byte

type UpdaterConfig struct {
	ReleaseURL     string
	PollInterval   time.Duration
	HTTPClient     *http.Client
	RequireInitial bool
}

type UpdateStatus struct {
	Active              Identity  `json:"active"`
	CheckedAt           time.Time `json:"checkedAt"`
	ConsecutiveFailures uint64    `json:"consecutiveFailures"`
	LastError           string    `json:"lastError,omitempty"`
	LastSuccess         time.Time `json:"lastSuccess,omitempty"`
}

type Updater struct {
	cancel context.CancelFunc
	client *http.Client
	config UpdaterConfig
	etag   string
	keys   map[string]ed25519.PublicKey
	mu     sync.RWMutex
	status UpdateStatus
}

func StartUpdater(parent context.Context, config UpdaterConfig) (*Updater, error) {
	config.ReleaseURL = strings.TrimSpace(config.ReleaseURL)
	if config.ReleaseURL == "" {
		return nil, nil
	}
	releaseURL, err := url.Parse(config.ReleaseURL)
	if err != nil || releaseURL.Scheme != "https" || releaseURL.Host == "" {
		return nil, fmt.Errorf("catalog release URL must be absolute HTTPS")
	}
	keys, err := trustedKeys()
	if err != nil {
		return nil, err
	}
	if config.PollInterval <= 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	ctx, cancel := context.WithCancel(parent)
	updater := &Updater{
		cancel: cancel,
		client: config.HTTPClient,
		config: config,
		keys:   keys,
	}
	if identity, ok := ActiveIdentity(); ok {
		updater.status.Active = identity
	}
	initiallyPolled := false
	if config.RequireInitial {
		now := time.Now().UTC()
		err := updater.pollOnce(ctx)
		updater.recordPoll(now, err)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("load initial signed catalog: %w", err)
		}
		initiallyPolled = true
	}
	go updater.run(ctx, initiallyPolled)
	return updater, nil
}

func (u *Updater) Close() {
	if u != nil && u.cancel != nil {
		u.cancel()
	}
}

func (u *Updater) Status() UpdateStatus {
	if u == nil {
		identity, _ := ActiveIdentity()
		return UpdateStatus{Active: identity}
	}
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.status
}

func (u *Updater) Ready(now time.Time) (bool, string) {
	if u == nil {
		return true, ""
	}
	status := u.Status()
	if status.Active.Sequence == 0 || status.Active.Digest == "" || status.LastSuccess.IsZero() {
		return false, "catalog_unavailable"
	}
	interval := u.config.PollInterval
	if interval <= 0 {
		interval = defaultPollInterval
	}
	if !status.CheckedAt.IsZero() && now.Sub(status.CheckedAt) > 2*interval {
		return false, "catalog_poll_stalled"
	}
	if status.ConsecutiveFailures >= 3 && now.Sub(status.LastSuccess) > 3*interval {
		return false, "catalog_refresh_failing"
	}
	return true, ""
}

func (u *Updater) run(ctx context.Context, initiallyPolled bool) {
	if initiallyPolled && !waitForPoll(ctx, u.config.PollInterval) {
		return
	}
	for {
		u.poll(ctx)
		if !waitForPoll(ctx, u.config.PollInterval) {
			return
		}
	}
}

func (u *Updater) poll(ctx context.Context) {
	checkedAt := time.Now().UTC()
	err := u.pollOnce(ctx)
	u.recordPoll(checkedAt, err)
}

func (u *Updater) recordPoll(checkedAt time.Time, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status.CheckedAt = checkedAt
	if err != nil {
		u.status.ConsecutiveFailures++
		u.status.LastError = err.Error()
		return
	}
	u.status.ConsecutiveFailures = 0
	u.status.LastError = ""
	u.status.LastSuccess = checkedAt
	if identity, ok := ActiveIdentity(); ok {
		u.status.Active = identity
	}
}

func (u *Updater) pollOnce(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.config.ReleaseURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if u.etag != "" {
		request.Header.Set("If-None-Match", u.etag)
	}
	response, err := u.client.Do(request)
	if err != nil {
		return fmt.Errorf("fetch catalog release: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return nil
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch catalog release: unexpected HTTP %d", response.StatusCode)
	}
	envelopeBytes, err := readLimited(response.Body, manifestSizeLimit)
	if err != nil {
		return fmt.Errorf("read catalog release: %w", err)
	}
	manifest, err := verifyEnvelope(envelopeBytes, u.keys)
	if err != nil {
		return err
	}
	if current, ok := ActiveIdentity(); ok && manifest.Sequence <= current.Sequence {
		if manifest.Sequence == current.Sequence && manifest.Runtime == current.Digest {
			if snapshot := active.Load(); snapshot != nil && snapshot.publicDigest == manifest.Public {
				u.etag = response.Header.Get("ETag")
				return nil
			}
			return fmt.Errorf("catalog sequence %d is bound to different public content", manifest.Sequence)
		}
		return fmt.Errorf("catalog sequence %d does not advance active sequence %d", manifest.Sequence, current.Sequence)
	}
	runtimeData, err := u.fetchArtifact(ctx, manifest.Runtime, runtimeSizeLimit)
	if err != nil {
		return fmt.Errorf("fetch runtime catalog: %w", err)
	}
	publicData, err := u.fetchArtifact(ctx, manifest.Public, publicSizeLimit)
	if err != nil {
		return fmt.Errorf("fetch public catalog: %w", err)
	}
	candidate, err := snapshotFromRelease(runtimeData, publicData, Identity{
		Sequence: manifest.Sequence,
		Digest:   manifest.Runtime,
	})
	if err != nil {
		return fmt.Errorf("validate catalog candidate: %w", err)
	}
	activationMu.Lock()
	defer activationMu.Unlock()
	if current := active.Load(); current != nil && candidate.identity.Sequence <= current.identity.Sequence {
		return fmt.Errorf("catalog candidate became stale before activation")
	}
	active.Store(candidate)
	u.etag = response.Header.Get("ETag")
	return nil
}

func (u *Updater) fetchArtifact(ctx context.Context, digestValue string, limit int64) ([]byte, error) {
	digest, err := parseSHA256(digestValue)
	if err != nil {
		return nil, err
	}
	releaseURL, _ := url.Parse(u.config.ReleaseURL)
	artifactURL := *releaseURL
	artifactURL.Path = path.Join(path.Dir(releaseURL.Path), "blobs/sha256", hex.EncodeToString(digest)+".json")
	artifactURL.RawQuery = ""
	artifactURL.Fragment = ""

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifactURL.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := u.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP %d", response.StatusCode)
	}
	data, err := readLimited(response.Body, limit)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if !bytes.Equal(sum[:], digest) {
		return nil, fmt.Errorf("artifact digest does not match the signed manifest")
	}
	return data, nil
}

func verifyEnvelope(data []byte, keys map[string]ed25519.PublicKey) (releaseManifest, error) {
	var envelope struct {
		Schema    string          `json:"schema"`
		KeyID     string          `json:"keyId"`
		Manifest  json.RawMessage `json:"manifest"`
		Signature string          `json:"signature"`
	}
	if err := decodeStrict(data, &envelope); err != nil {
		return releaseManifest{}, fmt.Errorf("decode signed catalog manifest: %w", err)
	}
	if envelope.Schema != "stogas.catalog.signed.v2" {
		return releaseManifest{}, fmt.Errorf("catalog signature envelope is unsupported")
	}
	key, ok := keys[envelope.KeyID]
	if !ok {
		return releaseManifest{}, fmt.Errorf("catalog signing key %q is not trusted", envelope.KeyID)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	payload := make([]byte, 0, len(catalogSignatureDomain)+len(envelope.Manifest))
	payload = append(payload, catalogSignatureDomain...)
	payload = append(payload, envelope.Manifest...)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return releaseManifest{}, fmt.Errorf("catalog manifest signature is invalid")
	}
	manifest := releaseManifest{}
	if err := decodeStrict(envelope.Manifest, &manifest); err != nil {
		return releaseManifest{}, fmt.Errorf("decode catalog manifest: %w", err)
	}
	if manifest.Schema != "stogas.catalog.release.v2" ||
		manifest.Sequence == 0 ||
		manifest.CatalogSchema != catalogSchema {
		return releaseManifest{}, fmt.Errorf("catalog manifest is unsupported")
	}
	if _, err := parseSHA256(manifest.Runtime); err != nil {
		return releaseManifest{}, fmt.Errorf("catalog runtime digest is invalid")
	}
	if _, err := parseSHA256(manifest.Public); err != nil {
		return releaseManifest{}, fmt.Errorf("catalog public digest is invalid")
	}
	return manifest, nil
}

func trustedKeys() (map[string]ed25519.PublicKey, error) {
	encoded := map[string]string{}
	if err := decodeStrict(trustedKeyJSON, &encoded); err != nil {
		return nil, fmt.Errorf("decode trusted catalog keys: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for id, value := range encoded {
		der, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("trusted catalog key %q is invalid", id)
		}
		publicKey, err := x509.ParsePKIXPublicKey(der)
		key, ok := publicKey.(ed25519.PublicKey)
		if err != nil || !ok || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted catalog key %q is invalid", id)
		}
		keys[id] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("no catalog signing keys are trusted")
	}
	return keys, nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

func parseSHA256(value string) ([]byte, error) {
	raw := strings.TrimPrefix(value, "sha256:")
	if len(raw) != sha256.Size*2 || raw == value {
		return nil, fmt.Errorf("digest must be a sha256 value")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("digest must be lowercase hexadecimal")
	}
	if hex.EncodeToString(decoded) != raw {
		return nil, fmt.Errorf("digest must be lowercase hexadecimal")
	}
	return decoded, nil
}

func jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return defaultPollInterval
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return base
	}
	fraction := float64(binary.LittleEndian.Uint64(raw[:])) / float64(^uint64(0))
	return time.Duration(float64(base) * (0.8 + fraction*0.4))
}

func waitForPoll(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(jitter(interval))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
