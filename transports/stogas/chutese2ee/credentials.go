package chutese2ee

import (
	"crypto/sha256"
	"errors"
	"strings"
	"time"
)

const (
	maximumChutesAPIKeyLength = 4096
	maximumCredentialPools    = 2048
	credentialIdleLifetime    = 5 * time.Minute
	credentialCleanupInterval = 15 * time.Second
)

var errCredentialUnavailable = errors.New("unavailable Chutes credential")

type credentialFingerprint [sha256.Size]byte

type credentialState struct {
	api         *apiClient
	pools       *poolState
	diagnostics *diagnostics
	lastUsed    time.Time
	active      int
}

func chutesAPIKeyFromAuthorization(value string) (string, error) {
	if len(value) <= len("Bearer ") || !strings.EqualFold(value[:len("Bearer")], "Bearer") || value[len("Bearer")] != ' ' {
		return "", errCredentialUnavailable
	}
	apiKey := value[len("Bearer "):]
	if err := validateChutesAPIKey(apiKey); err != nil {
		return "", err
	}
	return apiKey, nil
}

func validateChutesAPIKey(apiKey string) error {
	if apiKey == "" || len(apiKey) > maximumChutesAPIKeyLength {
		return errCredentialUnavailable
	}
	for index := 0; index < len(apiKey); index++ {
		if apiKey[index] < 0x21 || apiKey[index] > 0x7e {
			return errCredentialUnavailable
		}
	}
	return nil
}

func fingerprintCredential(apiKey string) credentialFingerprint {
	digest := sha256.New()
	_, _ = digest.Write([]byte("stogas.chutes-credential.v1\x00"))
	_, _ = digest.Write([]byte(apiKey))
	var fingerprint credentialFingerprint
	copy(fingerprint[:], digest.Sum(nil))
	return fingerprint
}

func (t *Transport) acquireCredential(apiKey string) (*credentialState, func(), error) {
	if t == nil || t.closed.Load() {
		return nil, nil, errCredentialUnavailable
	}
	fingerprint := fingerprintCredential(apiKey)
	now := time.Now()
	retired := make([]*credentialState, 0)

	t.credentialsMu.Lock()
	if t.closed.Load() {
		t.credentialsMu.Unlock()
		return nil, nil, errCredentialUnavailable
	}
	credential := t.managedCredential
	if fingerprint != t.managedFingerprint {
		credential = t.credentials[fingerprint]
		if credential != nil && credential.active == 0 && now.Sub(credential.lastUsed) >= credentialIdleLifetime {
			t.diagnostics.credentialExpired.Add(1)
			delete(t.credentials, fingerprint)
			retired = append(retired, credential)
			credential = nil
		}
		if credential == nil {
			t.diagnostics.credentialMisses.Add(1)
			if len(t.credentials) >= maximumCredentialPools {
				var oldestFingerprint credentialFingerprint
				var oldest *credentialState
				for candidateFingerprint, candidate := range t.credentials {
					if candidate.active == 0 && (oldest == nil || candidate.lastUsed.Before(oldest.lastUsed)) {
						oldestFingerprint = candidateFingerprint
						oldest = candidate
					}
				}
				if oldest == nil {
					t.diagnostics.credentialRejected.Add(1)
					t.credentialsMu.Unlock()
					closeCredentialStates(retired)
					return nil, nil, errCredentialUnavailable
				}
				delete(t.credentials, oldestFingerprint)
				t.diagnostics.credentialEvicted.Add(1)
				retired = append(retired, oldest)
			}
			api, err := t.api.withAPIKey(apiKey)
			if err != nil {
				t.credentialsMu.Unlock()
				closeCredentialStates(retired)
				return nil, nil, errCredentialUnavailable
			}
			credential = &credentialState{
				api:         api,
				pools:       newPoolState(api, t.attestor, t.diagnostics),
				diagnostics: t.diagnostics,
				lastUsed:    now,
			}
			t.credentials[fingerprint] = credential
		} else {
			t.diagnostics.credentialHits.Add(1)
		}
	}
	credential.active++
	credential.lastUsed = now
	t.credentialWG.Add(1)
	t.credentialsMu.Unlock()
	closeCredentialStates(retired)

	var released bool
	release := func() {
		t.credentialsMu.Lock()
		if !released {
			released = true
			credential.active--
			credential.lastUsed = time.Now()
			t.credentialWG.Done()
		}
		t.credentialsMu.Unlock()
	}
	return credential, release, nil
}

func (t *Transport) cleanupCredentials() {
	defer close(t.credentialCleanupDone)
	ticker := time.NewTicker(ticketWarmCheckInterval)
	defer ticker.Stop()
	nextCleanup := time.Now().Add(credentialCleanupInterval)
	for {
		select {
		case <-t.credentialCleanupStop:
			return
		case now := <-ticker.C:
			if !now.Before(nextCleanup) {
				t.expireCredentials()
				nextCleanup = now.Add(credentialCleanupInterval)
			}
			t.credentialsMu.Lock()
			pools := make([]*poolState, 0, len(t.credentials)+1)
			pools = append(pools, t.pools)
			for _, credential := range t.credentials {
				pools = append(pools, credential.pools)
			}
			t.credentialsMu.Unlock()
			for _, pool := range pools {
				if pool != nil {
					pool.maintain(now)
				}
			}
		}
	}
}

func (t *Transport) expireCredentials() {
	now := time.Now()
	var retired []*credentialState
	t.credentialsMu.Lock()
	for fingerprint, credential := range t.credentials {
		if credential.active == 0 && now.Sub(credential.lastUsed) >= credentialIdleLifetime {
			t.diagnostics.credentialExpired.Add(1)
			delete(t.credentials, fingerprint)
			retired = append(retired, credential)
		}
	}
	t.credentialsMu.Unlock()
	closeCredentialStates(retired)
}

func closeCredentialStates(credentials []*credentialState) {
	for _, credential := range credentials {
		if credential == nil {
			continue
		}
		if credential.pools != nil {
			credential.pools.close()
		}
		if credential.api != nil {
			credential.api.close()
		}
	}
}
