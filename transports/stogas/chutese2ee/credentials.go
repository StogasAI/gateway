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
)

var errCredentialUnavailable = errors.New("Chutes credential is unavailable")

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
	for existingFingerprint, existing := range t.credentials {
		if existing.active == 0 && now.Sub(existing.lastUsed) >= credentialIdleLifetime {
			delete(t.credentials, existingFingerprint)
			retired = append(retired, existing)
		}
	}

	credential := t.managedCredential
	if fingerprint != t.managedFingerprint {
		credential = t.credentials[fingerprint]
		if credential == nil {
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
					t.credentialsMu.Unlock()
					closeCredentialStates(retired)
					return nil, nil, errCredentialUnavailable
				}
				delete(t.credentials, oldestFingerprint)
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
