package secrets

import (
	"errors"
	"fmt"
	"github.com/maximhq/bifrost/transports/stogas/confidential/provision"
	"sync"
)

var ErrInvalidReleaseContents = errors.New("confidential secret release contents are invalid")

type Store struct {
	mu      sync.RWMutex
	secrets map[string]Secret
	closed  bool
}

type Secret struct {
	KeyID   string
	Name    string
	Value   []byte
	Version string
}

var requiredSecretNames = []string{
	"CHUTES_API_KEY",
	"API_KEY_PEPPER",
	"BYOK_ENCRYPTION_SECRET",
	"DATABASE_SCHEMA",
	"DATABASE_URL",
	"INFERENCE_TOKEN_PUBLIC_KEY",
}

func NewStore() *Store {
	return &Store{secrets: map[string]Secret{}}
}

// InstallBoot consumes authenticated provisioning contents exactly once.
// Renewal never calls this method; changing runtime secrets requires a new boot.
func (s *Store) InstallBoot(values []provision.BootSecretValue) error {
	secrets := make([]Secret, 0, len(values))
	for _, value := range values {
		secrets = append(secrets, Secret{KeyID: value.KeyID, Name: value.Name, Value: []byte(value.Plaintext), Version: value.Version})
	}
	return s.install(secrets)
}

func (s *Store) install(secrets []Secret) error {
	installed := false
	defer func() {
		if !installed {
			for _, secret := range secrets {
				clear(secret.Value)
			}
		}
	}()
	if s == nil {
		return fmt.Errorf("%w: secret store is nil", ErrInvalidReleaseContents)
	}
	next := make(map[string]Secret, len(secrets))
	for _, secret := range secrets {
		if secret.Name == "" || secret.KeyID == "" || secret.Version == "" || len(secret.Value) == 0 {
			return ErrInvalidReleaseContents
		}
		if _, exists := next[secret.Name]; exists {
			return fmt.Errorf("%w: secret release contains duplicate secret %s", ErrInvalidReleaseContents, secret.Name)
		}
		next[secret.Name] = secret
	}
	for _, name := range requiredSecretNames {
		if _, ok := next[name]; !ok {
			return fmt.Errorf("%w: secret release is missing required secret %s", ErrInvalidReleaseContents, name)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.secrets) > 0 {
		return fmt.Errorf("%w: runtime configuration is already installed; replace the guest to apply changes", ErrInvalidReleaseContents)
	}
	s.secrets = next
	installed = true
	return nil
}

// Close erases owned plaintext after request processing and finalization finish.
func (s *Store) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, secret := range s.secrets {
		clear(secret.Value)
	}
	s.secrets = nil
	s.closed = true
}

func (s *Store) Ready() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, name := range requiredSecretNames {
		if _, ok := s.secrets[name]; !ok {
			return false
		}
	}
	return true
}

func (s *Store) Versions() map[string]string {
	versions := map[string]string{}
	if s == nil {
		return versions
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for name, secret := range s.secrets {
		versions[name] = secret.Version
	}
	return versions
}

func (s *Store) Get(name string) (Secret, bool) {
	if s == nil {
		return Secret{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	secret, ok := s.secrets[name]
	if !ok {
		return Secret{}, false
	}
	secret.Value = append([]byte(nil), secret.Value...)
	return secret, true
}
