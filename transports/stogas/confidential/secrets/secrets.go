package secrets

import (
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	"github.com/maximhq/bifrost/transports/stogas/confidential/provision"
)

const (
	hpkeInfo              = "stogas.secret-release.v1"
	hpkeEncapsulationSize = 1_120
	hpkeTagSize           = 16
)

var (
	ErrInvalidReleaseContents = errors.New("confidential secret release contents are invalid")
	ErrInvalidReleaseEncoding = errors.New("confidential secret release encoding is invalid")
	ErrInvalidReleaseIdentity = errors.New("confidential secret release identity is invalid")
	ErrReleaseAuthentication  = errors.New("confidential secret release authentication failed")
	ErrReleaseBindingMismatch = errors.New("confidential secret release binding mismatch")
)

type Store struct {
	mu      sync.RWMutex
	secrets map[string]Secret
}

type Secret struct {
	KeyID   string
	Name    string
	Value   []byte
	Version string
}

type InstallInput struct {
	Bundle   *provision.SecretBundle
	Identity *identity.Material
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

func (s *Store) Install(input InstallInput) error {
	if s == nil {
		return fmt.Errorf("%w: secret store is nil", ErrInvalidReleaseContents)
	}
	secrets, err := DecryptRelease(input)
	if err != nil {
		return err
	}
	next := make(map[string]Secret, len(secrets))
	for _, secret := range secrets {
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
	if len(s.secrets) > 0 {
		return fmt.Errorf("%w: runtime configuration is already installed; replace the guest to apply changes", ErrInvalidReleaseContents)
	}
	s.secrets = next
	return nil
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

func DecryptRelease(input InstallInput) ([]Secret, error) {
	if input.Identity == nil || input.Identity.HPKEPrivateKey == nil {
		return nil, fmt.Errorf("%w: identity HPKE private key is required", ErrInvalidReleaseIdentity)
	}
	if input.Bundle == nil {
		return nil, fmt.Errorf("%w: secret release is required", ErrInvalidReleaseContents)
	}
	out := make([]Secret, 0, len(input.Bundle.Secrets))
	for _, encrypted := range input.Bundle.Secrets {
		aad, err := secretReleaseAAD(input.Bundle, encrypted)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrReleaseBindingMismatch, err)
		}
		sum := sha256.Sum256(aad)
		if hex.EncodeToString(sum[:]) != encrypted.AADSHA256 {
			return nil, fmt.Errorf("%w: secret %s AAD hash mismatch", ErrReleaseBindingMismatch, encrypted.Name)
		}
		plaintext, err := decryptSecret(input.Identity.HPKEPrivateKey, encrypted, aad)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret %s: %w", encrypted.Name, err)
		}
		out = append(out, Secret{
			KeyID:   encrypted.KeyID,
			Name:    encrypted.Name,
			Value:   plaintext,
			Version: encrypted.Version,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: secret release contained no secrets", ErrInvalidReleaseContents)
	}
	return out, nil
}

func decryptSecret(privateKey hpke.PrivateKey, encrypted provision.SecretCiphertext, aad []byte) ([]byte, error) {
	encapsulated, err := base64.RawURLEncoding.Strict().DecodeString(encrypted.EncapsulatedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: decode encapsulated key: %w", ErrInvalidReleaseEncoding, err)
	}
	if len(encapsulated) != hpkeEncapsulationSize {
		return nil, fmt.Errorf("%w: encapsulated key has an invalid length", ErrInvalidReleaseEncoding)
	}
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(encrypted.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: decode ciphertext: %w", ErrInvalidReleaseEncoding, err)
	}
	if len(ciphertext) < hpkeTagSize {
		return nil, fmt.Errorf("%w: ciphertext is too short", ErrInvalidReleaseEncoding)
	}
	recipient, err := hpke.NewRecipient(
		encapsulated,
		privateKey,
		hpke.HKDFSHA256(),
		hpke.AES256GCM(),
		[]byte(hpkeInfo),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize HPKE recipient: %w", ErrInvalidReleaseEncoding, err)
	}
	plaintext, err := recipient.Open(aad, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: HPKE ciphertext authentication failed", ErrReleaseAuthentication)
	}
	return plaintext, nil
}

func secretReleaseAAD(bundle *provision.SecretBundle, secret provision.SecretCiphertext) ([]byte, error) {
	payload := struct {
		NodeID           string `json:"node_id"`
		ReportDataSHA512 string `json:"report_data_sha512"`
		Schema           string `json:"schema"`
		SecretKeyID      string `json:"secret_key_id"`
		SecretName       string `json:"secret_name"`
		SecretVersion    string `json:"secret_version"`
	}{
		NodeID:           bundle.NodeID,
		ReportDataSHA512: bundle.ReportDataSHA512,
		Schema:           provision.SecretReleaseSchemaV1,
		SecretKeyID:      secret.KeyID,
		SecretName:       secret.Name,
		SecretVersion:    secret.Version,
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
