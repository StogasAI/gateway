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
	"ANTHROPIC_API_KEY",
	"API_KEY_PEPPER",
	"BYOK_ENCRYPTION_SECRET",
	"DATABASE_SCHEMA",
	"DATABASE_URL",
	"INFERENCE_TOKEN_PUBLIC_KEY",
	"OPENAI_API_KEY",
}

func NewStore() *Store {
	return &Store{secrets: map[string]Secret{}}
}

func (s *Store) Install(input InstallInput) error {
	if s == nil {
		return errors.New("secret store is nil")
	}
	secrets, err := DecryptRelease(input)
	if err != nil {
		return err
	}
	next := make(map[string]Secret, len(secrets))
	for _, secret := range secrets {
		next[secret.Name] = secret
	}
	s.mu.Lock()
	s.secrets = next
	s.mu.Unlock()
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
		return nil, errors.New("identity HPKE private key is required")
	}
	if input.Bundle == nil {
		return nil, errors.New("secret release is required")
	}
	out := make([]Secret, 0, len(input.Bundle.Secrets))
	for _, encrypted := range input.Bundle.Secrets {
		aad, err := secretReleaseAAD(input.Bundle, encrypted)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(aad)
		if hex.EncodeToString(sum[:]) != encrypted.AADSHA256 {
			return nil, fmt.Errorf("secret %s AAD hash mismatch", encrypted.Name)
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
		return nil, errors.New("secret release contained no secrets")
	}
	return out, nil
}

func decryptSecret(privateKey hpke.PrivateKey, encrypted provision.SecretCiphertext, aad []byte) ([]byte, error) {
	encapsulated, err := base64.RawURLEncoding.Strict().DecodeString(encrypted.EncapsulatedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encapsulated key: %w", err)
	}
	if len(encapsulated) != hpkeEncapsulationSize {
		return nil, errors.New("encapsulated key has an invalid length")
	}
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(encrypted.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	if len(ciphertext) < hpkeTagSize {
		return nil, errors.New("ciphertext is too short")
	}
	recipient, err := hpke.NewRecipient(
		encapsulated,
		privateKey,
		hpke.HKDFSHA256(),
		hpke.AES256GCM(),
		[]byte(hpkeInfo),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize HPKE recipient: %w", err)
	}
	plaintext, err := recipient.Open(aad, ciphertext)
	if err != nil {
		return nil, errors.New("HPKE ciphertext authentication failed")
	}
	return plaintext, nil
}

func secretReleaseAAD(bundle *provision.SecretBundle, secret provision.SecretCiphertext) ([]byte, error) {
	payload := struct {
		NodeID     string `json:"node_id"`
		ReportDataSHA512 string `json:"report_data_sha512"`
		Schema           string `json:"schema"`
		SecretKeyID      string `json:"secret_key_id"`
		SecretName       string `json:"secret_name"`
		SecretVersion    string `json:"secret_version"`
	}{
		NodeID:     bundle.NodeID,
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
