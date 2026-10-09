package provision

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Region is an operator-declared placement, not a hardware-attested location.
type Region string

const RegionUSVA Region = "US-VA"

func (region Region) Valid() bool {
	return region == RegionUSVA
}

// BootSecrets is the provisioning plaintext Control seals to this boot's key.
type BootSecrets struct {
	CertificatePEM string            `json:"certificate_pem"`
	Region         Region            `json:"region"`
	Secrets        []BootSecretValue `json:"secrets"`
}

type BootSecretValue struct {
	KeyID     string `json:"key_id"`
	Name      string `json:"name"`
	Plaintext string `json:"plaintext"`
	Version   string `json:"version"`
}

// ParseBootSecrets validates opened provisioning. Certificate/key/hostname checks
// and required runtime-secret checks remain mandatory before installation.
func ParseBootSecrets(plaintext []byte) (*BootSecrets, error) {
	var result BootSecrets
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, errors.New("invalid boot provisioning contents")
	}
	if decoder.Decode(new(any)) != io.EOF || result.CertificatePEM == "" || !result.Region.Valid() || len(result.Secrets) == 0 {
		return nil, errors.New("invalid boot provisioning contents")
	}
	names := make(map[string]bool, len(result.Secrets))
	for _, secret := range result.Secrets {
		if !bootSecretName(secret.Name) || names[secret.Name] || secret.KeyID == "" || secret.Plaintext == "" || secret.Version == "" {
			return nil, errors.New("invalid boot secret")
		}
		names[secret.Name] = true
	}
	return &result, nil
}

func bootSecretName(name string) bool {
	if len(name) == 0 || name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	for _, c := range []byte(name) {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
