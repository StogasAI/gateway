package provision

import (
	"bytes"
	"crypto/hpke"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

const BootProvisioningSchema = "stogas.boot-provisioning.v1"

// Region is an operator-declared placement, not a hardware-attested location.
type Region string

const RegionUSVA Region = "US-VA"

func (region Region) Valid() bool {
	return region == RegionUSVA
}

// BootProvisioning is delivered once, over the fixed authenticated Control origin.
// Its recipient and associated data bind it to the exact logged boot document.
type BootProvisioning struct {
	BootSHA256      string `json:"boot_sha256"`
	Ciphertext      string `json:"ciphertext"`
	EncapsulatedKey string `json:"encapsulated_key"`
	Schema          string `json:"schema"`
}

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

// Open checks the envelope before decrypting. Certificate/key/hostname checks and
// required runtime-secret checks remain mandatory before installing the result.
func (sealed BootProvisioning) Open(privateKey hpke.PrivateKey, bootDigest [32]byte) (*BootSecrets, error) {
	if privateKey == nil || sealed.Schema != BootProvisioningSchema || sealed.BootSHA256 != hex.EncodeToString(bootDigest[:]) {
		return nil, errors.New("invalid boot provisioning binding")
	}
	enc, err := decodeBootCiphertext(sealed.EncapsulatedKey, 1120, 1120)
	if err != nil {
		return nil, err
	}
	ciphertext, err := decodeBootCiphertext(sealed.Ciphertext, 17, 64*1024+16)
	if err != nil {
		return nil, err
	}
	recipient, err := hpke.NewRecipient(enc, privateKey, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("stogas.secret-release.v1"))
	if err != nil {
		return nil, errors.New("invalid boot provisioning recipient")
	}
	aad := []byte("{\"boot_sha256\":\"" + sealed.BootSHA256 + "\",\"schema\":\"" + BootProvisioningSchema + "\"}\n")
	plaintext, err := recipient.Open(aad, ciphertext)
	if err != nil {
		return nil, errors.New("boot provisioning authentication failed")
	}
	defer clear(plaintext)
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

func decodeBootCiphertext(value string, minBytes, maxBytes int) ([]byte, error) {
	if len(value) > base64.RawURLEncoding.EncodedLen(maxBytes) {
		return nil, errors.New("oversized boot provisioning")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) < minBytes || len(decoded) > maxBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid boot provisioning encoding")
	}
	return decoded, nil
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
