package provision

import (
	"bytes"
	"crypto/hpke"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

type bootProvisioningVector struct {
	Seed      string           `json:"seed_hex"`
	Plaintext BootSecrets      `json:"plaintext"`
	Sealed    BootProvisioning `json:"sealed"`
}

func bootVector(t *testing.T) (bootProvisioningVector, hpke.PrivateKey, [32]byte) {
	t.Helper()
	encoded, err := os.ReadFile("testdata/boot-provisioning-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector bootProvisioningVector
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(vector.Seed)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(vector.Sealed.BootSHA256)
	if err != nil || len(digest) != 32 {
		t.Fatal("bad fixture digest")
	}
	return vector, key, [32]byte(digest)
}

func TestBootProvisioningFromRust(t *testing.T) {
	vector, key, digest := bootVector(t)
	opened, err := vector.Sealed.Open(key, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*opened, vector.Plaintext) {
		t.Fatal("Rust/Go provisioning contents differ")
	}
}

func TestBootProvisioningRejectsSubstitutionAndMalformedEncoding(t *testing.T) {
	vector, key, digest := bootVector(t)
	mutations := map[string]func(*BootProvisioning){
		"schema": func(v *BootProvisioning) { v.Schema = "stogas.session.v1" },
		"boot":   func(v *BootProvisioning) { v.BootSHA256 = strings.Repeat("0", 64) },
		"encapsulation": func(v *BootProvisioning) {
			v.EncapsulatedKey = base64.RawURLEncoding.EncodeToString(make([]byte, 1120))
		},
		"encapsulation short":     func(v *BootProvisioning) { v.EncapsulatedKey = "AA" },
		"encapsulation oversized": func(v *BootProvisioning) { v.EncapsulatedKey += "A" },
		"ciphertext oversized":    func(v *BootProvisioning) { v.Ciphertext = strings.Repeat("A", 87404) },
		"ciphertext short":        func(v *BootProvisioning) { v.Ciphertext = "AA" },
		"ciphertext alphabet":     func(v *BootProvisioning) { v.Ciphertext = "?" + v.Ciphertext[1:] },
		"padding":                 func(v *BootProvisioning) { v.Ciphertext += "=" },
		"newline":                 func(v *BootProvisioning) { v.Ciphertext = "\n" + v.Ciphertext },
		"ciphertext": func(v *BootProvisioning) {
			encoded, _ := base64.RawURLEncoding.DecodeString(v.Ciphertext)
			encoded[0] ^= 1
			v.Ciphertext = base64.RawURLEncoding.EncodeToString(encoded)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			sealed := vector.Sealed
			mutate(&sealed)
			if opened, err := sealed.Open(key, digest); err == nil || opened != nil {
				t.Fatal("accepted changed provisioning")
			}
		})
	}
	other, err := hpke.MLKEM768X25519().NewPrivateKey(bytes.Repeat([]byte{99}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vector.Sealed.Open(other, digest); err == nil {
		t.Fatal("accepted wrong recipient")
	}
	if _, err := vector.Sealed.Open(nil, digest); err == nil {
		t.Fatal("accepted nil recipient")
	}
}

func TestBootProvisioningRejectsAuthenticatedInvalidContents(t *testing.T) {
	vector, key, digest := bootVector(t)
	valid, _ := json.Marshal(vector.Plaintext)
	for name, body := range map[string]string{
		"missing region": strings.Replace(string(valid), `"region":"US-VA",`, "", 1),
		"unknown region": strings.Replace(string(valid), `"region":"US-VA"`, `"region":"unregistered-region"`, 1),
		"malformed":      "{",
		"extra json":     string(valid) + "{}",
		"unknown field":  `{"certificate_pem":"cert","region":"US-VA","secrets":[],"instruction":"execute"}`,
		"no cert":        `{"region":"US-VA","secrets":[{"key_id":"key","name":"KEY","plaintext":"secret","version":"1"}]}`,
		"no secrets":     `{"certificate_pem":"cert","region":"US-VA","secrets":[]}`,
		"bad name":       `{"certificate_pem":"cert","region":"US-VA","secrets":[{"key_id":"key","name":"not-a-key","plaintext":"secret","version":"1"}]}`,
		"empty value":    `{"certificate_pem":"cert","region":"US-VA","secrets":[{"key_id":"key","name":"KEY","plaintext":"","version":"1"}]}`,
		"duplicate":      `{"certificate_pem":"cert","region":"US-VA","secrets":[{"key_id":"key","name":"KEY","plaintext":"secret","version":"1"},{"key_id":"key","name":"KEY","plaintext":"different","version":"1"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			enc, sender, err := hpke.NewSender(key.PublicKey(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("stogas.secret-release.v1"))
			if err != nil {
				t.Fatal(err)
			}
			aad := []byte(`{"boot_sha256":"` + vector.Sealed.BootSHA256 + `","schema":"stogas.boot-provisioning.v1"}` + "\n")
			ciphertext, err := sender.Seal(aad, []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			sealed := vector.Sealed
			sealed.EncapsulatedKey = base64.RawURLEncoding.EncodeToString(enc)
			sealed.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext)
			if opened, err := sealed.Open(key, digest); err == nil || opened != nil {
				t.Fatal("accepted invalid provisioning contents")
			}
		})
	}
}
