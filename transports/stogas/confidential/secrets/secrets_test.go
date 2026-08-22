package secrets

import (
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	"github.com/maximhq/bifrost/transports/stogas/confidential/provision"
)

func TestStoreInstallsDecryptedSecrets(t *testing.T) {
	material, err := identity.Generate(strings.NewReader(strings.Repeat("a", 4096)))
	if err != nil {
		t.Fatal(err)
	}
	bundle := testBundle()
	for _, name := range requiredSecretNames {
		encrypted, err := encryptForTest(material, bundle, name, "secret-for-"+name)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Secrets = append(bundle.Secrets, encrypted)
	}

	store := NewStore()
	if err := store.Install(InstallInput{Bundle: bundle, Identity: material}); err != nil {
		t.Fatal(err)
	}
	if !store.Ready() {
		t.Fatal("store did not become ready")
	}
	secret, ok := store.Get("CHUTES_API_KEY")
	if !ok {
		t.Fatal("secret not found")
	}
	if string(secret.Value) != "secret-for-CHUTES_API_KEY" || secret.Version != "2026-07-01" {
		t.Fatalf("unexpected secret: %#v", secret)
	}
	if err := store.Install(InstallInput{Bundle: bundle, Identity: material}); err == nil {
		t.Fatal("expected a second runtime configuration install to fail")
	}
}

func TestStoreRejectsIncompleteRuntimeConfiguration(t *testing.T) {
	material, err := identity.Generate(strings.NewReader(strings.Repeat("c", 4096)))
	if err != nil {
		t.Fatal(err)
	}
	bundle := testBundle()
	encrypted, err := encryptForTest(material, bundle, "CHUTES_API_KEY", "provider-secret")
	if err != nil {
		t.Fatal(err)
	}
	bundle.Secrets = []provision.SecretCiphertext{encrypted}

	store := NewStore()
	if err := store.Install(InstallInput{Bundle: bundle, Identity: material}); err == nil {
		t.Fatal("expected an incomplete runtime configuration to fail")
	}
	if len(store.Versions()) != 0 {
		t.Fatal("incomplete runtime configuration changed the store")
	}
}

func TestDecryptReleaseFailsClosedOnBindingMismatch(t *testing.T) {
	material, err := identity.Generate(strings.NewReader(strings.Repeat("b", 4096)))
	if err != nil {
		t.Fatal(err)
	}
	bundle := testBundle()
	encrypted, err := encryptForTest(material, bundle, "CHUTES_API_KEY", "provider-secret")
	if err != nil {
		t.Fatal(err)
	}
	bundle.Secrets = []provision.SecretCiphertext{encrypted}

	if _, err := DecryptRelease(InstallInput{Bundle: bundle, Identity: material}); err != nil {
		t.Fatal(err)
	}
	bundle.ReportDataSHA512 = strings.Repeat("4", 128)
	if _, err := DecryptRelease(InstallInput{Bundle: bundle, Identity: material}); err == nil {
		t.Fatal("expected report-data/AAD mismatch to fail")
	}
}

func testBundle() *provision.SecretBundle {
	return &provision.SecretBundle{
		NodeID:           strings.Repeat("1", 64),
		ReportDataSHA512: strings.Repeat("3", 128),
		Schema:           provision.SecretReleaseSchemaV1,
	}
}

func encryptForTest(material *identity.Material, bundle *provision.SecretBundle, name string, plaintext string) (provision.SecretCiphertext, error) {
	secret := provision.SecretCiphertext{
		KeyID:   "gateway-" + strings.ToLower(name),
		Name:    name,
		Version: "2026-07-01",
	}
	aad, err := secretReleaseAAD(bundle, secret)
	if err != nil {
		return provision.SecretCiphertext{}, err
	}
	sum := sha256.Sum256(aad)
	encapsulated, sender, err := hpke.NewSender(
		material.HPKEPrivateKey.PublicKey(),
		hpke.HKDFSHA256(),
		hpke.AES256GCM(),
		[]byte(hpkeInfo),
	)
	if err != nil {
		return provision.SecretCiphertext{}, err
	}
	ciphertext, err := sender.Seal(aad, []byte(plaintext))
	if err != nil {
		return provision.SecretCiphertext{}, err
	}
	secret.AADSHA256 = hex.EncodeToString(sum[:])
	secret.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext)
	secret.EncapsulatedKey = base64.RawURLEncoding.EncodeToString(encapsulated)
	return secret, nil
}
