package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"

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
	secret, ok := store.Get("OPENAI_API_KEY")
	if !ok {
		t.Fatal("secret not found")
	}
	if string(secret.Value) != "secret-for-OPENAI_API_KEY" || secret.Version != "2026-07-01" {
		t.Fatalf("unexpected secret: %#v", secret)
	}
}

func TestDecryptReleaseFailsClosedOnBindingMismatch(t *testing.T) {
	material, err := identity.Generate(strings.NewReader(strings.Repeat("b", 4096)))
	if err != nil {
		t.Fatal(err)
	}
	bundle := testBundle()
	encrypted, err := encryptForTest(material, bundle, "OPENAI_API_KEY", "provider-secret")
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
		GenerationID:     strings.Repeat("1", 64),
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
	ephemeralPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return provision.SecretCiphertext{}, err
	}
	recipientPublic, err := ecdh.P256().NewPublicKey(material.HPKEPrivateKey.PublicKey().Bytes())
	if err != nil {
		return provision.SecretCiphertext{}, err
	}
	shared, err := ephemeralPrivate.ECDH(recipientPublic)
	if err != nil {
		return provision.SecretCiphertext{}, err
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, aad, []byte(hkdfInfo)), key); err != nil {
		return provision.SecretCiphertext{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return provision.SecretCiphertext{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return provision.SecretCiphertext{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return provision.SecretCiphertext{}, err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), aad)
	envelope := append(append([]byte(nil), nonce...), ciphertext...)
	secret.AADSHA256 = hex.EncodeToString(sum[:])
	secret.Ciphertext = base64.RawURLEncoding.EncodeToString(envelope)
	secret.EncapsulatedKey = base64.RawURLEncoding.EncodeToString(ephemeralPrivate.PublicKey().Bytes())
	return secret, nil
}
