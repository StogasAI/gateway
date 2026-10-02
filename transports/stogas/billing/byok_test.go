package billing

import (
	"strings"
	"testing"
)

func TestByokDecryptorMatchesControlWebCryptoFormat(t *testing.T) {
	decryptor, err := newByokDecryptor("test-master-secret-0123456789-abcdef")
	if err != nil {
		t.Fatalf("newByokDecryptor returned error: %v", err)
	}

	plaintext, err := decryptor.decrypt(
		"v1.AAECAwQFBgcICQoL.M5UHaC_cZlPfCGItSfcUCDWzgSAaM5hTU7KSERrvi3SeVgsdZ4HR",
		"0198f4cc-6c25-7000-8000-000000000001",
		"org-test",
		"openai",
	)
	if err != nil {
		t.Fatalf("decrypt returned error: %v", err)
	}
	if plaintext != "sk-upstream-test-secret" {
		t.Fatalf("decrypted secret = %q", plaintext)
	}
}

func TestByokDecryptorBindsEveryScopeField(t *testing.T) {
	decryptor, err := newByokDecryptor("test-master-secret-0123456789-abcdef")
	if err != nil {
		t.Fatalf("newByokDecryptor returned error: %v", err)
	}
	ciphertext := "v1.AAECAwQFBgcICQoL.M5UHaC_cZlPfCGItSfcUCDWzgSAaM5hTU7KSERrvi3SeVgsdZ4HR"

	for _, tc := range []struct {
		name           string
		byokID         string
		organizationID string
		provider       string
	}{
		{
			name:           "byok",
			byokID:         "0198f4cc-6c25-7000-8000-000000000002",
			organizationID: "org-test",
			provider:       "openai",
		},
		{
			name:           "organization",
			byokID:         "0198f4cc-6c25-7000-8000-000000000001",
			organizationID: "org-other",
			provider:       "openai",
		},
		{
			name:           "provider",
			byokID:         "0198f4cc-6c25-7000-8000-000000000001",
			organizationID: "org-test",
			provider:       "anthropic",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decryptor.decrypt(
				ciphertext,
				tc.byokID,
				tc.organizationID,
				tc.provider,
			)
			if err == nil || !strings.Contains(err.Error(), "authentication failed") {
				t.Fatalf("decrypt error = %v, want authenticated-scope failure", err)
			}
		})
	}
}

func TestByokDecryptorRejectsMalformedInputAndShortMasterSecret(t *testing.T) {
	if _, err := newByokDecryptor("too-short"); err == nil {
		t.Fatalf("short master secret was accepted")
	}
	decryptor, err := newByokDecryptor("test-master-secret-0123456789-abcdef")
	if err != nil {
		t.Fatalf("newByokDecryptor returned error: %v", err)
	}
	for _, ciphertext := range []string{
		"",
		"v2.AAECAwQFBgcICQoL.body",
		"v1.invalid.body",
		"v1.AAECAwQFBgcICQoL.invalid",
	} {
		if _, err := decryptor.decrypt(
			ciphertext,
			"0198f4cc-6c25-7000-8000-000000000001",
			"org-test",
			"openai",
		); err == nil {
			t.Fatalf("malformed ciphertext %q was accepted", ciphertext)
		}
	}
}
