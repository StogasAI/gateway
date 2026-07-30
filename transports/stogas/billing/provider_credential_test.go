package billing

import (
	"strings"
	"testing"
)

func TestProviderCredentialDecryptorMatchesControlWebCryptoFormat(t *testing.T) {
	decryptor, err := newProviderCredentialDecryptor("test-master-secret-0123456789-abcdef")
	if err != nil {
		t.Fatalf("newProviderCredentialDecryptor returned error: %v", err)
	}

	plaintext, err := decryptor.decrypt(
		"v1.AAECAwQFBgcICQoL.M5UHaC_cZlPfCGItSfcUCDWzgSAaM5i4VXZVKJ63p_EzoXLgdIOq",
		"0198f4cc-6c25-7000-8000-000000000001",
		"org-test",
		"workspace-test",
		"openai",
	)
	if err != nil {
		t.Fatalf("decrypt returned error: %v", err)
	}
	if plaintext != "sk-upstream-test-secret" {
		t.Fatalf("decrypted secret = %q", plaintext)
	}
}

func TestProviderCredentialDecryptorBindsEveryScopeField(t *testing.T) {
	decryptor, err := newProviderCredentialDecryptor("test-master-secret-0123456789-abcdef")
	if err != nil {
		t.Fatalf("newProviderCredentialDecryptor returned error: %v", err)
	}
	ciphertext := "v1.AAECAwQFBgcICQoL.M5UHaC_cZlPfCGItSfcUCDWzgSAaM5i4VXZVKJ63p_EzoXLgdIOq"

	for _, tc := range []struct {
		name           string
		credentialID   string
		organizationID string
		workspaceID    string
		provider       string
	}{
		{
			name:           "credential",
			credentialID:   "0198f4cc-6c25-7000-8000-000000000002",
			organizationID: "org-test",
			workspaceID:    "workspace-test",
			provider:       "openai",
		},
		{
			name:           "organization",
			credentialID:   "0198f4cc-6c25-7000-8000-000000000001",
			organizationID: "org-other",
			workspaceID:    "workspace-test",
			provider:       "openai",
		},
		{
			name:           "workspace",
			credentialID:   "0198f4cc-6c25-7000-8000-000000000001",
			organizationID: "org-test",
			workspaceID:    "workspace-other",
			provider:       "openai",
		},
		{
			name:           "provider",
			credentialID:   "0198f4cc-6c25-7000-8000-000000000001",
			organizationID: "org-test",
			workspaceID:    "workspace-test",
			provider:       "anthropic",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decryptor.decrypt(
				ciphertext,
				tc.credentialID,
				tc.organizationID,
				tc.workspaceID,
				tc.provider,
			)
			if err == nil || !strings.Contains(err.Error(), "authentication failed") {
				t.Fatalf("decrypt error = %v, want authenticated-scope failure", err)
			}
		})
	}
}

func TestProviderCredentialDecryptorRejectsMalformedInputAndShortMasterSecret(t *testing.T) {
	if _, err := newProviderCredentialDecryptor("too-short"); err == nil {
		t.Fatalf("short master secret was accepted")
	}
	decryptor, err := newProviderCredentialDecryptor("test-master-secret-0123456789-abcdef")
	if err != nil {
		t.Fatalf("newProviderCredentialDecryptor returned error: %v", err)
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
			"workspace-test",
			"openai",
		); err == nil {
			t.Fatalf("malformed ciphertext %q was accepted", ciphertext)
		}
	}
}
