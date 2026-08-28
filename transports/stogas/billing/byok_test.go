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
		"v1.AAECAwQFBgcICQoL.M5UHaC_cZlPfCGItSfcUCDWzgSAaM5h7bRYxlBQ8Th_H9MNpncc_",
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

func TestPassthroughCredentialHashIsStableAndScoped(t *testing.T) {
	decryptor, err := newByokDecryptor("test-master-secret-0123456789-abcdef")
	if err != nil {
		t.Fatalf("newByokDecryptor returned error: %v", err)
	}
	credentialHash, err := decryptor.credentialHash(
		"sk-upstream-test-secret",
		"org-test",
		"workspace-test",
		"openai",
	)
	if err != nil {
		t.Fatalf("credentialHash returned error: %v", err)
	}
	if len(credentialHash) != 64 {
		t.Fatalf("credential hash length = %d, want 64", len(credentialHash))
	}
	repeated, err := decryptor.credentialHash(
		"sk-upstream-test-secret",
		"org-test",
		"workspace-test",
		"openai",
	)
	if err != nil {
		t.Fatalf("repeated credentialHash returned error: %v", err)
	}
	if repeated != credentialHash {
		t.Fatal("pass-through hash was not stable across requests")
	}
	for _, scope := range []struct {
		name           string
		secret         string
		organizationID string
		workspaceID    string
		provider       string
	}{
		{name: "secret", secret: "sk-other", organizationID: "org-test", workspaceID: "workspace-test", provider: "openai"},
		{name: "organization", secret: "sk-upstream-test-secret", organizationID: "org-other", workspaceID: "workspace-test", provider: "openai"},
		{name: "workspace", secret: "sk-upstream-test-secret", organizationID: "org-test", workspaceID: "workspace-other", provider: "openai"},
		{name: "provider", secret: "sk-upstream-test-secret", organizationID: "org-test", workspaceID: "workspace-test", provider: "anthropic"},
	} {
		other, hashErr := decryptor.credentialHash(
			scope.secret,
			scope.organizationID,
			scope.workspaceID,
			scope.provider,
		)
		if hashErr != nil {
			t.Fatalf("%s scope credentialHash returned error: %v", scope.name, hashErr)
		}
		if other == credentialHash {
			t.Fatalf("credential hash did not bind %s", scope.name)
		}
	}
	_, err = decryptor.credentialHash(
		"sk-upstream-test-secret",
		"",
		"workspace-test",
		"openai",
	)
	if err == nil {
		t.Fatal("empty credential hash scope was accepted")
	}
}

func TestByokDecryptorBindsEveryScopeField(t *testing.T) {
	decryptor, err := newByokDecryptor("test-master-secret-0123456789-abcdef")
	if err != nil {
		t.Fatalf("newByokDecryptor returned error: %v", err)
	}
	ciphertext := "v1.AAECAwQFBgcICQoL.M5UHaC_cZlPfCGItSfcUCDWzgSAaM5h7bRYxlBQ8Th_H9MNpncc_"

	for _, tc := range []struct {
		name           string
		byokID         string
		organizationID string
		workspaceID    string
		provider       string
	}{
		{
			name:           "byok",
			byokID:         "0198f4cc-6c25-7000-8000-000000000002",
			organizationID: "org-test",
			workspaceID:    "workspace-test",
			provider:       "openai",
		},
		{
			name:           "organization",
			byokID:         "0198f4cc-6c25-7000-8000-000000000001",
			organizationID: "org-other",
			workspaceID:    "workspace-test",
			provider:       "openai",
		},
		{
			name:           "workspace",
			byokID:         "0198f4cc-6c25-7000-8000-000000000001",
			organizationID: "org-test",
			workspaceID:    "workspace-other",
			provider:       "openai",
		},
		{
			name:           "provider",
			byokID:         "0198f4cc-6c25-7000-8000-000000000001",
			organizationID: "org-test",
			workspaceID:    "workspace-test",
			provider:       "anthropic",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decryptor.decrypt(
				ciphertext,
				tc.byokID,
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
			"workspace-test",
			"openai",
		); err == nil {
			t.Fatalf("malformed ciphertext %q was accepted", ciphertext)
		}
	}
}
