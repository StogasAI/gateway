package billing

import (
	"strings"
	"testing"
	"time"
)

func TestParseAzureBoundBindingNamesTheTargetAndItsAccount(t *testing.T) {
	const binding = `{"id":"019a0000-0000-7000-8000-000000000001","deploymentName":"customer-sol","deploymentType":"global_standard","endpoint":"https://stogas-east.openai.azure.com","hosting":"azure","modelFormat":"OpenAI","modelName":"gpt-5.6-sol","modelVersion":"2026-07-09","processingLocation":"world","storageLocation":"US","tokenScope":"https://ai.azure.com/.default"}`
	const account = "/subscriptions/00000000-0000-4000-8000-000000000003/resourcegroups/stogas/providers/microsoft.cognitiveservices/accounts/stogas-east"
	bound, err := parseAzureBoundBinding(`{"schema":"stogas.azure-binding.v1","accountId":"` + account + `","verifiedAt":"2026-11-02T12:00:00.123+00:00","binding":` + binding + `}`)
	if err != nil {
		t.Fatal(err)
	}
	if bound.AccountID != account || bound.Binding.ID != "019a0000-0000-7000-8000-000000000001" ||
		bound.VerifiedAt == nil || !bound.VerifiedAt.Equal(time.Date(2026, 11, 2, 12, 0, 0, 123e6, time.UTC)) {
		t.Fatalf("bound binding = %#v", bound)
	}
	// A credential that no check confirmed yet still binds.
	if bound, err := parseAzureBoundBinding(`{"schema":"stogas.azure-binding.v1","accountId":"` + account + `","verifiedAt":null,"binding":` + binding + `}`); err != nil || bound.VerifiedAt != nil {
		t.Fatalf("unconfirmed binding = %#v, %v", bound, err)
	}
	// A customer-encrypted credential's hold says when its next discovery is due; a stored one's
	// says nothing, since Control discovers those.
	var encrypted Authorization
	raw := `{"schema":"stogas.azure-binding.v1","accountId":"` + account + `","verifiedAt":null,"discoverAt":"2026-11-03T12:00:00.5+00:00","binding":` + binding + `}`
	if !encrypted.bindAzure(&raw) || !encrypted.AzureDiscoverAt.Equal(time.Date(2026, 11, 3, 12, 0, 0, 5e8, time.UTC)) ||
		encrypted.AzureAccountID != account || encrypted.AzureBinding == nil || !encrypted.AzureVerifiedAt.IsZero() {
		t.Fatalf("encrypted binding = %#v", encrypted)
	}
	var stored Authorization
	raw = `{"schema":"stogas.azure-binding.v1","accountId":"` + account + `","verifiedAt":"2026-11-02T12:00:00Z","discoverAt":null,"binding":` + binding + `}`
	if !stored.bindAzure(&raw) || !stored.AzureDiscoverAt.IsZero() || stored.AzureVerifiedAt.IsZero() {
		t.Fatalf("stored binding = %#v", stored)
	}
	if stored := (Authorization{}); stored.bindAzure(nil) || stored.AzureBinding != nil {
		t.Fatal("bound a missing binding")
	}
	// A key that a newer function adds, at either level, does not stop an older release.
	raw = `{"schema":"stogas.azure-binding.v1","accountId":"` + account + `","verifiedAt":null,"extra":1,"binding":` + strings.Replace(binding, `{`, `{"extra":{"a":[1]},`, 1) + `}`
	if added := (Authorization{}); !added.bindAzure(&raw) || added.AzureBinding.ID != "019a0000-0000-7000-8000-000000000001" {
		t.Fatalf("binding with added keys = %#v", added)
	}
	for name, raw := range map[string]string{
		"no account":     `{"schema":"stogas.azure-binding.v1","verifiedAt":null,"binding":` + binding + `}`,
		"no target ID":   `{"schema":"stogas.azure-binding.v1","accountId":"` + account + `","verifiedAt":null,"binding":` + strings.Replace(binding, `"id":"019a0000-0000-7000-8000-000000000001",`, "", 1) + `}`,
		"another schema": `{"schema":"stogas.azure-binding.v2","accountId":"` + account + `","verifiedAt":null,"binding":` + binding + `}`,
		"trailing JSON":  `{"schema":"stogas.azure-binding.v1","accountId":"` + account + `","verifiedAt":null,"binding":` + binding + `} {}`,
	} {
		if _, err := parseAzureBoundBinding(raw); err == nil {
			t.Fatalf("%s: accepted %s", name, raw)
		}
	}
}
