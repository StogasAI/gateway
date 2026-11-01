package azure

import (
	"errors"
	"testing"

	schemas "github.com/maximhq/bifrost/core/schemas"
)

func TestDefaultAzureCredentialRefusedWhenHostIdentityDisabled(t *testing.T) {
	previous := schemas.UseHostCloudCredentials
	schemas.UseHostCloudCredentials = false
	t.Cleanup(func() { schemas.UseHostCloudCredentials = previous })

	if _, err := (&AzureProvider{}).getOrCreateDefaultAzureCredential(); !errors.Is(err, schemas.ErrHostCloudCredentials) {
		t.Fatalf("getOrCreateDefaultAzureCredential() error = %v, want the host-identity refusal", err)
	}
}
