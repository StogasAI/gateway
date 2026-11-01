package vertex

import (
	"errors"
	"testing"

	schemas "github.com/maximhq/bifrost/core/schemas"
)

func TestVertexRefusesHostIdentityWhenDisabled(t *testing.T) {
	previous := schemas.UseHostCloudCredentials
	schemas.UseHostCloudCredentials = false
	t.Cleanup(func() { schemas.UseHostCloudCredentials = previous })

	for name, cfg := range map[string]*schemas.VertexKeyConfig{
		"application default credentials": {},
		"aws workload identity": {AWSWorkloadIdentity: &schemas.VertexAWSWorkloadIdentityConfig{
			Audience: schemas.SecretVar{Val: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/aws"},
		}},
		"external account":     {AuthCredentials: schemas.SecretVar{Val: `{"type":"external_account","credential_source":{"file":"/etc/hostname"}}`}},
		"impersonated account": {AuthCredentials: schemas.SecretVar{Val: `{"type":"impersonated_service_account","source_credentials":{"type":"external_account"}}`}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := (&VertexProvider{}).getAuthTokenSource(schemas.Key{VertexKeyConfig: cfg})
			if !errors.Is(err, schemas.ErrHostCloudCredentials) {
				t.Fatalf("getAuthTokenSource() error = %v, want the host-identity refusal", err)
			}
		})
	}
	_, err := (&VertexProvider{}).getAuthTokenSource(schemas.Key{VertexKeyConfig: &schemas.VertexKeyConfig{
		AuthCredentials: schemas.SecretVar{Val: `{"type":"service_account"}`},
	}})
	if errors.Is(err, schemas.ErrHostCloudCredentials) {
		t.Fatal("a service-account key was refused as host identity")
	}
}
