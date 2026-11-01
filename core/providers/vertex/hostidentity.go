package vertex

import (
	"github.com/bytedance/sonic"
	schemas "github.com/maximhq/bifrost/core/schemas"
	"golang.org/x/oauth2/google"
)

// refuseHostIdentity refuses a key that would sign in with the machine's own
// identity while schemas.UseHostCloudCredentials is false.
func refuseHostIdentity(key schemas.Key) error {
	if !schemas.UseHostCloudCredentials && usesHostIdentity(key.VertexKeyConfig) {
		return schemas.ErrHostCloudCredentials
	}
	return nil
}

// usesHostIdentity reports whether cfg signs in with something the machine
// holds: Application Default Credentials, AWS workload identity, or an
// external account, whose credential source is a machine file, URL, program
// or AWS identity. Impersonated credentials can wrap an external account, so
// they count too.
func usesHostIdentity(cfg *schemas.VertexKeyConfig) bool {
	if cfg.AWSWorkloadIdentity.IsSet() || cfg.AuthCredentials.GetValue() == "" {
		return true
	}
	var meta struct {
		Type string `json:"type"`
	}
	if err := sonic.UnmarshalString(cfg.AuthCredentials.GetValue(), &meta); err != nil {
		return false // getAuthTokenSource reports the parse error
	}
	switch google.CredentialsType(meta.Type) {
	case google.ExternalAccount, google.ImpersonatedServiceAccount:
		return true
	}
	return false
}
