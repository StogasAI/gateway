package bedrock

import (
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/maximhq/bifrost/core/providers/utils/tokencache"
	schemas "github.com/maximhq/bifrost/core/schemas"
)

// maxAssumeRoleCreds bounds assumeRoleCredsCache. Every distinct set of role
// inputs adds an entry, including inputs STS later rejects, so a caller who
// varies them would otherwise grow the map without limit. Clearing the map
// when it is full costs each live role one more AssumeRole call.
const maxAssumeRoleCreds = 1024

var assumeRoleCredsCount atomic.Int64

// assumeRoleCacheKey identifies assumed-role credentials by every input that
// decides them, secrets included. A key without the secret would let a caller
// who knows another key's access key ID, role ARN and external ID, none of
// which AWS treats as secret, reuse that key's role session.
func assumeRoleCacheKey(region, roleARN, externalID, sessionName string, accessKey, secretKey schemas.SecretVar, sessionToken *schemas.SecretVar) string {
	token := ""
	if sessionToken != nil {
		token = sessionToken.GetValue()
	}
	return tokencache.CacheKey("bedrock-assume-role-v1", region, roleARN, externalID, sessionName,
		accessKey.GetValue(), secretKey.GetValue(), token)
}

// storeAssumeRoleCreds caches creds under key unless another caller stored
// first, and returns the cached value.
func storeAssumeRoleCreds(key string, creds *aws.CredentialsCache) *aws.CredentialsCache {
	if assumeRoleCredsCount.Load() >= maxAssumeRoleCreds {
		assumeRoleCredsCache.Clear()
		assumeRoleCredsCount.Store(0)
	}
	actual, loaded := assumeRoleCredsCache.LoadOrStore(key, creds)
	if !loaded {
		assumeRoleCredsCount.Add(1)
	}
	return actual.(*aws.CredentialsCache)
}
