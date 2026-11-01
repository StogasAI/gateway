package bedrock

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	schemas "github.com/maximhq/bifrost/core/schemas"
)

func withoutHostCloudCredentials(t *testing.T) {
	t.Helper()
	previous := schemas.UseHostCloudCredentials
	schemas.UseHostCloudCredentials = false
	t.Cleanup(func() { schemas.UseHostCloudCredentials = previous })
}

func TestResolveAWSCredentialsRefusesHostIdentityWhenDisabled(t *testing.T) {
	withoutHostCloudCredentials(t)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	defer ctx.Cancel()
	role := &schemas.SecretVar{Val: "arn:aws:iam::123456789012:role/bedrock"}
	for name, cfg := range map[string]*schemas.BedrockKeyConfig{
		"nil config":          nil,
		"empty keys":          {},
		"role without source": {RoleARN: role},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ResolveAWSCredentials(ctx, cfg, "us-east-1"); err == nil || err.Error.Message != schemas.ErrHostCloudCredentials.Error() {
				t.Fatalf("ResolveAWSCredentials() error = %v, want the host-identity refusal", err)
			}
		})
	}
	creds, err := ResolveAWSCredentials(ctx, &schemas.BedrockKeyConfig{AccessKey: schemas.SecretVar{Val: "AKIAEXAMPLE"}, SecretKey: schemas.SecretVar{Val: "secret"}}, "us-east-1")
	if err != nil || creds.AccessKeyID != "AKIAEXAMPLE" || creds.SecretAccessKey != "secret" {
		t.Fatalf("explicit keys = %+v, %v; want them unchanged", creds, err)
	}
	if err := uploadToS3(ctx, "", "", nil, "us-east-1", "bucket", "key", nil); err == nil || err.Error.Message != schemas.ErrHostCloudCredentials.Error() {
		t.Fatalf("uploadToS3() error = %v, want the host-identity refusal", err)
	}
	if err := signAWSRequestFastHTTP(ctx, nil, nil, "", "", nil, "us-east-1", "bedrock"); err == nil || err.Error.Message != schemas.ErrHostCloudCredentials.Error() {
		t.Fatalf("signAWSRequestFastHTTP() error = %v, want the host-identity refusal", err)
	}
}

func TestAssumeRoleCacheKeyCoversEverySecret(t *testing.T) {
	access := schemas.SecretVar{Val: "AKIAEXAMPLE"}
	base := assumeRoleCacheKey("us-east-1", "arn:aws:iam::123456789012:role/r", "external", "session", access, schemas.SecretVar{Val: "one"}, nil)
	for name, other := range map[string]string{
		"secret key":    assumeRoleCacheKey("us-east-1", "arn:aws:iam::123456789012:role/r", "external", "session", access, schemas.SecretVar{Val: "two"}, nil),
		"session token": assumeRoleCacheKey("us-east-1", "arn:aws:iam::123456789012:role/r", "external", "session", access, schemas.SecretVar{Val: "one"}, &schemas.SecretVar{Val: "token"}),
		"field framing": assumeRoleCacheKey("us-east-1", "arn:aws:iam::123456789012:role/r", "externalsession", "", access, schemas.SecretVar{Val: "one"}, nil),
	} {
		if other == base {
			t.Errorf("changing the %s kept the cache key", name)
		}
	}
}

func TestAssumeRoleCredsCacheIsBounded(t *testing.T) {
	assumeRoleCredsCache.Clear()
	assumeRoleCredsCount.Store(0)
	t.Cleanup(func() {
		assumeRoleCredsCache.Clear()
		assumeRoleCredsCount.Store(0)
	})
	first := aws.NewCredentialsCache(aws.AnonymousCredentials{})
	if got := storeAssumeRoleCreds("first", first); got != first {
		t.Fatal("first store did not keep its value")
	}
	if got := storeAssumeRoleCreds("first", aws.NewCredentialsCache(aws.AnonymousCredentials{})); got != first {
		t.Fatal("a second store for the same key replaced the cached value")
	}
	for i := 1; i < maxAssumeRoleCreds; i++ {
		storeAssumeRoleCreds(string(rune(0x10000+i)), aws.NewCredentialsCache(aws.AnonymousCredentials{}))
	}
	if _, ok := assumeRoleCredsCache.Load("first"); !ok {
		t.Fatal("the cache dropped entries before it was full")
	}
	storeAssumeRoleCreds("overflow", aws.NewCredentialsCache(aws.AnonymousCredentials{}))
	entries := 0
	assumeRoleCredsCache.Range(func(any, any) bool { entries++; return true })
	if entries != 1 {
		t.Fatalf("cache holds %d entries after overflowing, want only the newest", entries)
	}
}

func TestSigningKeyDependsOnTheSecret(t *testing.T) {
	one := getSigningKey("AKIAEXAMPLE", "one", "20261031", "us-east-1", "bedrock")
	two := getSigningKey("AKIAEXAMPLE", "two", "20261031", "us-east-1", "bedrock")
	if string(one) == string(two) {
		t.Fatal("two secrets for one access key ID produced the same signing key")
	}
}
