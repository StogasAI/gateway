package bedrock

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/require"
)

type bedrockSecurityRoundTripper struct {
	calls int
}

func (transport *bedrockSecurityRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls++
	return nil, errors.New("unexpected outbound AWS request")
}

func TestPrepareBedrockAWSSignedKeyRequiresExplicitCredentialsForBearerKeys(t *testing.T) {
	region := schemas.NewSecretVar("us-west-2")
	roleARN := schemas.NewSecretVar("arn:aws:iam::123456789012:role/BedrockRequestRole")
	accessKey := *schemas.NewSecretVar("AKIAEXPLICIT")
	secretKey := *schemas.NewSecretVar("explicit-secret")

	for _, test := range []struct {
		name   string
		config *schemas.BedrockKeyConfig
	}{
		{name: "missing config"},
		{name: "empty config", config: &schemas.BedrockKeyConfig{}},
		{name: "region only", config: &schemas.BedrockKeyConfig{Region: region}},
		{name: "assume role only", config: &schemas.BedrockKeyConfig{RoleARN: roleARN}},
		{name: "access key only", config: &schemas.BedrockKeyConfig{AccessKey: accessKey}},
		{name: "secret key only", config: &schemas.BedrockKeyConfig{SecretKey: secretKey}},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := schemas.Key{
				Value:            *schemas.NewSecretVar("bedrock-api-key"),
				BedrockKeyConfig: test.config,
			}

			bifrostErr := prepareBedrockAWSSignedKey(&key)

			require.NotNil(t, bifrostErr)
			require.NotNil(t, bifrostErr.Error)
			require.Equal(t, bedrockAWSSignedCredentialsRequired, bifrostErr.Error.Message)
		})
	}

	t.Run("unresolved API key reference", func(t *testing.T) {
		const envName = "STOGAS_TEST_UNRESOLVED_BEDROCK_API_KEY"
		t.Setenv(envName, "")
		key := schemas.Key{
			Value:            *schemas.NewSecretVar("env." + envName),
			BedrockKeyConfig: &schemas.BedrockKeyConfig{},
		}

		bifrostErr := prepareBedrockAWSSignedKey(&key)

		require.NotNil(t, bifrostErr)
		require.NotNil(t, bifrostErr.Error)
		require.Equal(t, bedrockAWSSignedCredentialsRequired, bifrostErr.Error.Message)
	})
}

func TestPrepareBedrockAWSSignedKeyPreservesExplicitAuthenticationModes(t *testing.T) {
	t.Run("IAM default chain", func(t *testing.T) {
		key := schemas.Key{}
		bifrostErr := prepareBedrockAWSSignedKey(&key)

		require.Nil(t, bifrostErr)
		require.NotNil(t, key.BedrockKeyConfig)
	})

	t.Run("bearer and static AWS credentials", func(t *testing.T) {
		key := schemas.Key{
			Value: *schemas.NewSecretVar("bedrock-api-key"),
			BedrockKeyConfig: &schemas.BedrockKeyConfig{
				AccessKey: *schemas.NewSecretVar("AKIAEXPLICIT"),
				SecretKey: *schemas.NewSecretVar("explicit-secret"),
			},
		}

		bifrostErr := prepareBedrockAWSSignedKey(&key)

		require.Nil(t, bifrostErr)
		require.NotNil(t, key.BedrockKeyConfig)
	})
}

func TestBedrockAWSSignedOperationsRejectBearerOnlyKeys(t *testing.T) {
	provider, err := NewBedrockProvider(&schemas.ProviderConfig{}, noopLogger{})
	require.NoError(t, err)
	transport := &bedrockSecurityRoundTripper{}
	provider.client = &http.Client{Transport: transport}

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAHOSTVALIDATION")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "host-validation-secret")
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	cancelledParent, cancel := context.WithCancel(context.Background())
	cancel()
	cancelledCtx := schemas.NewBifrostContext(cancelledParent, schemas.NoDeadline)
	model := "anthropic.claude-3-5-sonnet-20241022-v2:0"

	operations := []struct {
		name string
		run  func(schemas.Key) *schemas.BifrostError
	}{
		{
			name: "file upload",
			run: func(key schemas.Key) *schemas.BifrostError {
				_, bifrostErr := provider.FileUpload(ctx, key, &schemas.BifrostFileUploadRequest{
					Provider: schemas.Bedrock,
					Filename: "input.jsonl",
					StorageConfig: &schemas.FileStorageConfig{S3: &schemas.S3StorageConfig{
						Bucket: "attacker-bucket",
					}},
				})
				return bifrostErr
			},
		},
		{
			name: "file list",
			run: func(key schemas.Key) *schemas.BifrostError {
				_, bifrostErr := provider.FileList(ctx, []schemas.Key{key}, &schemas.BifrostFileListRequest{
					Provider: schemas.Bedrock,
					StorageConfig: &schemas.FileStorageConfig{S3: &schemas.S3StorageConfig{
						Bucket: "attacker-bucket",
					}},
				})
				return bifrostErr
			},
		},
		{
			name: "file retrieve",
			run: func(key schemas.Key) *schemas.BifrostError {
				_, bifrostErr := provider.FileRetrieve(ctx, []schemas.Key{key}, &schemas.BifrostFileRetrieveRequest{
					Provider: schemas.Bedrock,
					FileID:   "s3://attacker-bucket/victim.jsonl",
				})
				return bifrostErr
			},
		},
		{
			name: "file delete",
			run: func(key schemas.Key) *schemas.BifrostError {
				_, bifrostErr := provider.FileDelete(ctx, []schemas.Key{key}, &schemas.BifrostFileDeleteRequest{
					Provider: schemas.Bedrock,
					FileID:   "s3://attacker-bucket/victim.jsonl",
				})
				return bifrostErr
			},
		},
		{
			name: "file content",
			run: func(key schemas.Key) *schemas.BifrostError {
				_, bifrostErr := provider.FileContent(ctx, []schemas.Key{key}, &schemas.BifrostFileContentRequest{
					Provider: schemas.Bedrock,
					FileID:   "s3://attacker-bucket/victim.jsonl",
				})
				return bifrostErr
			},
		},
		{
			name: "batch create",
			run: func(key schemas.Key) *schemas.BifrostError {
				_, bifrostErr := provider.BatchCreate(ctx, key, &schemas.BifrostBatchCreateRequest{
					Provider:    schemas.Bedrock,
					Model:       &model,
					InputFileID: "s3://attacker-bucket/input.jsonl",
					ExtraParams: map[string]interface{}{
						"role_arn":      "arn:aws:iam::123456789012:role/BedrockBatchRole",
						"output_s3_uri": "s3://attacker-bucket/output/",
					},
				})
				return bifrostErr
			},
		},
		{
			name: "batch create inline upload",
			run: func(key schemas.Key) *schemas.BifrostError {
				_, bifrostErr := provider.BatchCreate(cancelledCtx, key, &schemas.BifrostBatchCreateRequest{
					Provider: schemas.Bedrock,
					Model:    &model,
					Requests: []schemas.BatchRequestItem{{
						CustomID: "request-1",
						Body:     map[string]interface{}{"max_tokens": 16},
					}},
					ExtraParams: map[string]interface{}{
						"role_arn":      "arn:aws:iam::123456789012:role/BedrockBatchRole",
						"output_s3_uri": "s3://attacker-bucket/output/",
					},
				})
				return bifrostErr
			},
		},
		{
			name: "batch list",
			run: func(key schemas.Key) *schemas.BifrostError {
				_, bifrostErr := provider.BatchList(ctx, []schemas.Key{key}, &schemas.BifrostBatchListRequest{
					Provider: schemas.Bedrock,
				})
				return bifrostErr
			},
		},
		{
			name: "batch retrieve",
			run: func(key schemas.Key) *schemas.BifrostError {
				_, bifrostErr := provider.BatchRetrieve(ctx, []schemas.Key{key}, &schemas.BifrostBatchRetrieveRequest{
					Provider: schemas.Bedrock,
					BatchID:  "arn:aws:bedrock:us-east-1:123456789012:model-invocation-job/attacker-job",
				})
				return bifrostErr
			},
		},
		{
			name: "batch cancel",
			run: func(key schemas.Key) *schemas.BifrostError {
				_, bifrostErr := provider.BatchCancel(ctx, []schemas.Key{key}, &schemas.BifrostBatchCancelRequest{
					Provider: schemas.Bedrock,
					BatchID:  "arn:aws:bedrock:us-east-1:123456789012:model-invocation-job/attacker-job",
				})
				return bifrostErr
			},
		},
		{
			name: "batch results",
			run: func(key schemas.Key) *schemas.BifrostError {
				_, bifrostErr := provider.BatchResults(ctx, []schemas.Key{key}, &schemas.BifrostBatchResultsRequest{
					Provider: schemas.Bedrock,
					BatchID:  "arn:aws:bedrock:us-east-1:123456789012:model-invocation-job/attacker-job",
				})
				return bifrostErr
			},
		},
	}

	for _, config := range []struct {
		name   string
		config *schemas.BedrockKeyConfig
	}{
		{name: "missing config"},
		{name: "empty config", config: &schemas.BedrockKeyConfig{}},
	} {
		t.Run(config.name, func(t *testing.T) {
			for _, operation := range operations {
				t.Run(operation.name, func(t *testing.T) {
					transport.calls = 0
					key := schemas.Key{
						ID:               "api-key-only",
						Value:            *schemas.NewSecretVar("bedrock-api-key"),
						BedrockKeyConfig: config.config,
					}

					bifrostErr := operation.run(key)

					require.NotNil(t, bifrostErr)
					require.NotNil(t, bifrostErr.Error)
					require.Equal(t, bedrockAWSSignedCredentialsRequired, bifrostErr.Error.Message)
					require.Zero(t, transport.calls)
				})
			}
		})
	}
}
