package stogas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/googleauth"
)

// AWS and Google Cloud each serve Claude two ways. The cloud runs the model
// (Amazon Bedrock, Vertex AI), or Anthropic runs it behind the cloud's sign-in
// and billing (Claude Platform on AWS, Claude on Google Cloud managed by
// Anthropic). Every offering takes the Messages body. The deployment's hosting
// and the customer's credential choose the URL, the sign-in and the body shape;
// nothing in a credential can name a host.
const (
	awsByokSchema         = "stogas.aws-byok.v1"
	googleCloudByokSchema = "stogas.google-cloud-byok.v1"

	hostingAnthropic = "anthropic"
	hostingAWS       = "aws"
	hostingGoogle    = "google"
)

var (
	awsRegionPattern          = regexp.MustCompile(`^(af|ap|ca|eu|il|me|mx|sa|us)-(central|east|west|north|south|northeast|northwest|southeast|southwest)-[1-9][0-9]?$`)
	awsAccessKeyIDPattern     = regexp.MustCompile(`^AKIA[A-Z0-9]{16}$`)
	awsSecretKeyPattern       = regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)
	anthropicWorkspacePattern = regexp.MustCompile(`^wrkspc_[A-Za-z0-9]{1,64}$`)
	googleProjectPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	googleClientEmailPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}@[a-z0-9][a-z0-9.-]{0,200}\.gserviceaccount\.com$`)
	googleKeyIDPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// vertexHosts are Vertex AI's endpoints for Claude by location: the global
// endpoint and the us and eu multi-regions.
var vertexHosts = map[string]string{
	"global": "aiplatform.googleapis.com",
	"us":     "aiplatform.us.rep.googleapis.com",
	"eu":     "aiplatform.eu.rep.googleapis.com",
}

// awsByokCredential signs in with an IAM access key, which serves Bedrock and,
// with a workspace, Claude Platform on AWS; or with an API key, which serves
// Claude Platform on AWS when a workspace is given and Bedrock otherwise.
type awsByokCredential struct {
	Schema          string `json:"schema"`
	Region          string `json:"region"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	APIKey          string `json:"apiKey"`
	WorkspaceID     string `json:"workspaceId"`
}

// googleCloudByokCredential is a service-account key. It serves Vertex AI and,
// with a workspace, Claude on Google Cloud managed by Anthropic.
type googleCloudByokCredential struct {
	Schema       string `json:"schema"`
	ProjectID    string `json:"projectId"`
	ClientEmail  string `json:"clientEmail"`
	PrivateKeyID string `json:"privateKeyId"`
	PrivateKey   string `json:"privateKey"`
	WorkspaceID  string `json:"workspaceId"`
}

func decodeStrictJSON(raw string, target any) error {
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func parseAWSByokCredential(raw string) (awsByokCredential, error) {
	var credential awsByokCredential
	if err := decodeStrictJSON(raw, &credential); err != nil {
		return awsByokCredential{}, err
	}
	accessKey := credential.AccessKeyID != "" || credential.SecretAccessKey != ""
	valid := credential.Schema == awsByokSchema && awsRegionPattern.MatchString(credential.Region) &&
		(credential.WorkspaceID == "" || anthropicWorkspacePattern.MatchString(credential.WorkspaceID))
	if accessKey {
		valid = valid && credential.APIKey == "" &&
			awsAccessKeyIDPattern.MatchString(credential.AccessKeyID) && awsSecretKeyPattern.MatchString(credential.SecretAccessKey)
	} else {
		// A short-term Bedrock API key expires within 12 hours, so it cannot be stored.
		valid = valid && validUpstreamAPIKey(credential.APIKey) && !strings.HasPrefix(credential.APIKey, "bedrock-api-key-")
	}
	if !valid {
		return awsByokCredential{}, errors.New("invalid AWS BYOK")
	}
	return credential, nil
}

func parseGoogleCloudByokCredential(raw string) (googleCloudByokCredential, error) {
	var credential googleCloudByokCredential
	if err := decodeStrictJSON(raw, &credential); err != nil {
		return googleCloudByokCredential{}, err
	}
	if credential.Schema != googleCloudByokSchema ||
		!googleProjectPattern.MatchString(credential.ProjectID) ||
		!googleClientEmailPattern.MatchString(credential.ClientEmail) ||
		!googleKeyIDPattern.MatchString(credential.PrivateKeyID) ||
		(credential.WorkspaceID != "" && !anthropicWorkspacePattern.MatchString(credential.WorkspaceID)) {
		return googleCloudByokCredential{}, errors.New("invalid Google Cloud BYOK")
	}
	if _, err := googleauth.ParsePrivateKey(credential.PrivateKey); err != nil {
		return googleCloudByokCredential{}, err
	}
	return credential, nil
}

// cloudCredentialTarget parses an AWS or Google Cloud secret and returns
// everything it can serve.
func cloudCredentialTarget(provider schemas.ModelProvider, secret string) (billing.CloudTarget, error) {
	switch provider {
	case catalog.ProviderAWS:
		credential, err := parseAWSByokCredential(secret)
		if err != nil {
			return billing.CloudTarget{}, err
		}
		hosting := []string{hostingAWS}
		switch {
		case credential.APIKey != "" && credential.WorkspaceID != "":
			hosting = []string{hostingAnthropic}
		case credential.WorkspaceID != "":
			hosting = []string{hostingAnthropic, hostingAWS}
		}
		return billing.CloudTarget{Hosting: hosting, Region: credential.Region}, nil
	case catalog.ProviderGoogleCloud:
		credential, err := parseGoogleCloudByokCredential(secret)
		if err != nil {
			return billing.CloudTarget{}, err
		}
		if credential.WorkspaceID != "" {
			return billing.CloudTarget{Hosting: []string{hostingAnthropic, hostingGoogle}}, nil
		}
		return billing.CloudTarget{Hosting: []string{hostingGoogle}}, nil
	}
	return billing.CloudTarget{}, errors.New("not a cloud provider")
}

// cloudTargetServes reports whether a target can serve a deployment: it names
// the deployment's hosting, and a Bedrock inference profile other than global
// starts in a Region that keeps it in its geography.
func cloudTargetServes(provider schemas.ModelProvider, target *billing.CloudTarget, deployment catalog.Deployment) bool {
	if target == nil || !slices.Contains(target.Hosting, deployment.Upstream.Hosting) {
		return false
	}
	switch provider {
	case catalog.ProviderAWS:
		if !awsRegionPattern.MatchString(target.Region) {
			return false
		}
		geo := deployment.Upstream.InferenceGeo
		return deployment.Upstream.Hosting != hostingAWS || geo == "global" || catalog.BedrockSourceRegions[geo][target.Region]
	case catalog.ProviderGoogleCloud:
		return target.Region == ""
	}
	return false
}

// validateCloudCredential checks a decrypted secret against the public target
// it was registered with: it must serve every hosting the target names, in the
// same Region. The target may name less, which keeps a credential off a hosting.
func validateCloudCredential(provider schemas.ModelProvider, secret string, registered *billing.CloudTarget, deployment catalog.Deployment) error {
	actual, err := cloudCredentialTarget(provider, secret)
	if err != nil || registered == nil || registered.Region != actual.Region {
		return billing.ErrByok
	}
	for _, hosting := range registered.Hosting {
		if !slices.Contains(actual.Hosting, hosting) {
			return billing.ErrByok
		}
	}
	if !cloudTargetServes(provider, registered, deployment) {
		return billing.ErrByokTarget
	}
	return nil
}

type googleTokenSource interface {
	Token(context.Context, googleauth.Credential) (string, error)
}

// cloudRequest is how one attempt reaches a cloud-hosted Claude deployment.
type cloudRequest struct {
	url     string
	headers map[string]string
	signer  schemas.RequestSigner
}

// cloudClaudeRequest builds the URL, headers and per-attempt signer for a
// deployment from the customer's secret. A Google token is fetched once here,
// so a rejected key fails before any provider call.
func cloudClaudeRequest(ctx context.Context, provider schemas.ModelProvider, secret string, deployment catalog.Deployment, streaming bool, googleTokens googleTokenSource) (cloudRequest, error) {
	upstream := deployment.Upstream
	switch provider {
	case catalog.ProviderAWS:
		credential, err := parseAWSByokCredential(secret)
		if err != nil {
			return cloudRequest{}, billing.ErrByok
		}
		request := cloudRequest{headers: map[string]string{}}
		service := "bedrock"
		switch upstream.Hosting {
		case hostingAWS:
			request.url = "https://bedrock-runtime." + credential.Region + ".amazonaws.com/anthropic/v1/messages"
		case hostingAnthropic:
			if credential.WorkspaceID == "" {
				return cloudRequest{}, billing.ErrByokTarget
			}
			request.url = "https://aws-external-anthropic." + credential.Region + ".api.aws/v1/messages"
			request.headers["anthropic-workspace-id"] = credential.WorkspaceID
			service = "aws-external-anthropic"
		default:
			return cloudRequest{}, billing.ErrByokTarget
		}
		// Both offerings take an API key as a bearer token; Bedrock also takes
		// x-api-key, but AWS documents the bearer form for every Bedrock API.
		if credential.APIKey != "" {
			request.signer = staticHeaders("Authorization", "Bearer "+credential.APIKey)
		} else {
			request.signer = sigV4Signer(aws.Credentials{AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey}, service, credential.Region, request.url)
		}
		return request, nil
	case catalog.ProviderGoogleCloud:
		credential, err := parseGoogleCloudByokCredential(secret)
		if err != nil {
			return cloudRequest{}, billing.ErrByok
		}
		request := cloudRequest{headers: map[string]string{}}
		switch upstream.Hosting {
		case hostingGoogle:
			host, ok := vertexHosts[upstream.InferenceGeo]
			if !ok || !vertexModelPattern.MatchString(upstream.Model) {
				return cloudRequest{}, billing.ErrByokTarget
			}
			method := ":rawPredict"
			if streaming {
				method = ":streamRawPredict"
			}
			request.url = "https://" + host + "/v1/projects/" + credential.ProjectID + "/locations/" + upstream.InferenceGeo +
				"/publishers/anthropic/models/" + upstream.Model + method
		case hostingAnthropic:
			if credential.WorkspaceID == "" {
				return cloudRequest{}, billing.ErrByokTarget
			}
			request.url = "https://claude.googleapis.com/v1/projects/" + credential.ProjectID + "/locations/global/workspaces/" +
				credential.WorkspaceID + "/invoke/v1/messages"
		default:
			return cloudRequest{}, billing.ErrByokTarget
		}
		if googleTokens == nil {
			return cloudRequest{}, billing.ErrGatewayUnavailable
		}
		signIn := googleauth.Credential{ClientEmail: credential.ClientEmail, PrivateKeyID: credential.PrivateKeyID, PrivateKey: credential.PrivateKey}
		if _, err := googleTokens.Token(ctx, signIn); err != nil {
			if errors.Is(err, googleauth.ErrCredential) {
				return cloudRequest{}, billing.ErrByok
			}
			return cloudRequest{}, billing.ErrGatewayUnavailable
		}
		request.signer = googleBearer(ctx, googleTokens, signIn)
		return request, nil
	}
	return cloudRequest{}, billing.ErrByok
}

// vertexModelPattern keeps a catalog model name to one URL path segment.
var vertexModelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.@-]{0,127}$`)

func staticHeaders(name, value string) schemas.RequestSigner {
	return func([]byte) (map[string]string, *schemas.BifrostError) {
		return map[string]string{name: value}, nil
	}
}

// sigV4Signer signs each attempt's exact body when it is sent, so a retry
// never reuses a signature that AWS would reject as expired. It signs only the
// host and date, which the gateway and AWS both fix.
func sigV4Signer(credentials aws.Credentials, service, region, url string) schemas.RequestSigner {
	signer := v4.NewSigner()
	return func(body []byte) (map[string]string, *schemas.BifrostError) {
		request, err := http.NewRequest(http.MethodPost, url, nil)
		if err != nil {
			return nil, upstreamSignInFailure(err)
		}
		digest := sha256.Sum256(body)
		if err := signer.SignHTTP(context.Background(), credentials, request, hex.EncodeToString(digest[:]), service, region, time.Now()); err != nil {
			return nil, upstreamSignInFailure(err)
		}
		return map[string]string{"Authorization": request.Header.Get("Authorization"), "X-Amz-Date": request.Header.Get("X-Amz-Date")}, nil
	}
}

// googleBearer reads the access token for each attempt, so a retry late in a
// long request gets a current token rather than the one its first attempt used.
func googleBearer(ctx context.Context, tokens googleTokenSource, credential googleauth.Credential) schemas.RequestSigner {
	return func([]byte) (map[string]string, *schemas.BifrostError) {
		token, err := tokens.Token(ctx, credential)
		if err != nil {
			return nil, upstreamSignInFailure(err)
		}
		return map[string]string{"Authorization": "Bearer " + token}, nil
	}
}

// upstreamSignInFailure reports a sign-in failure as the provider would: a
// rejected credential as 401, anything else as 503, which a retry may fix.
func upstreamSignInFailure(err error) *schemas.BifrostError {
	status, message := http.StatusServiceUnavailable, "Upstream sign-in is unavailable"
	if errors.Is(err, googleauth.ErrCredential) {
		status, message = http.StatusUnauthorized, "Upstream credential rejected"
	}
	return &schemas.BifrostError{StatusCode: schemas.Ptr(status), Error: &schemas.ErrorField{Message: message}}
}

// applyCloudClaudeRequest installs one pair's cloud request. The body was
// built for the deployment's hosting; this adds what depends on the secret.
func applyCloudClaudeRequest(ctx *schemas.BifrostContext, state *State, googleTokens googleTokenSource) (schemas.Key, error) {
	resolution := state.Resolution
	authorization := state.Authorization
	if !cloudTargetServesSecret(resolution.Provider, authorization.UpstreamByokSecret, resolution.Deployment) {
		return schemas.Key{}, billing.ErrByokTarget
	}
	streaming := resolution.RequestType == schemas.ChatCompletionStreamRequest || resolution.RequestType == schemas.ResponsesStreamRequest
	request, err := cloudClaudeRequest(ctx, resolution.Provider, authorization.UpstreamByokSecret, resolution.Deployment, streaming, googleTokens)
	if err != nil {
		return schemas.Key{}, err
	}
	// Keep the beta headers that body preparation added for this hosting.
	headers := make(map[string][]string, len(request.headers)+1)
	if existing, ok := ctx.Value(schemas.BifrostContextKeyExtraHeaders).(map[string][]string); ok {
		for name, values := range existing {
			headers[name] = slices.Clone(values)
		}
	}
	for name, value := range request.headers {
		headers[name] = []string{value}
	}
	ctx.SetValue(schemas.BifrostContextKeyExtraHeaders, headers)
	ctx.SetValue(schemas.BifrostContextKeyURLPath, request.url)
	ctx.SetValue(schemas.BifrostContextKeyRequestSigner, request.signer)
	// The signer carries the credential; core sends no x-api-key for an empty key.
	return schemas.Key{
		ID:      authorization.UpstreamByok,
		Name:    authorization.UpstreamByok,
		Value:   literalSecret(""),
		Models:  schemas.WhiteList{"*"},
		Weight:  1,
		Enabled: schemas.Ptr(true),
	}, nil
}

// cloudTargetServesSecret checks the decrypted secret itself against the
// deployment, after the registered target let routing choose it.
func cloudTargetServesSecret(provider schemas.ModelProvider, secret string, deployment catalog.Deployment) bool {
	target, err := cloudCredentialTarget(provider, secret)
	return err == nil && cloudTargetServes(provider, &target, deployment)
}
