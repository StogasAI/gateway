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
	"github.com/maximhq/bifrost/core/network"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/accesstoken"
	"github.com/maximhq/bifrost/transports/stogas/awsauth"
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

	// The companies that run Claude on the two clouds, as the catalog names a deployment's hosting.
	hostingAnthropic = catalog.CompanyAnthropic
	hostingAmazon    = catalog.CompanyAmazon
	hostingGoogle    = "google"
)

var (
	awsRegionPattern      = regexp.MustCompile(`^(af|ap|ca|eu|il|me|mx|sa|us)-(central|east|west|north|south|northeast|northwest|southeast|southwest)-[1-9][0-9]?$`)
	awsAccessKeyIDPattern = regexp.MustCompile(`^AKIA[A-Z0-9]{16}$`)
	awsSecretKeyPattern   = regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)
	// A role of the commercial partition, with its path.
	awsRoleARNPattern         = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,576}$`)
	anthropicWorkspacePattern = regexp.MustCompile(`^wrkspc_[A-Za-z0-9]{1,64}$`)
	googleProjectPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	googleClientEmailPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}@[a-z0-9][a-z0-9.-]{0,200}\.gserviceaccount\.com$`)
	googleKeyIDPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// A workload identity pool provider by its resource path, which names the project by number.
	googleProviderPattern = regexp.MustCompile(`^projects/[0-9]{1,20}/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}$`)
)

// vertexHosts are Agent Platform's (Vertex AI's) endpoints by location: the
// global endpoint and the us and eu multi-regions.
var vertexHosts = map[string]string{
	"global": "aiplatform.googleapis.com",
	"us":     "aiplatform.us.rep.googleapis.com",
	"eu":     "aiplatform.eu.rep.googleapis.com",
}

// awsByokCredential signs in with an IAM role that trusts the organization's
// federation issuer or with an IAM access key, which serve Bedrock and, with a
// workspace, Claude Platform on AWS; or with an API key, which serves Claude
// Platform on AWS when a workspace is given and Bedrock otherwise. A role holds
// no secret.
type awsByokCredential struct {
	Schema          string `json:"schema"`
	Region          string `json:"region"`
	RoleARN         string `json:"roleArn"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	APIKey          string `json:"apiKey"`
	WorkspaceID     string `json:"workspaceId"`
}

// googleCloudByokCredential is a service-account key, or a workload identity
// pool provider that trusts the organization's federation issuer, with the
// service account to act as if the pool grants access through one. It serves
// Vertex AI and, with a workspace, Claude on Google Cloud managed by Anthropic.
type googleCloudByokCredential struct {
	Schema                   string `json:"schema"`
	ProjectID                string `json:"projectId"`
	ClientEmail              string `json:"clientEmail"`
	PrivateKeyID             string `json:"privateKeyId"`
	PrivateKey               string `json:"privateKey"`
	WorkloadIdentityProvider string `json:"workloadIdentityProvider"`
	ServiceAccountEmail      string `json:"serviceAccountEmail"`
	WorkspaceID              string `json:"workspaceId"`
}

// signIn is how the credential signs in to Google for one organization.
func (c googleCloudByokCredential) signIn(organizationID string) googleauth.Credential {
	if c.WorkloadIdentityProvider != "" {
		return googleauth.Credential{ClientEmail: c.ServiceAccountEmail, OrganizationID: organizationID, Provider: c.WorkloadIdentityProvider}
	}
	return googleauth.Credential{ClientEmail: c.ClientEmail, PrivateKeyID: c.PrivateKeyID, PrivateKey: c.PrivateKey}
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
	switch {
	case credential.RoleARN != "":
		valid = valid && !accessKey && credential.APIKey == "" && awsRoleARNPattern.MatchString(credential.RoleARN)
	case accessKey:
		valid = valid && credential.APIKey == "" &&
			awsAccessKeyIDPattern.MatchString(credential.AccessKeyID) && awsSecretKeyPattern.MatchString(credential.SecretAccessKey)
	default:
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
		(credential.WorkspaceID != "" && !anthropicWorkspacePattern.MatchString(credential.WorkspaceID)) {
		return googleCloudByokCredential{}, errors.New("invalid Google Cloud BYOK")
	}
	if credential.WorkloadIdentityProvider != "" {
		if credential.ClientEmail != "" || credential.PrivateKeyID != "" || credential.PrivateKey != "" ||
			!googleProviderPattern.MatchString(credential.WorkloadIdentityProvider) ||
			(credential.ServiceAccountEmail != "" && !googleClientEmailPattern.MatchString(credential.ServiceAccountEmail)) {
			return googleCloudByokCredential{}, errors.New("invalid Google Cloud BYOK")
		}
		return credential, nil
	}
	if credential.ServiceAccountEmail != "" ||
		!googleClientEmailPattern.MatchString(credential.ClientEmail) ||
		!googleKeyIDPattern.MatchString(credential.PrivateKeyID) {
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
		hosting := []string{hostingAmazon}
		switch {
		case credential.APIKey != "" && credential.WorkspaceID != "":
			hosting = []string{hostingAnthropic}
		case credential.WorkspaceID != "":
			hosting = []string{hostingAmazon, hostingAnthropic}
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
// starts in a Region that keeps it in its geography, and a model that runs only
// in the Region of each request runs in one of the deployment's Regions.
func cloudTargetServes(provider schemas.ModelProvider, target *billing.CloudTarget, deployment catalog.Deployment) bool {
	if target == nil || !slices.Contains(target.Hosting, deployment.Hosting) {
		return false
	}
	switch provider {
	case catalog.ProviderAWS:
		if !awsRegionPattern.MatchString(target.Region) {
			return false
		}
		geo := deployment.Upstream.InferenceGeo
		switch {
		case deployment.Hosting != hostingAmazon:
			return true
		case deployment.Upstream.Regions != nil:
			return slices.Contains(deployment.Upstream.Regions, target.Region)
		}
		return geo == "global" || catalog.BedrockSourceRegions[geo][target.Region]
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

type awsRoleSource interface {
	Credentials(context.Context, awsauth.Credential) (aws.Credentials, error)
}

// cloudSignIns are the sign-ins that cloud credentials exchange for tokens.
type cloudSignIns struct {
	google googleTokenSource
	roles  awsRoleSource
}

// cloudRequest is how one attempt reaches a deployment on AWS or Google Cloud.
type cloudRequest struct {
	url     string
	headers map[string]string
	signer  schemas.RequestSigner
}

// newCloudRequest builds the URL, headers and per-attempt signer for a
// deployment from the customer's secret. A Google token and a role's
// credentials are fetched once here, so a rejected credential fails before any
// provider call.
func newCloudRequest(ctx context.Context, provider schemas.ModelProvider, organizationID, secret string, deployment catalog.Deployment, streaming bool, signIns cloudSignIns) (cloudRequest, error) {
	upstream := deployment.Upstream
	switch provider {
	case catalog.ProviderAWS:
		credential, err := parseAWSByokCredential(secret)
		if err != nil {
			return cloudRequest{}, billing.ErrByok
		}
		request := cloudRequest{headers: map[string]string{}}
		service := "bedrock"
		switch deployment.Hosting {
		case hostingAmazon:
			// Bedrock takes Claude on its Messages API and other models on its Chat Completions API.
			path := "/openai/v1/chat/completions"
			if catalog.UsesClaudeWire(provider, deployment.ModelID) {
				path = "/anthropic/v1/messages"
			}
			request.url = "https://bedrock-runtime." + credential.Region + ".amazonaws.com" + path
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
		switch {
		case credential.APIKey != "":
			request.signer = staticHeaders("Authorization", "Bearer "+credential.APIKey)
		case credential.RoleARN != "":
			if signIns.roles == nil {
				return cloudRequest{}, billing.ErrGatewayUnavailable
			}
			role := awsauth.Credential{OrganizationID: organizationID, Region: credential.Region, RoleARN: credential.RoleARN}
			request.signer = sigV4Signer(func() (aws.Credentials, error) { return signIns.roles.Credentials(ctx, role) }, service, credential.Region, request.url)
		default:
			key := aws.Credentials{AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey}
			request.signer = sigV4Signer(func() (aws.Credentials, error) { return key, nil }, service, credential.Region, request.url)
		}
		return request, nil
	case catalog.ProviderGoogleCloud:
		credential, err := parseGoogleCloudByokCredential(secret)
		if err != nil {
			return cloudRequest{}, billing.ErrByok
		}
		request := cloudRequest{headers: map[string]string{}}
		switch deployment.Hosting {
		case hostingGoogle:
			host, ok := vertexHosts[upstream.InferenceGeo]
			if !ok {
				return cloudRequest{}, billing.ErrByokTarget
			}
			location := "https://" + host + "/v1/projects/" + credential.ProjectID + "/locations/" + upstream.InferenceGeo
			// Agent Platform serves open models on one Chat Completions endpoint, which takes the
			// publisher and model in the body.
			if deployment.RouteID == string(catalog.CoreProviderGoogleCloudChatCompletions) {
				if !vertexOpenModelPattern.MatchString(upstream.Model) {
					return cloudRequest{}, billing.ErrByokTarget
				}
				request.url = location + "/endpoints/openapi/chat/completions"
				break
			}
			if !vertexModelPattern.MatchString(upstream.Model) {
				return cloudRequest{}, billing.ErrByokTarget
			}
			// Agent Platform takes Claude's Messages body raw and Gemini's generateContent body.
			publisher, method := "google", ":generateContent"
			switch {
			case catalog.UsesClaudeWire(provider, deployment.ModelID) && streaming:
				publisher, method = "anthropic", ":streamRawPredict"
			case catalog.UsesClaudeWire(provider, deployment.ModelID):
				publisher, method = "anthropic", ":rawPredict"
			case streaming:
				method = ":streamGenerateContent?alt=sse"
			}
			request.url = location + "/publishers/" + publisher + "/models/" + upstream.Model + method
		case hostingAnthropic:
			if credential.WorkspaceID == "" {
				return cloudRequest{}, billing.ErrByokTarget
			}
			request.url = "https://claude.googleapis.com/v1/projects/" + credential.ProjectID + "/locations/global/workspaces/" +
				credential.WorkspaceID + "/invoke/v1/messages"
		default:
			return cloudRequest{}, billing.ErrByokTarget
		}
		googleTokens := signIns.google
		if googleTokens == nil {
			return cloudRequest{}, billing.ErrGatewayUnavailable
		}
		signIn := credential.signIn(organizationID)
		request.signer = bearerSigner(func() (string, error) { return googleTokens.Token(ctx, signIn) })
		return request, nil
	}
	return cloudRequest{}, billing.ErrByok
}

// vertexModelPattern keeps a catalog model name to one URL path segment.
var vertexModelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.@-]{0,127}$`)

// vertexOpenModelPattern is an open model's publisher and model, as Agent Platform's Chat
// Completions API names it, such as openai/gpt-oss-120b-maas.
var vertexOpenModelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}/[a-z0-9][a-z0-9.@-]{0,127}$`)

func staticHeaders(name, value string) schemas.RequestSigner {
	return func([]byte) (map[string]string, *schemas.BifrostError) {
		return map[string]string{name: value}, nil
	}
}

// sigV4Signer signs each attempt's exact body when it is sent, so a retry
// never reuses a signature that AWS would reject as expired, and reads the
// credentials for each attempt, so a retry late in a long request signs with a
// role's current ones. It signs only the host, the date and a role's session
// token, which the gateway and AWS both fix.
func sigV4Signer(current func() (aws.Credentials, error), service, region, url string) schemas.RequestSigner {
	signer := v4.NewSigner()
	return func(body []byte) (map[string]string, *schemas.BifrostError) {
		credentials, err := current()
		if err != nil {
			return nil, upstreamSignInFailure(err)
		}
		request, err := http.NewRequest(http.MethodPost, url, nil)
		if err != nil {
			return nil, upstreamSignInFailure(err)
		}
		digest := sha256.Sum256(body)
		if err := signer.SignHTTP(context.Background(), credentials, request, hex.EncodeToString(digest[:]), service, region, time.Now()); err != nil {
			return nil, upstreamSignInFailure(err)
		}
		headers := map[string]string{"Authorization": request.Header.Get("Authorization"), "X-Amz-Date": request.Header.Get("X-Amz-Date")}
		if token := request.Header.Get("X-Amz-Security-Token"); token != "" {
			headers["X-Amz-Security-Token"] = token
		}
		return headers, nil
	}
}

// bearerSigner reads the access token for each attempt, so a retry late in a
// long request gets a current token rather than the one its first attempt used.
func bearerSigner(current func() (string, error)) schemas.RequestSigner {
	return func([]byte) (map[string]string, *schemas.BifrostError) {
		token, err := current()
		if err != nil {
			return nil, upstreamSignInFailure(err)
		}
		return map[string]string{"Authorization": "Bearer " + token}, nil
	}
}

// upstreamSignInFailure reports a sign-in failure as the provider would: a
// rejected credential as 401, which moves the request to the next pair, and
// anything else as 503, which a retry may fix. The attempt never sent the
// request, so no provider can have run it.
func upstreamSignInFailure(err error) *schemas.BifrostError {
	status, message, cause := http.StatusServiceUnavailable, "Upstream sign-in is unavailable", accesstoken.ErrUnavailable
	// Every sign-in reports a rejected credential as accesstoken.ErrCredential.
	if errors.Is(err, accesstoken.ErrCredential) {
		status, message, cause = http.StatusUnauthorized, "Upstream credential rejected", accesstoken.ErrCredential
	}
	return &schemas.BifrostError{StatusCode: schemas.Ptr(status), Error: &schemas.ErrorField{
		Message: message,
		Error:   &network.NotSentError{Err: cause},
	}}
}

// applyCloudRequest installs one pair's cloud request. The body was
// built for the deployment's hosting; this adds what depends on the secret.
func applyCloudRequest(ctx *schemas.BifrostContext, state *State, signIns cloudSignIns) (schemas.Key, error) {
	resolution := state.Resolution
	authorization := state.Authorization
	if !cloudTargetServesSecret(resolution.Provider, authorization.UpstreamByokSecret, resolution.Deployment) {
		return schemas.Key{}, billing.ErrByokTarget
	}
	streaming := resolution.RequestType == schemas.ChatCompletionStreamRequest || resolution.RequestType == schemas.ResponsesStreamRequest
	request, err := newCloudRequest(ctx, resolution.Provider, authorization.OrganizationID, authorization.UpstreamByokSecret, resolution.Deployment, streaming, signIns)
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
