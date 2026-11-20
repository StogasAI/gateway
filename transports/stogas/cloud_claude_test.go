package stogas

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/maximhq/bifrost/core/network"
	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/awsauth"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/googleauth"
)

const (
	testAWSAccessKeyID = "AKIAIOSFODNN7EXAMPLE"
	testAWSSecretKey   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	testGoogleKeyID    = "0123456789abcdef0123456789abcdef01234567"
	testWorkspaceID    = "wrkspc_01Test"

	testOrganizationID = "01990000-0000-7000-8000-000000000001"
	testAWSRoleARN     = "arn:aws:iam::123456789012:role/gateways/stogas"
	testGoogleProvider = "projects/123456789012/locations/global/workloadIdentityPools/stogas/providers/stogas"
)

var testGooglePrivateKey = func() string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}()

func cloudSecret(t *testing.T, fields map[string]string) string {
	t.Helper()
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func awsIAMSecret(t *testing.T, region, workspace string) string {
	fields := map[string]string{"schema": awsByokSchema, "region": region, "accessKeyId": testAWSAccessKeyID, "secretAccessKey": testAWSSecretKey}
	if workspace != "" {
		fields["workspaceId"] = workspace
	}
	return cloudSecret(t, fields)
}

func awsAPIKeySecret(t *testing.T, region, workspace string) string {
	fields := map[string]string{"schema": awsByokSchema, "region": region, "apiKey": "customer-api-key"}
	if workspace != "" {
		fields["workspaceId"] = workspace
	}
	return cloudSecret(t, fields)
}

// awsRoleSecret and googleFederatedSecret hold no secret: the cloud trusts the organization's
// federation issuer.
func awsRoleSecret(t *testing.T, region, workspace string) string {
	fields := map[string]string{"schema": awsByokSchema, "region": region, "roleArn": testAWSRoleARN}
	if workspace != "" {
		fields["workspaceId"] = workspace
	}
	return cloudSecret(t, fields)
}

func googleFederatedSecret(t *testing.T, serviceAccount string) string {
	fields := map[string]string{"schema": googleCloudByokSchema, "projectId": "stogas-test", "workloadIdentityProvider": testGoogleProvider}
	if serviceAccount != "" {
		fields["serviceAccountEmail"] = serviceAccount
	}
	return cloudSecret(t, fields)
}

type awsRoleFunc func(context.Context, awsauth.Credential) (aws.Credentials, error)

func (f awsRoleFunc) Credentials(ctx context.Context, credential awsauth.Credential) (aws.Credentials, error) {
	return f(ctx, credential)
}

func googleSecret(t *testing.T, workspace string) string {
	fields := map[string]string{
		"schema":       googleCloudByokSchema,
		"projectId":    "stogas-test",
		"clientEmail":  "runner@stogas-test.iam.gserviceaccount.com",
		"privateKeyId": testGoogleKeyID,
		"privateKey":   testGooglePrivateKey,
	}
	if workspace != "" {
		fields["workspaceId"] = workspace
	}
	return cloudSecret(t, fields)
}

// resolveCloudState resolves a request to one cataloged cloud deployment.
func resolveCloudState(t *testing.T, path, deploymentID, extra string) *State {
	t.Helper()
	state, err := resolveCloudRequest(t, path, deploymentID, extra)
	if err != nil {
		t.Fatalf("resolve %s: %v", deploymentID, err)
	}
	return state
}

// resolveCloudRequest routes a request for Claude at the deployment's provider with a credential
// that serves only that deployment.
func resolveCloudRequest(t *testing.T, path, deploymentID, extra string) (*State, error) {
	t.Helper()
	provider, rest, _ := strings.Cut(deploymentID, "-claude")
	// The model is the deployment ID without its provider and its offering or geography.
	model := "claude" + rest
	for _, suffix := range []string{"-anthropic-hosted", "-us", "-eu", "-jp", "-au", "-in", "-ca"} {
		model = strings.TrimSuffix(model, suffix)
	}
	body := `{` + extra + `"model":"provider:` + provider + ` ` + model + `"}`
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Body: []byte(body), Method: "POST", Path: path,
		AvailableCredentials: map[string][]int{provider: {0}},
		DeploymentEligible: func(_ schemas.ModelProvider, _ int, _ catalog.Route, deployment catalog.Deployment) bool {
			return deployment.ID == deploymentID
		},
	})
	if err != nil {
		return nil, err
	}
	if resolution.Deployment.ID != deploymentID {
		t.Fatalf("resolved %s, want %s", resolution.Deployment.ID, deploymentID)
	}
	return NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider)), nil
}

func cloudDeployment(t *testing.T, deploymentID string) catalog.Deployment {
	t.Helper()
	return resolveCloudState(t, "/v1/responses", deploymentID, `"input":"hi",`).Resolution.Deployment
}

func TestCloudCredentialTargetNamesWhatEachSecretServes(t *testing.T) {
	for _, test := range []struct {
		name     string
		provider schemas.ModelProvider
		secret   string
		want     billing.CloudTarget
	}{
		{"IAM key", catalog.ProviderAWS, awsIAMSecret(t, "us-east-1", ""), billing.CloudTarget{Hosting: []string{"amazon"}, Region: "us-east-1"}},
		{"IAM key with workspace", catalog.ProviderAWS, awsIAMSecret(t, "eu-west-1", testWorkspaceID), billing.CloudTarget{Hosting: []string{"amazon", "anthropic"}, Region: "eu-west-1"}},
		{"Bedrock API key", catalog.ProviderAWS, awsAPIKeySecret(t, "us-west-2", ""), billing.CloudTarget{Hosting: []string{"amazon"}, Region: "us-west-2"}},
		{"Claude Platform API key", catalog.ProviderAWS, awsAPIKeySecret(t, "us-east-1", testWorkspaceID), billing.CloudTarget{Hosting: []string{"anthropic"}, Region: "us-east-1"}},
		{"role", catalog.ProviderAWS, awsRoleSecret(t, "us-east-1", ""), billing.CloudTarget{Hosting: []string{"amazon"}, Region: "us-east-1"}},
		{"role with workspace", catalog.ProviderAWS, awsRoleSecret(t, "eu-west-1", testWorkspaceID), billing.CloudTarget{Hosting: []string{"amazon", "anthropic"}, Region: "eu-west-1"}},
		{"workload identity pool", catalog.ProviderGoogleCloud, googleFederatedSecret(t, ""), billing.CloudTarget{Hosting: []string{"google"}}},
		{"workload identity pool with service account", catalog.ProviderGoogleCloud, googleFederatedSecret(t, "runner@stogas-test.iam.gserviceaccount.com"), billing.CloudTarget{Hosting: []string{"google"}}},
		{"service account", catalog.ProviderGoogleCloud, googleSecret(t, ""), billing.CloudTarget{Hosting: []string{"google"}}},
		{"service account with workspace", catalog.ProviderGoogleCloud, googleSecret(t, testWorkspaceID), billing.CloudTarget{Hosting: []string{"anthropic", "google"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := cloudCredentialTarget(test.provider, test.secret)
			if err != nil || !slices.Equal(got.Hosting, test.want.Hosting) || got.Region != test.want.Region {
				t.Fatalf("target %+v, error %v; want %+v", got, err, test.want)
			}
		})
	}
}

func TestCloudCredentialsRejectEveryMalformedSecret(t *testing.T) {
	iam := map[string]string{"schema": awsByokSchema, "region": "us-east-1", "accessKeyId": testAWSAccessKeyID, "secretAccessKey": testAWSSecretKey}
	with := func(base map[string]string, key, value string) map[string]string {
		changed := map[string]string{}
		for name, field := range base {
			changed[name] = field
		}
		if value == "" {
			delete(changed, key)
		} else {
			changed[key] = value
		}
		return changed
	}
	google := map[string]string{
		"schema": googleCloudByokSchema, "projectId": "stogas-test", "clientEmail": "runner@stogas-test.iam.gserviceaccount.com",
		"privateKeyId": testGoogleKeyID, "privateKey": testGooglePrivateKey,
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	smallDER, _ := x509.MarshalPKCS8PrivateKey(small)
	for name, test := range map[string]struct {
		provider schemas.ModelProvider
		secret   string
	}{
		"AWS unknown field":          {catalog.ProviderAWS, cloudSecret(t, with(iam, "sessionToken", "token"))},
		"AWS trailing JSON":          {catalog.ProviderAWS, cloudSecret(t, iam) + "{}"},
		"AWS older schema":           {catalog.ProviderAWS, cloudSecret(t, with(iam, "schema", "stogas.aws-byok.v0"))},
		"AWS GovCloud Region":        {catalog.ProviderAWS, cloudSecret(t, with(iam, "region", "us-gov-west-1"))},
		"AWS China Region":           {catalog.ProviderAWS, cloudSecret(t, with(iam, "region", "cn-north-1"))},
		"AWS temporary key":          {catalog.ProviderAWS, cloudSecret(t, with(iam, "accessKeyId", "ASIAIOSFODNN7EXAMPLE"))},
		"AWS short secret":           {catalog.ProviderAWS, cloudSecret(t, with(iam, "secretAccessKey", "short"))},
		"AWS key without secret":     {catalog.ProviderAWS, cloudSecret(t, with(iam, "secretAccessKey", ""))},
		"AWS key and API key":        {catalog.ProviderAWS, cloudSecret(t, with(iam, "apiKey", "customer-api-key"))},
		"AWS no sign-in":             {catalog.ProviderAWS, cloudSecret(t, map[string]string{"schema": awsByokSchema, "region": "us-east-1"})},
		"AWS role and access key":    {catalog.ProviderAWS, cloudSecret(t, with(iam, "roleArn", testAWSRoleARN))},
		"AWS role and API key":       {catalog.ProviderAWS, cloudSecret(t, map[string]string{"schema": awsByokSchema, "region": "us-east-1", "roleArn": testAWSRoleARN, "apiKey": "customer-api-key"})},
		"AWS user instead of a role": {catalog.ProviderAWS, cloudSecret(t, map[string]string{"schema": awsByokSchema, "region": "us-east-1", "roleArn": "arn:aws:iam::123456789012:user/stogas"})},
		"AWS GovCloud role":          {catalog.ProviderAWS, cloudSecret(t, map[string]string{"schema": awsByokSchema, "region": "us-east-1", "roleArn": "arn:aws-us-gov:iam::123456789012:role/stogas"})},
		"AWS role with a query":      {catalog.ProviderAWS, cloudSecret(t, map[string]string{"schema": awsByokSchema, "region": "us-east-1", "roleArn": testAWSRoleARN + "&Action=GetCallerIdentity"})},
		"Google pool and key":        {catalog.ProviderGoogleCloud, cloudSecret(t, with(google, "workloadIdentityProvider", testGoogleProvider))},
		"Google pool by project ID":  {catalog.ProviderGoogleCloud, cloudSecret(t, map[string]string{"schema": googleCloudByokSchema, "projectId": "stogas-test", "workloadIdentityProvider": "projects/stogas-test/locations/global/workloadIdentityPools/stogas/providers/stogas"})},
		"Google pool in a URL":       {catalog.ProviderGoogleCloud, cloudSecret(t, map[string]string{"schema": googleCloudByokSchema, "projectId": "stogas-test", "workloadIdentityProvider": "//iam.googleapis.com/" + testGoogleProvider})},
		"Google pool, user account":  {catalog.ProviderGoogleCloud, cloudSecret(t, map[string]string{"schema": googleCloudByokSchema, "projectId": "stogas-test", "workloadIdentityProvider": testGoogleProvider, "serviceAccountEmail": "person@example.com"})},
		"Google key, second account": {catalog.ProviderGoogleCloud, cloudSecret(t, with(google, "serviceAccountEmail", "runner@stogas-test.iam.gserviceaccount.com"))},
		"AWS bad workspace":          {catalog.ProviderAWS, cloudSecret(t, with(iam, "workspaceId", "workspace-1"))},
		"AWS API key with space":     {catalog.ProviderAWS, cloudSecret(t, map[string]string{"schema": awsByokSchema, "region": "us-east-1", "apiKey": "two words"})},
		"AWS short-term API key":     {catalog.ProviderAWS, cloudSecret(t, map[string]string{"schema": awsByokSchema, "region": "us-east-1", "apiKey": "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t"})},
		"Google unknown field":       {catalog.ProviderGoogleCloud, cloudSecret(t, with(google, "tokenUri", "https://example.com/token"))},
		"Google bad project":         {catalog.ProviderGoogleCloud, cloudSecret(t, with(google, "projectId", "Stogas/../x"))},
		"Google user email":          {catalog.ProviderGoogleCloud, cloudSecret(t, with(google, "clientEmail", "person@example.com"))},
		"Google bad key ID":          {catalog.ProviderGoogleCloud, cloudSecret(t, with(google, "privateKeyId", "key-1"))},
		"Google PEM key":             {catalog.ProviderGoogleCloud, cloudSecret(t, with(google, "privateKey", "-----BEGIN PRIVATE KEY-----"))},
		"Google 1024-bit key":        {catalog.ProviderGoogleCloud, cloudSecret(t, with(google, "privateKey", base64.StdEncoding.EncodeToString(smallDER)))},
		"Google bad workspace":       {catalog.ProviderGoogleCloud, cloudSecret(t, with(google, "workspaceId", "wrkspc_bad/../x"))},
		"Google key as AWS":          {catalog.ProviderAWS, cloudSecret(t, google)},
		"not a cloud provider":       {schemas.Anthropic, cloudSecret(t, iam)},
		"plain API key as AWS":       {catalog.ProviderAWS, "sk-ant-api03-example"},
		"plain API key as Google":    {catalog.ProviderGoogleCloud, "sk-ant-api03-example"},
		"Google missing private key": {catalog.ProviderGoogleCloud, cloudSecret(t, with(google, "privateKey", ""))},
	} {
		if _, err := cloudCredentialTarget(test.provider, test.secret); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCloudTargetServesOnlyItsHostingsAndTheRegionsThatKeepAProfileInItsGeography(t *testing.T) {
	global := cloudDeployment(t, "aws-claude-fable-5-1")
	us := cloudDeployment(t, "aws-claude-fable-5-1-us")
	eu := cloudDeployment(t, "aws-claude-haiku-5-5-eu")
	canada := cloudDeployment(t, "aws-claude-haiku-5-5-ca")
	platform := cloudDeployment(t, "aws-claude-fable-5-1-anthropic-hosted")
	vertex := cloudDeployment(t, "google-cloud-claude-fable-5-1-eu")
	managed := cloudDeployment(t, "google-cloud-claude-fable-5-1-anthropic-hosted")
	aws := func(region string, hosting ...string) *billing.CloudTarget {
		return &billing.CloudTarget{Hosting: hosting, Region: region}
	}
	for _, test := range []struct {
		name       string
		provider   schemas.ModelProvider
		target     *billing.CloudTarget
		deployment catalog.Deployment
		want       bool
	}{
		{"Bedrock global from Europe", catalog.ProviderAWS, aws("eu-west-1", "amazon"), global, true},
		{"Bedrock US from a US Region", catalog.ProviderAWS, aws("us-east-2", "amazon"), us, true},
		{"Bedrock US from Canada", catalog.ProviderAWS, aws("ca-central-1", "amazon"), us, false},
		{"Bedrock US from Europe", catalog.ProviderAWS, aws("eu-west-1", "amazon"), us, false},
		{"Bedrock EU from Ireland", catalog.ProviderAWS, aws("eu-west-1", "amazon"), eu, true},
		{"Bedrock EU from London, which adds the UK", catalog.ProviderAWS, aws("eu-west-2", "amazon"), eu, false},
		{"Bedrock EU from a US Region", catalog.ProviderAWS, aws("us-east-1", "amazon"), eu, false},
		{"Bedrock Canada from Canada (Central)", catalog.ProviderAWS, aws("ca-central-1", "amazon"), canada, true},
		{"Bedrock Canada from Calgary, an opt-in Region", catalog.ProviderAWS, aws("ca-west-1", "amazon"), canada, false},
		{"Claude Platform without the hosting", catalog.ProviderAWS, aws("us-east-1", "amazon"), platform, false},
		{"Claude Platform", catalog.ProviderAWS, aws("eu-west-1", "anthropic"), platform, true},
		{"Bedrock without the hosting", catalog.ProviderAWS, aws("us-east-1", "anthropic"), global, false},
		{"AWS target without a Region", catalog.ProviderAWS, aws("", "amazon"), global, false},
		{"missing target", catalog.ProviderAWS, nil, global, false},
		{"Vertex", catalog.ProviderGoogleCloud, &billing.CloudTarget{Hosting: []string{"google"}}, vertex, true},
		{"Google target with a Region", catalog.ProviderGoogleCloud, &billing.CloudTarget{Hosting: []string{"google"}, Region: "us-east-1"}, vertex, false},
		{"managed without a workspace", catalog.ProviderGoogleCloud, &billing.CloudTarget{Hosting: []string{"google"}}, managed, false},
		{"managed", catalog.ProviderGoogleCloud, &billing.CloudTarget{Hosting: []string{"anthropic", "google"}}, managed, true},
		{"AWS target for Google", catalog.ProviderAzure, aws("us-east-1", "amazon"), global, false},
	} {
		if got := cloudTargetServes(test.provider, test.target, test.deployment); got != test.want {
			t.Errorf("%s: serves=%v, want %v", test.name, got, test.want)
		}
	}
}

func TestValidateCloudCredentialHoldsTheSecretToItsRegisteredTarget(t *testing.T) {
	global := cloudDeployment(t, "aws-claude-fable-5-1")
	platform := cloudDeployment(t, "aws-claude-fable-5-1-anthropic-hosted")
	secret := awsIAMSecret(t, "us-east-1", testWorkspaceID)
	for _, test := range []struct {
		name       string
		registered *billing.CloudTarget
		deployment catalog.Deployment
		want       error
	}{
		{"everything it serves", &billing.CloudTarget{Hosting: []string{"amazon", "anthropic"}, Region: "us-east-1"}, global, nil},
		{"a narrower target", &billing.CloudTarget{Hosting: []string{"amazon"}, Region: "us-east-1"}, global, nil},
		{"a hosting the narrower target leaves out", &billing.CloudTarget{Hosting: []string{"amazon"}, Region: "us-east-1"}, platform, billing.ErrByokTarget},
		{"another Region", &billing.CloudTarget{Hosting: []string{"amazon"}, Region: "us-west-2"}, global, billing.ErrByok},
		{"a hosting the secret cannot serve", &billing.CloudTarget{Hosting: []string{"amazon", "anthropic", "google"}, Region: "us-east-1"}, global, billing.ErrByok},
		{"no target", nil, global, billing.ErrByok},
	} {
		if err := validateCloudCredential(catalog.ProviderAWS, secret, test.registered, test.deployment); !errors.Is(err, test.want) {
			t.Errorf("%s: error %v, want %v", test.name, err, test.want)
		}
	}
	if err := validateCloudCredential(catalog.ProviderAWS, "not json", &billing.CloudTarget{Hosting: []string{"amazon"}, Region: "us-east-1"}, global); !errors.Is(err, billing.ErrByok) {
		t.Fatalf("malformed secret error %v", err)
	}
}

type googleTokenFunc func(context.Context, googleauth.Credential) (string, error)

func (f googleTokenFunc) Token(ctx context.Context, credential googleauth.Credential) (string, error) {
	return f(ctx, credential)
}

// sigV4Authorization recomputes a SigV4 Authorization header that signs only
// host and x-amz-date, as AWS checks it.
func sigV4Authorization(t *testing.T, rawURL, amzDate, service, region string, body []byte) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	mac := func(key []byte, data string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(data))
		return h.Sum(nil)
	}
	payload := sha256.Sum256(body)
	canonical := strings.Join([]string{
		http.MethodPost, parsed.EscapedPath(), "",
		"host:" + parsed.Host, "x-amz-date:" + amzDate, "",
		"host;x-amz-date", hex.EncodeToString(payload[:]),
	}, "\n")
	canonicalDigest := sha256.Sum256([]byte(canonical))
	scope := amzDate[:8] + "/" + region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(canonicalDigest[:])
	key := mac(mac(mac(mac([]byte("AWS4"+testAWSSecretKey), amzDate[:8]), region), service), "aws4_request")
	return "AWS4-HMAC-SHA256 Credential=" + testAWSAccessKeyID + "/" + scope +
		", SignedHeaders=host;x-amz-date, Signature=" + hex.EncodeToString(mac(key, stringToSign))
}

func TestCloudClaudeRequestReachesEachOfferingWithItsOwnSignIn(t *testing.T) {
	ctx := context.Background()
	body := []byte(`{"model":"global.anthropic.claude-fable-5-1","max_tokens":16}`)
	tokens := googleTokenFunc(func(_ context.Context, credential googleauth.Credential) (string, error) {
		if credential.ClientEmail != "runner@stogas-test.iam.gserviceaccount.com" || credential.PrivateKeyID != testGoogleKeyID {
			t.Fatal("incorrect Google sign-in")
		}
		return "ya29.test", nil
	})
	for _, test := range []struct {
		name       string
		provider   schemas.ModelProvider
		secret     string
		deployment string
		streaming  bool
		url        string
		headers    map[string]string
		sigV4      string
		auth       map[string]string
	}{
		{
			name: "Bedrock with an IAM key", provider: catalog.ProviderAWS, secret: awsIAMSecret(t, "eu-west-1", ""),
			deployment: "aws-claude-fable-5-1", url: "https://bedrock-runtime.eu-west-1.amazonaws.com/anthropic/v1/messages",
			headers: map[string]string{}, sigV4: "bedrock",
		},
		{
			name: "Bedrock with an API key", provider: catalog.ProviderAWS, secret: awsAPIKeySecret(t, "us-east-1", ""),
			deployment: "aws-claude-fable-5-1-us", url: "https://bedrock-runtime.us-east-1.amazonaws.com/anthropic/v1/messages",
			headers: map[string]string{}, auth: map[string]string{"Authorization": "Bearer customer-api-key"},
		},
		{
			name: "Claude Platform with an IAM key", provider: catalog.ProviderAWS, secret: awsIAMSecret(t, "us-west-2", testWorkspaceID),
			deployment: "aws-claude-fable-5-1-anthropic-hosted", url: "https://aws-external-anthropic.us-west-2.api.aws/v1/messages",
			headers: map[string]string{"anthropic-workspace-id": testWorkspaceID}, sigV4: "aws-external-anthropic",
		},
		{
			name: "Claude Platform with an API key", provider: catalog.ProviderAWS, secret: awsAPIKeySecret(t, "us-east-1", testWorkspaceID),
			deployment: "aws-claude-fable-5-1-anthropic-hosted", url: "https://aws-external-anthropic.us-east-1.api.aws/v1/messages",
			headers: map[string]string{"anthropic-workspace-id": testWorkspaceID}, auth: map[string]string{"Authorization": "Bearer customer-api-key"},
		},
		{
			name: "Vertex global", provider: catalog.ProviderGoogleCloud, secret: googleSecret(t, ""),
			deployment: "google-cloud-claude-fable-5-1",
			url:        "https://aiplatform.googleapis.com/v1/projects/stogas-test/locations/global/publishers/anthropic/models/claude-fable-5-1:rawPredict",
			headers:    map[string]string{}, auth: map[string]string{"Authorization": "Bearer ya29.test"},
		},
		{
			name: "Vertex eu streaming", provider: catalog.ProviderGoogleCloud, secret: googleSecret(t, ""),
			deployment: "google-cloud-claude-fable-5-1-eu", streaming: true,
			url:     "https://aiplatform.eu.rep.googleapis.com/v1/projects/stogas-test/locations/eu/publishers/anthropic/models/claude-fable-5-1:streamRawPredict",
			headers: map[string]string{}, auth: map[string]string{"Authorization": "Bearer ya29.test"},
		},
		{
			name: "Vertex us", provider: catalog.ProviderGoogleCloud, secret: googleSecret(t, ""),
			deployment: "google-cloud-claude-fable-5-1-us",
			url:        "https://aiplatform.us.rep.googleapis.com/v1/projects/stogas-test/locations/us/publishers/anthropic/models/claude-fable-5-1:rawPredict",
			headers:    map[string]string{}, auth: map[string]string{"Authorization": "Bearer ya29.test"},
		},
		{
			name: "Claude on Google Cloud", provider: catalog.ProviderGoogleCloud, secret: googleSecret(t, testWorkspaceID),
			deployment: "google-cloud-claude-fable-5-1-anthropic-hosted", streaming: true,
			url:     "https://claude.googleapis.com/v1/projects/stogas-test/locations/global/workspaces/" + testWorkspaceID + "/invoke/v1/messages",
			headers: map[string]string{}, auth: map[string]string{"Authorization": "Bearer ya29.test"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := newCloudRequest(ctx, test.provider, testOrganizationID, test.secret, cloudDeployment(t, test.deployment), test.streaming, cloudSignIns{google: tokens})
			if err != nil || request.url != test.url || request.signer == nil || len(request.headers) != len(test.headers) {
				t.Fatalf("request %+v, error %v", request, err)
			}
			for name, value := range test.headers {
				if request.headers[name] != value {
					t.Fatalf("header %s = %q, want %q", name, request.headers[name], value)
				}
			}
			signed, bifrostErr := request.signer(body)
			if bifrostErr != nil {
				t.Fatalf("sign: %v", bifrostErr.Error.Message)
			}
			if test.sigV4 == "" {
				if len(signed) != len(test.auth) {
					t.Fatalf("signed headers %v", slices.Collect(func(yield func(string) bool) {
						for name := range signed {
							yield(name)
						}
					}))
				}
				for name, value := range test.auth {
					if signed[name] != value {
						t.Fatalf("auth header %s is wrong", name)
					}
				}
				return
			}
			amzDate := signed["X-Amz-Date"]
			if _, err := time.Parse("20060102T150405Z", amzDate); err != nil || len(signed) != 2 {
				t.Fatalf("X-Amz-Date %q, %d headers", amzDate, len(signed))
			}
			region := strings.Split(strings.TrimPrefix(test.url, "https://"), ".")[1]
			if signed["Authorization"] != sigV4Authorization(t, test.url, amzDate, test.sigV4, region, body) {
				t.Fatalf("Authorization %q does not match SigV4 for %s in %s", signed["Authorization"], test.sigV4, region)
			}
			again, _ := request.signer([]byte(`{"other":true}`))
			if again["Authorization"] == signed["Authorization"] {
				t.Fatal("signature does not cover the body")
			}
		})
	}
}

func TestCloudClaudeRequestRefusesSecretsThatCannotServeTheHosting(t *testing.T) {
	ctx := context.Background()
	platform := cloudDeployment(t, "aws-claude-fable-5-1-anthropic-hosted")
	managed := cloudDeployment(t, "google-cloud-claude-fable-5-1-anthropic-hosted")
	if _, err := newCloudRequest(ctx, catalog.ProviderAWS, testOrganizationID, awsIAMSecret(t, "us-east-1", ""), platform, false, cloudSignIns{}); !errors.Is(err, billing.ErrByokTarget) {
		t.Fatalf("Claude Platform without a workspace: %v", err)
	}
	if _, err := newCloudRequest(ctx, catalog.ProviderGoogleCloud, testOrganizationID, googleSecret(t, ""), managed, false, cloudSignIns{}); !errors.Is(err, billing.ErrByokTarget) {
		t.Fatalf("Claude on Google Cloud without a workspace: %v", err)
	}
	if _, err := newCloudRequest(ctx, catalog.ProviderAWS, testOrganizationID, googleSecret(t, ""), platform, false, cloudSignIns{}); !errors.Is(err, billing.ErrByok) {
		t.Fatalf("Google key for AWS: %v", err)
	}
}

func TestGoogleSignInSeparatesRejectedKeysFromOutages(t *testing.T) {
	ctx := context.Background()
	vertex := cloudDeployment(t, "google-cloud-claude-fable-5-1")
	if _, err := newCloudRequest(ctx, catalog.ProviderGoogleCloud, testOrganizationID, googleSecret(t, ""), vertex, false, cloudSignIns{}); !errors.Is(err, billing.ErrGatewayUnavailable) {
		t.Fatalf("no token cache: %v", err)
	}

	// Each attempt reads the token, so a late retry gets a fresh one, and a rejected key answers
	// as the provider would, from the first attempt on. No attempt that fails to sign in sent the
	// request.
	calls := 0
	request, err := newCloudRequest(ctx, catalog.ProviderGoogleCloud, testOrganizationID, googleSecret(t, ""), vertex, false,
		cloudSignIns{google: googleTokenFunc(func(context.Context, googleauth.Credential) (string, error) {
			calls++
			switch calls {
			case 1:
				return "ya29.first", nil
			case 2:
				return "ya29.second", nil
			case 3:
				return "", googleauth.ErrCredential
			}
			return "", googleauth.ErrUnavailable
		})})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("signed in %d times before the first attempt", calls)
	}
	first, _ := request.signer(nil)
	second, _ := request.signer(nil)
	_, rejected := request.signer(nil)
	_, unavailable := request.signer(nil)
	if first["Authorization"] != "Bearer ya29.first" || second["Authorization"] != "Bearer ya29.second" ||
		rejected == nil || *rejected.StatusCode != http.StatusUnauthorized || !network.RequestNotSent(rejected.Error.Error) ||
		unavailable == nil || *unavailable.StatusCode != http.StatusServiceUnavailable || !network.RequestNotSent(unavailable.Error.Error) {
		t.Fatalf("attempts = %v, %v, %+v, %+v", first, second, rejected, unavailable)
	}
	if billing.NormalizeUpstreamStatus(rejected) != "authentication_error" {
		t.Fatalf("a rejected key logs as %s", billing.NormalizeUpstreamStatus(rejected))
	}
}

func TestFederatedCredentialsSignInAsTheOrganization(t *testing.T) {
	ctx := context.Background()
	bedrock := cloudDeployment(t, "aws-claude-fable-5-1")
	vertex := cloudDeployment(t, "google-cloud-claude-fable-5-1-eu")

	// A role's credentials are read for each attempt, so a retry late in a long request signs
	// with the current ones, and the session token travels with the signature.
	var asked []awsauth.Credential
	roles := awsRoleFunc(func(_ context.Context, credential awsauth.Credential) (aws.Credentials, error) {
		asked = append(asked, credential)
		switch len(asked) {
		case 1:
			return aws.Credentials{AccessKeyID: "ASIAFIRST", SecretAccessKey: "first", SessionToken: "session-1"}, nil
		case 2:
			return aws.Credentials{AccessKeyID: "ASIASECOND", SecretAccessKey: "second", SessionToken: "session-2"}, nil
		case 3:
			return aws.Credentials{}, awsauth.ErrCredential
		}
		return aws.Credentials{}, awsauth.ErrUnavailable
	})
	request, err := newCloudRequest(ctx, catalog.ProviderAWS, testOrganizationID, awsRoleSecret(t, "us-east-1", ""), bedrock, false, cloudSignIns{roles: roles})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := request.signer([]byte("{}"))
	if want := (awsauth.Credential{OrganizationID: testOrganizationID, Region: "us-east-1", RoleARN: testAWSRoleARN}); asked[0] != want {
		t.Fatalf("assumed %+v", asked[0])
	}
	second, _ := request.signer([]byte("{}"))
	_, rejected := request.signer([]byte("{}"))
	_, unavailable := request.signer([]byte("{}"))
	if first["X-Amz-Security-Token"] != "session-1" || !strings.Contains(first["Authorization"], "Credential=ASIAFIRST/") ||
		second["X-Amz-Security-Token"] != "session-2" || !strings.Contains(second["Authorization"], "Credential=ASIASECOND/") {
		t.Fatalf("signatures %v, %v", first, second)
	}
	if !strings.Contains(first["Authorization"], "SignedHeaders=host;x-amz-date;x-amz-security-token") {
		t.Fatalf("the signature leaves the session token out: %s", first["Authorization"])
	}
	if rejected == nil || *rejected.StatusCode != http.StatusUnauthorized || !network.RequestNotSent(rejected.Error.Error) {
		t.Fatalf("a role that AWS stopped trusting answered %+v", rejected)
	}
	if unavailable == nil || *unavailable.StatusCode != http.StatusServiceUnavailable || !network.RequestNotSent(unavailable.Error.Error) {
		t.Fatalf("an AWS outage answered %+v", unavailable)
	}
	if _, err := newCloudRequest(ctx, catalog.ProviderAWS, testOrganizationID, awsRoleSecret(t, "us-east-1", ""), bedrock, false, cloudSignIns{}); !errors.Is(err, billing.ErrGatewayUnavailable) {
		t.Fatalf("no role cache: %v", err)
	}

	// Google signs in through the pool as the organization, and as the service account when the
	// credential names one.
	var signIn googleauth.Credential
	tokens := googleTokenFunc(func(_ context.Context, credential googleauth.Credential) (string, error) {
		signIn = credential
		return "ya29.federated", nil
	})
	for _, account := range []string{"", "runner@stogas-test.iam.gserviceaccount.com"} {
		request, err := newCloudRequest(ctx, catalog.ProviderGoogleCloud, testOrganizationID, googleFederatedSecret(t, account), vertex, false, cloudSignIns{google: tokens})
		if err != nil {
			t.Fatal(err)
		}
		if headers, _ := request.signer(nil); headers["Authorization"] != "Bearer ya29.federated" {
			t.Fatalf("headers %v", headers)
		}
		if want := (googleauth.Credential{ClientEmail: account, OrganizationID: testOrganizationID, Provider: testGoogleProvider}); signIn != want {
			t.Fatalf("signed in as %+v", signIn)
		}
	}
}

func TestApplyCloudClaudeRequestKeepsBetaHeadersAndSendsNoKey(t *testing.T) {
	state := resolveCloudState(t, "/v1/responses", "aws-claude-fable-5-1-anthropic-hosted", `"input":"hi","stream":true,`)
	state.Authorization = &billing.Authorization{
		UpstreamByok:       "00000000-0000-8000-8000-000000000001",
		UpstreamByokSecret: awsIAMSecret(t, "us-east-1", testWorkspaceID),
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	beta := map[string][]string{"anthropic-beta": {"compact-2026-01-12"}}
	ctx.SetValue(schemas.BifrostContextKeyExtraHeaders, beta)
	if err := applyUpstreamCredentials(ctx, state, nil, cloudSignIns{}, nil); err != nil {
		t.Fatal(err)
	}
	headers, _ := ctx.Value(schemas.BifrostContextKeyExtraHeaders).(map[string][]string)
	if !slices.Equal(headers["anthropic-beta"], []string{"compact-2026-01-12"}) ||
		!slices.Equal(headers["anthropic-workspace-id"], []string{testWorkspaceID}) || len(beta) != 1 {
		t.Fatalf("headers %v, original %v", headers, beta)
	}
	if ctx.Value(schemas.BifrostContextKeyURLPath) != "https://aws-external-anthropic.us-east-1.api.aws/v1/messages" {
		t.Fatalf("URL %v", ctx.Value(schemas.BifrostContextKeyURLPath))
	}
	if signer, _ := ctx.Value(schemas.BifrostContextKeyRequestSigner).(schemas.RequestSigner); signer == nil {
		t.Fatal("no request signer")
	}
	key, ok := ctx.Value(schemas.BifrostContextKeyDirectKey).(schemas.Key)
	if !ok || key.Value.GetValue() != "" || key.ID != state.Authorization.UpstreamByok {
		t.Fatalf("direct key %#v", key)
	}

	// Indented JSON is the same credential.
	var indented bytes.Buffer
	if err := json.Indent(&indented, []byte(awsIAMSecret(t, "us-east-1", testWorkspaceID)), "", "  "); err != nil {
		t.Fatal(err)
	}
	state.Authorization.UpstreamByokSecret = indented.String()
	if err := applyUpstreamCredentials(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), state, nil, cloudSignIns{}, nil); err != nil {
		t.Fatalf("indented credential: %v", err)
	}

	// A secret that cannot serve the routed deployment is refused before any
	// provider call, whatever the registered target claimed.
	state.Authorization.UpstreamByokSecret = awsIAMSecret(t, "us-east-1", "")
	if err := applyUpstreamCredentials(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), state, nil, cloudSignIns{}, nil); !errors.Is(err, billing.ErrByokTarget) {
		t.Fatalf("error %v", err)
	}
}

func TestCloudCredentialEligibilityUsesThePublicTarget(t *testing.T) {
	now := time.Now()
	snapshot := &billing.KeyConfigSnapshot{Credentials: map[string][]billing.CredentialSelection{
		"aws": {
			{Credential: &billing.CachedCredential{Target: &billing.CloudTarget{Hosting: []string{"amazon"}, Region: "eu-west-1"}}},
			{Credential: &billing.CachedCredential{}},
		},
		"google-cloud": {{Credential: &billing.CachedCredential{Target: &billing.CloudTarget{Hosting: []string{"google"}}}}},
	}}
	eligible := CredentialDeploymentFilter(snapshot, now)
	if !eligible(catalog.ProviderAWS, 0, catalog.RouteChat, cloudDeployment(t, "aws-claude-fable-5-1")) ||
		eligible(catalog.ProviderAWS, 0, catalog.RouteChat, cloudDeployment(t, "aws-claude-fable-5-1-us")) ||
		eligible(catalog.ProviderAWS, 0, catalog.RouteChat, cloudDeployment(t, "aws-claude-fable-5-1-anthropic-hosted")) ||
		eligible(catalog.ProviderAWS, 1, catalog.RouteChat, cloudDeployment(t, "aws-claude-fable-5-1")) {
		t.Fatal("AWS eligibility ignored the public target")
	}
	if !eligible(catalog.ProviderGoogleCloud, 0, catalog.RouteChat, cloudDeployment(t, "google-cloud-claude-fable-5-1-eu")) ||
		eligible(catalog.ProviderGoogleCloud, 0, catalog.RouteChat, cloudDeployment(t, "google-cloud-claude-fable-5-1-anthropic-hosted")) {
		t.Fatal("Google Cloud eligibility ignored the public target")
	}
}

func TestCloudClaudeAdapterRefusesWhatTheCloudLacks(t *testing.T) {
	for _, test := range []struct {
		deployment string
		path       string
		body       string
		want       string
	}{
		{"aws-claude-fable-5-1", "/v1/responses", `"input":"hi","task_budget":{"type":"tokens","total":20000},`, ""},
		{"aws-claude-fable-5-1-anthropic-hosted", "/v1/responses", `"input":"hi","task_budget":{"type":"tokens","total":20000},`, ""},
		// Only Anthropic's hosting runs hosted tools, so a credential that reaches only the
		// cloud's own hosting gets the tool named.
		{"google-cloud-claude-fable-5-1", "/v1/responses", `"input":"hi","tools":[{"type":"web_search"}],`, "No deployment that your credentials reach runs web_search. Remove the tool or check each credential's Region, hostings and Azure deployments."},
		{"aws-claude-fable-5-1", "/v1/responses", `"input":"hi","tools":[{"type":"web_fetch"}],`, "No deployment that your credentials reach runs web_fetch."},
		{"aws-claude-fable-5-1-anthropic-hosted", "/v1/responses", `"input":"hi","tools":[{"type":"web_fetch"}],`, ""},
		{"google-cloud-claude-fable-5-1-anthropic-hosted", "/v1/responses", `"input":"hi","tools":[{"type":"web_search"}],`, ""},
		// A Claude file ID names a file in Anthropic's Files API, which only Anthropic's hosting has.
		{"aws-claude-fable-5-1", "/v1/responses", `"input":[{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}],`, "input[0].content[0] file IDs are not supported by any deployment that this request can use"},
		{"azure-claude-haiku-5-5", "/v1/responses", `"input":[{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}],`, "input[0].content[0] file IDs are not supported by any deployment that this request can use"},
		{"aws-claude-fable-5-1-anthropic-hosted", "/v1/responses", `"input":[{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}],`, "input[0].content[0] is a provider file ID, which only a BYOK credential can read"},
		{"azure-claude-haiku-5-5-anthropic-hosted", "/v1/responses", `"input":[{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}],`, "input[0].content[0] is a provider file ID, which only a BYOK credential can read"},
		{"aws-claude-fable-5-1-us", "/v1/responses", `"input":[{"role":"user","content":[{"type":"input_image","image_url":"https://example.com/a.png"}]}],`, "input[0].content[0] URLs are not supported by any deployment that this request can use; send the content inline"},
		{"google-cloud-claude-fable-5-1-us", "/v1/chat/completions", `"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}],`, "messages[0].content[0] URLs are not supported by any deployment that this request can use; send the content inline"},
		// Of file IDs and URL sources, Claude that Azure hosts lacks only file IDs, which need the
		// Files API.
		{"azure-claude-haiku-5-5", "/v1/chat/completions", `"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}],`, ""},
		{"google-cloud-claude-fable-5-1-anthropic-hosted", "/v1/chat/completions", `"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}],`, ""},
	} {
		// The model's deployments at AWS and Google read attachments differently, so routing
		// refuses a part that the cloud cannot read before the adapter does.
		state, err := resolveCloudRequest(t, test.path, test.deployment, test.body)
		if err == nil {
			err = state.Adapter.ValidateRequest(state)
		}
		if test.want == "" && err != nil || test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("%s %s: error %v, want %q", test.deployment, test.body, err, test.want)
		}
	}
}

func TestCloudClaudeAdapterSendsGeographyOnlyToAnthropic(t *testing.T) {
	for deployment, want := range map[string]any{
		"aws-claude-fable-5-1":                           nil,
		"aws-claude-fable-5-1-us":                        nil,
		"google-cloud-claude-fable-5-1-eu":               nil,
		"aws-claude-fable-5-1-anthropic-hosted":          "global",
		"google-cloud-claude-fable-5-1-anthropic-hosted": "global",
	} {
		state := resolveCloudState(t, "/v1/responses", deployment, `"input":"hi",`)
		if err := state.Adapter.ValidateRequest(state); err != nil {
			t.Fatal(err)
		}
		if err := state.Adapter.SanitizeRequest(state); err != nil {
			t.Fatal(err)
		}
		request, err := state.Resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
		if err != nil {
			t.Fatal(err)
		}
		params := request.ResponsesRequest.Params
		if got := params.ExtraParams["inference_geo"]; got != want || params.ExtraParams["speed"] != nil || params.ServiceTier != nil {
			t.Errorf("%s: params %v, tier %v, want inference_geo %v", deployment, params.ExtraParams, params.ServiceTier, want)
		}
	}
}

// Every hosting keeps a system message in place after the conversation starts, as
// Anthropic documents on every platform that runs Claude.
func TestCloudClaudeKeepsMidConversationSystemMessagesInPlace(t *testing.T) {
	body := `"messages":[{"role":"user","content":"first"},{"role":"developer","content":"new policy"},{"role":"assistant","content":"answer"},{"role":"user","content":"continue"}],`
	for _, deployment := range []string{
		"aws-claude-fable-5-1",
		"google-cloud-claude-fable-5-1",
		"aws-claude-fable-5-1-anthropic-hosted",
		"google-cloud-claude-fable-5-1-anthropic-hosted",
	} {
		state := resolveCloudState(t, "/v1/chat/completions", deployment, body)
		if err := state.Adapter.ValidateRequest(state); err != nil {
			t.Fatalf("%s: %v", deployment, err)
		}
		if err := state.Adapter.SanitizeRequest(state); err != nil {
			t.Fatalf("%s: %v", deployment, err)
		}
		ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
		request, err := state.Resolution.ToBifrost(ctx)
		if err != nil {
			t.Fatalf("%s: %v", deployment, err)
		}
		wire, bifrostErr := prepareChatProviderBody(ctx, request.ChatRequest, false, state.Resolution.Deployment.Hosting)
		if bifrostErr != nil {
			t.Fatalf("%s: %v", deployment, bifrostErr.Error)
		}
		var roles []string
		for _, message := range providerutils.GetJSONField(wire, "messages").Array() {
			roles = append(roles, message.Get("role").String())
		}
		if strings.Join(roles, " ") != "user system assistant user" {
			t.Errorf("%s: roles %v: %s", deployment, roles, wire)
		}
	}
}

// Every hosting gets the output format natively and keeps the client's strict
// tools, although core's tables drop strict where AWS or Google runs Claude.
// Every hosting gets fine-grained tool streaming on each function tool of a
// streamed request, which core would add on some hostings and models only, with
// a beta header. The edge-cases note describes both; update it when they change.
func TestCloudClaudeKeepsStrictToolsOnEveryHosting(t *testing.T) {
	format := `"type":"json_schema","strict":true,"schema":{"type":"object","properties":{"a":{"type":"string"}},"required":["a"],"additionalProperties":false}`
	parameters := `"parameters":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"],"additionalProperties":false}`
	routes := map[string]string{
		"/v1/chat/completions": `"messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"answer",` + format[len(`"type":"json_schema",`):] + `}},` +
			`"tools":[{"type":"function","function":{"name":"lookup","strict":true,` + parameters + `}},{"type":"function","function":{"name":"loose",` + parameters + `}}],`,
		"/v1/responses": `"input":"hi","text":{"format":{"name":"answer",` + format + `}},` +
			`"tools":[{"type":"function","name":"lookup","strict":true,` + parameters + `},{"type":"function","name":"loose","strict":false,` + parameters + `}],`,
	}
	for path, body := range routes {
		for _, deployment := range []string{
			"aws-claude-fable-5-1",
			"aws-claude-fable-5-1-us",
			"google-cloud-claude-fable-5-1",
			"aws-claude-fable-5-1-anthropic-hosted",
			"google-cloud-claude-fable-5-1-anthropic-hosted",
		} {
			for _, streaming := range []bool{false, true} {
				state := resolveCloudState(t, path, deployment, body)
				if err := state.Adapter.ValidateRequest(state); err != nil {
					t.Fatalf("%s %s: %v", path, deployment, err)
				}
				if err := state.Adapter.SanitizeRequest(state); err != nil {
					t.Fatalf("%s %s: %v", path, deployment, err)
				}
				ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
				request, err := state.Resolution.ToBifrost(ctx)
				if err != nil {
					t.Fatalf("%s %s: %v", path, deployment, err)
				}
				hosting := state.Resolution.Deployment.Hosting
				var wire []byte
				var bifrostErr *schemas.BifrostError
				if request.ChatRequest != nil {
					wire, bifrostErr = prepareChatProviderBody(ctx, request.ChatRequest, streaming, hosting)
				} else {
					wire, bifrostErr = prepareResponsesProviderBody(ctx, request.ResponsesRequest, streaming, hosting)
				}
				if bifrostErr != nil {
					t.Fatalf("%s %s: %v", path, deployment, bifrostErr.Error)
				}
				tools := providerutils.GetJSONField(wire, "tools").Array()
				if len(tools) != 2 || !providerutils.JSONFieldExists(wire, "output_config.format") || strings.Contains(string(wire), `"bf_so_`) {
					t.Fatalf("%s %s: wire %s", path, deployment, wire)
				}
				lookup, loose := tools[0], tools[1]
				if lookup.Get("name").String() != "lookup" || !lookup.Get("strict").Bool() || loose.Get("strict").Bool() {
					t.Errorf("%s %s: strict lost or added: %s", path, deployment, wire)
				}
				// A whole request carries the same tools as a stream, because Claude compares them before it
				// accepts earlier reasoning.
				for _, tool := range tools {
					if !tool.Get("eager_input_streaming").Bool() {
						t.Errorf("%s %s streaming %v: eager_input_streaming: %s", path, deployment, streaming, wire)
					}
				}
				if strings.Contains(string(wire), "structured-outputs-") || strings.Contains(string(wire), "fine-grained-tool-streaming-") ||
					hosting == hostingAmazon && strings.Contains(string(wire), "anthropic_beta") {
					t.Errorf("%s %s: unneeded beta: %s", path, deployment, wire)
				}
			}
		}
	}
}

// Claude's own fields reach every hosting as the client sent them, on both routes: a top-level
// cache_control, which Bedrock's Messages API took and cached in the capture, context_management,
// and task_budget with its beta, which Anthropic documents everywhere but on Bedrock, whose
// validation refuses it.
func TestClaudeFieldsReachEveryHosting(t *testing.T) {
	var taken bytes.Buffer
	if err := json.Compact(&taken, []byte(providerutils.GetJSONField(exchange(t, providerCapture(t, "aws/automatic-prompt-caching"), "first request").Request.Body, "cache_control").Raw)); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"cache_control":             taken.String(),
		"context_management":        `{"edits":[{"type":"clear_tool_uses_20250919"}]}`,
		"output_config.task_budget": `{"type":"tokens","total":20000}`,
	}
	for _, deployment := range []string{
		"aws-claude-fable-5-1", "aws-claude-fable-5-1-anthropic-hosted",
		"google-cloud-claude-fable-5-1", "google-cloud-claude-fable-5-1-anthropic-hosted",
		"azure-claude-haiku-5-5", "azure-claude-haiku-5-5-anthropic-hosted",
	} {
		budget := deployment != "aws-claude-fable-5-1"
		fields := `"cache_control":` + want["cache_control"] + `,"context_management":` + want["context_management"] + `,`
		if budget {
			fields += `"task_budget":` + want["output_config.task_budget"] + `,`
		}
		for path, input := range map[string]string{
			"/v1/chat/completions": `"messages":[{"role":"user","content":"hi"}],`,
			"/v1/responses":        `"input":"hi",`,
		} {
			state := resolveCloudState(t, path, deployment, input+fields)
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("%s %s: %v", path, deployment, err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("%s %s: %v", path, deployment, err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, state.Resolution.RequestType)
			request, err := state.Resolution.ToBifrost(ctx)
			if err != nil {
				t.Fatalf("%s %s: %v", path, deployment, err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatalf("%s %s: %v", path, deployment, err)
			}
			var wire []byte
			if request.ChatRequest != nil {
				wire = preparedProviderBody(t, ctx, request.ChatRequest)
			} else {
				wire = preparedProviderBody(t, ctx, request.ResponsesRequest)
			}
			for field, value := range want {
				if sent := providerutils.GetJSONField(wire, field).Raw; sent != value && (budget || field != "output_config.task_budget") {
					t.Errorf("%s %s: %s %s, want %s: %s", path, deployment, field, sent, value, wire)
				}
			}
			// Google takes betas in the body, the other hostings in a header.
			headers, _ := ctx.Value(schemas.BifrostContextKeyExtraHeaders).(map[string][]string)
			betas := append(headers["anthropic-beta"], providerutils.GetJSONField(wire, "anthropic_beta").String())
			if budget && !strings.Contains(strings.Join(betas, ","), "task-budgets-2026-03-13") {
				t.Errorf("%s %s: no task budget beta in %v", path, deployment, betas)
			}
		}
	}
}
