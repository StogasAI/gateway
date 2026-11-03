package stogas

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/googleauth"
)

// seenRequest is what a provider received, with the host that the gateway dialed.
type seenRequest struct {
	method, host, path, query string
	header                    http.Header
	body                      string
}

// redirectAll sends every request to server, keeping the host that the gateway asked for, as the
// fixed AWS hosts cannot be reached from a test.
type redirectAll struct{ server *httptest.Server }

func (r redirectAll) RoundTrip(request *http.Request) (*http.Response, error) {
	target, _ := url.Parse(r.server.URL)
	copied := request.Clone(request.Context())
	copied.Header.Set("X-Test-Host", request.URL.Host)
	copied.URL.Scheme, copied.URL.Host = target.Scheme, target.Host
	return http.DefaultTransport.RoundTrip(copied)
}

type googleSignInFunc func(context.Context, googleauth.Credential) error

func (f googleSignInFunc) SignIn(ctx context.Context, credential googleauth.Credential) error {
	return f(ctx, credential)
}

func byokCheckTestServer(t *testing.T, status *int) (*httptest.Server, func() []seenRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []seenRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		host := r.Header.Get("X-Test-Host")
		if host == "" {
			host = r.Host
		}
		mu.Lock()
		seen = append(seen, seenRequest{method: r.Method, host: host, path: r.URL.Path, query: r.URL.RawQuery, header: r.Header.Clone(), body: string(body)})
		mu.Unlock()
		if *status >= 300 && *status < 400 {
			w.Header().Set("Location", "https://example.com/")
		}
		w.WriteHeader(*status)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(server.Close)
	return server, func() []seenRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]seenRequest(nil), seen...)
	}
}

func newTestByokChecker(server *httptest.Server, google googleSignIn, now time.Time) *byokChecker {
	client := &http.Client{Transport: http.DefaultTransport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	awsClient := &http.Client{Transport: redirectAll{server}, Timeout: time.Second, CheckRedirect: client.CheckRedirect}
	return &byokChecker{
		openAIBaseURL: server.URL, anthropicBaseURL: server.URL, chutesAPIBaseURL: server.URL,
		client: client, aws: awsClient, google: google, now: func() time.Time { return now },
		slots: make(chan struct{}, byokCheckLimit),
	}
}

func TestByokCheckReadsEachProviderAsControlDoes(t *testing.T) {
	status := http.StatusOK
	server, seen := byokCheckTestServer(t, &status)
	now := time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC)
	checker := newTestByokChecker(server, nil, now)
	ctx := context.Background()

	for _, provider := range []string{"openai", "anthropic", "chutes"} {
		if failure := checker.check(ctx, provider, "secret-"+provider, nil); failure != "" {
			t.Fatalf("%s: %s", provider, failure)
		}
	}
	requests := seen()
	if len(requests) != 3 {
		t.Fatalf("requests = %d", len(requests))
	}
	if r := requests[0]; r.method != http.MethodGet || r.path != "/v1/models" || r.header.Get("Authorization") != "Bearer secret-openai" {
		t.Fatalf("OpenAI request = %+v", r)
	}
	if r := requests[1]; r.path != "/v1/models" || r.query != "limit=1" || r.header.Get("x-api-key") != "secret-anthropic" ||
		r.header.Get("anthropic-version") != "2023-06-01" || r.header.Get("Authorization") != "" {
		t.Fatalf("Anthropic request = %+v", r)
	}
	if r := requests[2]; r.path != "/users/me/quotas" || r.header.Get("Authorization") != "Bearer secret-chutes" {
		t.Fatalf("Chutes request = %+v", r)
	}

	// Only a provider's refusal rejects the credential; a refusal that a retry can clear, an outage
	// or a redirect leaves it unverified, as in Control's check.
	for code, want := range map[int]string{
		200: "", 204: "",
		400: byokRejected("openai"), 401: byokRejected("openai"), 403: byokRejected("openai"), 404: byokRejected("openai"),
		408: byokUnavailable("openai"), 409: byokUnavailable("openai"), 425: byokUnavailable("openai"), 429: byokUnavailable("openai"),
		302: byokUnavailable("openai"), 500: byokUnavailable("openai"), 503: byokUnavailable("openai"),
	} {
		status = code
		if got := checker.check(ctx, "openai", "sk-test", nil); got != want {
			t.Fatalf("status %d: %q, want %q", code, got, want)
		}
	}
	if byokRejected("openai") != "OpenAI did not accept this API key or configuration" ||
		byokUnavailable("aws") != "Could not verify the AWS credential. Try again." {
		t.Fatal("messages differ from Control's")
	}

	// A secret that no request could send is refused before any provider call.
	before := len(seen())
	if got := checker.check(ctx, "openai", "sk test", nil); got != invalidByokSecret("openai") {
		t.Fatalf("invalid secret: %q", got)
	}
	if len(seen()) != before {
		t.Fatal("an invalid secret reached the provider")
	}

	unreachable := newTestByokChecker(server, nil, now)
	unreachable.openAIBaseURL = "http://127.0.0.1:1"
	status = http.StatusOK
	if got := unreachable.check(ctx, "openai", "sk-test", nil); got != byokUnavailable("openai") {
		t.Fatalf("unreachable provider: %q", got)
	}
}

// verifySigV4 recomputes a SigV4 signature over the headers that it names, as AWS does.
func verifySigV4(t *testing.T, r seenRequest, service, region string) {
	t.Helper()
	authorization := r.header.Get("Authorization")
	prefix := "AWS4-HMAC-SHA256 Credential=" + testAWSAccessKeyID + "/"
	if !strings.HasPrefix(authorization, prefix) {
		t.Fatalf("Authorization = %q", authorization)
	}
	parts := strings.Split(strings.TrimPrefix(authorization, "AWS4-HMAC-SHA256 "), ", ")
	if len(parts) != 3 {
		t.Fatalf("Authorization = %q", authorization)
	}
	scope := strings.TrimPrefix(parts[0], "Credential="+testAWSAccessKeyID+"/")
	signed := strings.Split(strings.TrimPrefix(parts[1], "SignedHeaders="), ";")
	amzDate := r.header.Get("X-Amz-Date")
	if scope != amzDate[:8]+"/"+region+"/"+service+"/aws4_request" {
		t.Fatalf("scope = %q", scope)
	}
	var canonicalHeaders []string
	for _, name := range signed {
		value := r.header.Get(name)
		if name == "host" {
			value = r.host
		}
		canonicalHeaders = append(canonicalHeaders, name+":"+strings.TrimSpace(value))
	}
	payload := sha256.Sum256([]byte(r.body))
	canonical := strings.Join([]string{r.method, r.path, r.query, strings.Join(canonicalHeaders, "\n") + "\n", strings.Join(signed, ";"), hex.EncodeToString(payload[:])}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	mac := func(key []byte, data string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(data))
		return h.Sum(nil)
	}
	key := mac(mac(mac(mac([]byte("AWS4"+testAWSSecretKey), amzDate[:8]), region), service), "aws4_request")
	want := hex.EncodeToString(mac(key, "AWS4-HMAC-SHA256\n"+amzDate+"\n"+scope+"\n"+hex.EncodeToString(digest[:])))
	if parts[2] != "Signature="+want {
		t.Fatalf("signature = %q, want %q", parts[2], want)
	}
}

func TestByokCheckSignsInToAWSWithEachKindOfCredential(t *testing.T) {
	status := http.StatusOK
	server, seen := byokCheckTestServer(t, &status)
	now := time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC)
	checker := newTestByokChecker(server, nil, now)
	ctx := context.Background()

	cases := []struct {
		secret   string
		target   billing.CloudTarget
		method   string
		host     string
		path     string
		query    string
		bearer   string
		workpace string
	}{
		{awsIAMSecret(t, "eu-west-1", ""), billing.CloudTarget{Hosting: []string{"aws"}, Region: "eu-west-1"},
			http.MethodPost, "sts.eu-west-1.amazonaws.com", "/", "", "", ""},
		{awsAPIKeySecret(t, "us-east-1", ""), billing.CloudTarget{Hosting: []string{"aws"}, Region: "us-east-1"},
			http.MethodGet, "bedrock.us-east-1.amazonaws.com", "/foundation-models", "byProvider=Anthropic", "customer-api-key", ""},
		{awsAPIKeySecret(t, "us-west-2", testWorkspaceID), billing.CloudTarget{Hosting: []string{"anthropic"}, Region: "us-west-2"},
			http.MethodGet, "aws-external-anthropic.us-west-2.api.aws", "/v1/models", "limit=1", "customer-api-key", testWorkspaceID},
	}
	for i, c := range cases {
		if failure := checker.check(ctx, "aws", c.secret, &c.target); failure != "" {
			t.Fatalf("case %d: %s", i, failure)
		}
		r := seen()[i]
		if r.method != c.method || r.host != c.host || r.path != c.path || r.query != c.query {
			t.Fatalf("case %d request = %+v", i, r)
		}
		if c.bearer != "" && r.header.Get("Authorization") != "Bearer "+c.bearer {
			t.Fatalf("case %d Authorization = %q", i, r.header.Get("Authorization"))
		}
		if r.header.Get("anthropic-workspace-id") != c.workpace {
			t.Fatalf("case %d workspace = %q", i, r.header.Get("anthropic-workspace-id"))
		}
	}
	sts := seen()[0]
	if sts.body != stsRequestBody || sts.header.Get("Content-Type") != "application/x-www-form-urlencoded; charset=utf-8" {
		t.Fatalf("STS request = %+v", sts)
	}
	verifySigV4(t, sts, "sts", "eu-west-1")

	status = http.StatusForbidden
	if got := checker.check(ctx, "aws", awsIAMSecret(t, "eu-west-1", ""), &billing.CloudTarget{Hosting: []string{"aws"}, Region: "eu-west-1"}); got != byokRejected("aws") {
		t.Fatalf("rejected access key: %q", got)
	}
}

func TestByokCheckHoldsCloudSecretsToTheirTarget(t *testing.T) {
	status := http.StatusOK
	server, seen := byokCheckTestServer(t, &status)
	var signIns []googleauth.Credential
	google := googleSignInFunc(func(_ context.Context, credential googleauth.Credential) error {
		signIns = append(signIns, credential)
		return nil
	})
	checker := newTestByokChecker(server, google, time.Now())
	ctx := context.Background()

	for name, c := range map[string]struct {
		provider, secret string
		target           *billing.CloudTarget
	}{
		"another Region":     {"aws", awsIAMSecret(t, "eu-west-1", ""), &billing.CloudTarget{Hosting: []string{"aws"}, Region: "us-east-1"}},
		"no workspace":       {"aws", awsIAMSecret(t, "us-east-1", ""), &billing.CloudTarget{Hosting: []string{"anthropic", "aws"}, Region: "us-east-1"}},
		"no target":          {"aws", awsIAMSecret(t, "us-east-1", ""), nil},
		"Google workspace":   {"google-cloud", googleSecret(t, ""), &billing.CloudTarget{Hosting: []string{"anthropic", "google"}}},
		"Google with Region": {"google-cloud", googleSecret(t, ""), &billing.CloudTarget{Hosting: []string{"google"}, Region: "us"}},
	} {
		if got := checker.check(ctx, c.provider, c.secret, c.target); got == "" || !strings.Contains(got, "stogas encrypt printed") {
			t.Fatalf("%s: %q", name, got)
		}
	}
	if len(seen()) != 0 || len(signIns) != 0 {
		t.Fatal("a secret that cannot serve its target reached the provider")
	}

	// Requests parse a secret the same way, so these would fail at every request too.
	for _, secret := range []string{`{"schema":"stogas.aws-byok.v1"}`, "not json", awsIAMSecret(t, "mars-north-1", ""), strings.Replace(awsIAMSecret(t, "us-east-1", ""), `"region"`, `"unknown":"x","region"`, 1)} {
		if got := checker.check(ctx, "aws", secret, &billing.CloudTarget{Hosting: []string{"aws"}, Region: "us-east-1"}); got != invalidByokSecret("aws") {
			t.Fatalf("invalid AWS secret: %q", got)
		}
	}

	target := &billing.CloudTarget{Hosting: []string{"google"}}
	if got := checker.check(ctx, "google-cloud", googleSecret(t, ""), target); got != "" {
		t.Fatalf("Google: %q", got)
	}
	if len(signIns) != 1 || signIns[0].ClientEmail != "runner@stogas-test.iam.gserviceaccount.com" || signIns[0].PrivateKeyID != testGoogleKeyID {
		t.Fatalf("sign-ins = %+v", signIns)
	}
	for err, want := range map[error]string{
		googleauth.ErrCredential:  byokRejected("google-cloud"),
		googleauth.ErrUnavailable: byokUnavailable("google-cloud"),
	} {
		checker.google = googleSignInFunc(func(context.Context, googleauth.Credential) error { return err })
		if got := checker.check(ctx, "google-cloud", googleSecret(t, ""), target); got != want {
			t.Fatalf("%v: %q", err, got)
		}
	}
}

type fakeByokCheckStore struct {
	target   *billing.ByokCheckTarget
	readErr  error
	recorded []string
	record   error
}

func (s *fakeByokCheckStore) ByokCheckTarget(context.Context, *billing.ByokCheckGrant) (*billing.ByokCheckTarget, error) {
	return s.target, s.readErr
}

func (s *fakeByokCheckStore) RecordByokCheck(_ context.Context, _ *billing.ByokCheckTarget, failure string) (time.Time, error) {
	s.recorded = append(s.recorded, failure)
	return time.Date(2026, time.November, 3, 12, 0, 1, 0, time.UTC), s.record
}

func TestCheckByokRecordsWhatTheProviderAnswered(t *testing.T) {
	status := http.StatusOK
	server, seen := byokCheckTestServer(t, &status)
	checker := newTestByokChecker(server, nil, time.Now())
	ctx := context.Background()
	grant := &billing.ByokCheckGrant{}

	// A target whose key the request lacks fails before any provider call and records nothing.
	store := &fakeByokCheckStore{target: &billing.ByokCheckTarget{Provider: "openai", EncryptionKeyID: strings.Repeat("a", 64)}}
	if _, err := checkByok(ctx, store, checker, grant, customerkey.Keys{}); !errors.Is(err, billing.ErrByokKeyUnregistered) {
		t.Fatalf("unregistered key: %v", err)
	}
	if len(store.recorded) != 0 || len(seen()) != 0 {
		t.Fatal("a check that could not open its credential went on")
	}
	store = &fakeByokCheckStore{readErr: billing.ErrByokCheckStored}
	if _, err := checkByok(ctx, store, checker, grant, customerkey.Keys{}); !errors.Is(err, billing.ErrByokCheckStored) {
		t.Fatalf("stored credential: %v", err)
	}

	root := make([]byte, 32)
	keys, err := customerkey.ParseKeys(map[string]string{"prod": base64.RawURLEncoding.EncodeToString(root)})
	if err != nil {
		t.Fatal(err)
	}
	organizationID := "0196f0f4-0000-7000-8000-000000000001"
	target := &billing.ByokCheckTarget{
		Grant:    billing.ByokCheckGrant{OrganizationID: organizationID},
		Provider: "openai", EncryptionKeyID: keys["prod"].ID(),
		EncryptedSecret: sealTestByokSecret(t, root, keys["prod"].ID(), organizationID, "byok/openai", "sk-sealed"),
		Registered:      map[string]string{"prod": keys["prod"].ID()},
	}
	for code, want := range map[int]string{http.StatusOK: "", http.StatusUnauthorized: byokRejected("openai")} {
		status = code
		store = &fakeByokCheckStore{target: target}
		result, err := checkByok(ctx, store, checker, grant, keys)
		if err != nil {
			t.Fatal(err)
		}
		if len(store.recorded) != 1 || store.recorded[0] != want || result.CheckedAt.IsZero() ||
			(want == "") != (result.CheckError == nil) || (result.CheckError != nil && *result.CheckError != want) {
			t.Fatalf("status %d: recorded %q, result %+v", code, store.recorded, result)
		}
	}
	if r := seen()[len(seen())-1]; r.header.Get("Authorization") != "Bearer sk-sealed" {
		t.Fatalf("the provider got %q", r.header.Get("Authorization"))
	}
	store = &fakeByokCheckStore{target: target, record: billing.ErrByokCheckChanged}
	if _, err := checkByok(ctx, store, checker, grant, keys); !errors.Is(err, billing.ErrByokCheckChanged) {
		t.Fatalf("changed during the check: %v", err)
	}
}

// sealTestByokSecret seals plaintext as stogas encrypt does.
func sealTestByokSecret(t *testing.T, root []byte, keyID, organizationID, purpose, plaintext string) string {
	t.Helper()
	salt, nonce := make([]byte, 32), make([]byte, 12)
	context := strings.Join([]string{"stogas.customer-content.v1", organizationID, purpose, keyID}, "\x00")
	derived, err := hkdf.Key(sha256.New, root, salt, context, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(customerkey.Envelope{
		Version: 1, KeyID: keyID,
		Salt:  base64.RawURLEncoding.EncodeToString(salt),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		Blob:  base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, []byte(plaintext), []byte(context))),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
