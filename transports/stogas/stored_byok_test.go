package stogas

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/azureauth"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/googleauth"
)

// fakeStoredOpener opens the envelope "sealed" as secret, as the gateway opens what Control sealed
// for a grant's credential, and refuses any other envelope.
type fakeStoredOpener struct {
	secret string
	opened int
}

func (o *fakeStoredOpener) OpenStoredByok(_ *billing.StoredByokGrant, envelope string) (string, error) {
	if envelope != "sealed" {
		return "", billing.ErrStoredByokSecret
	}
	o.opened++
	return o.secret, nil
}

func storedTestGrant(provider, scope string) *billing.StoredByokGrant {
	return &billing.StoredByokGrant{
		OrganizationID: "0196f0f4-0000-7000-8000-000000000001", ByokID: "0196f0f4-0000-7000-8000-000000000002",
		Provider: provider, Scope: scope,
	}
}

const (
	storedTestApp = `{"clientId":"00000000-0000-4000-8000-000000000002","clientSecret":"azure-client-secret","schema":"stogas.azure-byok.v6","tenantId":"00000000-0000-4000-8000-000000000001"}`
	// An account that no test serves, for requests that the gateway refuses before it reads Azure.
	storedTestAccount = "/subscriptions/00000000-0000-4000-8000-000000000003/resourcegroups/stogas/providers/microsoft.cognitiveservices/accounts/stogas-east"
)

func encodeJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestProbeStoredByokChecksTheSealedSecret(t *testing.T) {
	status := http.StatusOK
	server, seen := byokCheckTestServer(t, &status)
	checker := newTestByokChecker(server, nil, time.Now())
	ctx := context.Background()
	grant := storedTestGrant("openai", billing.StoredByokProbe)
	opener := &fakeStoredOpener{secret: "sk-stored"}

	for code, want := range map[int]string{
		http.StatusOK:                 `{"outcome":"accepted","message":null}`,
		http.StatusUnauthorized:       `{"outcome":"rejected","message":"` + byokRejected("openai") + `"}`,
		http.StatusServiceUnavailable: `{"outcome":"unavailable","message":"` + byokUnavailable("openai") + `"}`,
	} {
		status = code
		got, err := probeStoredByok(ctx, opener, checker, grant, StoredByokProbeRequest{Secret: "sealed"})
		if err != nil {
			t.Fatal(err)
		}
		if encoded := encodeJSON(t, got); encoded != want {
			t.Fatalf("status %d: %s, want %s", code, encoded, want)
		}
	}
	if r := seen()[len(seen())-1]; r.path != "/v1/models" || r.header.Get("Authorization") != "Bearer sk-stored" {
		t.Fatalf("the provider got %+v", r)
	}

	// The gateway refuses a request that does not fit its grant before it opens the secret.
	status = http.StatusOK
	before, opened := len(seen()), opener.opened
	azure := storedTestGrant("azure", billing.StoredByokProbe)
	for name, c := range map[string]struct {
		grant   *billing.StoredByokGrant
		request StoredByokProbeRequest
		want    error
	}{
		"no grant":                    {nil, StoredByokProbeRequest{Secret: "sealed"}, billing.ErrStoredByokGrant},
		"an account listing grant":    {storedTestGrant("azure", billing.StoredByokAzureAccounts), StoredByokProbeRequest{Secret: "sealed", AzureAccountID: storedTestAccount}, billing.ErrStoredByokGrant},
		"no secret":                   {grant, StoredByokProbeRequest{}, billing.ErrStoredByokRequest},
		"an Azure account for OpenAI": {grant, StoredByokProbeRequest{Secret: "sealed", AzureAccountID: storedTestAccount}, billing.ErrStoredByokRequest},
		"Azure without an account":    {azure, StoredByokProbeRequest{Secret: "sealed"}, billing.ErrStoredByokRequest},
		"Azure with an uppercase account": {azure, StoredByokProbeRequest{
			Secret: "sealed", AzureAccountID: strings.ToUpper(storedTestAccount),
		}, billing.ErrStoredByokRequest},
		"another credential's secret": {grant, StoredByokProbeRequest{Secret: "other"}, billing.ErrStoredByokSecret},
		"AWS without a target":        {storedTestGrant("aws", billing.StoredByokProbe), StoredByokProbeRequest{Secret: "sealed"}, billing.ErrStoredByokRequest},
		"a target for OpenAI": {grant, StoredByokProbeRequest{
			Secret: "sealed", Target: &billing.CloudTarget{Hosting: []string{"amazon"}, Region: "us-east-1"},
		}, billing.ErrStoredByokRequest},
	} {
		if _, err := probeStoredByok(ctx, opener, checker, c.grant, c.request); !errors.Is(err, c.want) {
			t.Fatalf("%s: %v, want %v", name, err, c.want)
		}
	}
	if len(seen()) != before || opener.opened != opened {
		t.Fatal("a refused request opened its secret or reached the provider")
	}

	// The probe holds a cloud secret to the target that Control would store beside it, as requests
	// do, and reaches the target's own host.
	awsTarget := &billing.CloudTarget{Hosting: []string{"amazon"}, Region: "eu-west-1"}
	opener.secret = awsIAMSecret(t, "eu-west-1", "")
	got, err := probeStoredByok(ctx, opener, checker, storedTestGrant("aws", billing.StoredByokProbe), StoredByokProbeRequest{Secret: "sealed", Target: awsTarget})
	if err != nil || got.Outcome != storedByokAccepted || seen()[len(seen())-1].host != "sts.eu-west-1.amazonaws.com" {
		t.Fatalf("AWS: %+v, %v", got, err)
	}
	var signIns []googleauth.Credential
	checker.google = googleSignInFunc(func(_ context.Context, credential googleauth.Credential) error {
		signIns = append(signIns, credential)
		return nil
	})
	googleTarget := &billing.CloudTarget{Hosting: []string{"anthropic", "google"}}
	opener.secret = googleSecret(t, testWorkspaceID)
	got, err = probeStoredByok(ctx, opener, checker, storedTestGrant("google-cloud", billing.StoredByokProbe), StoredByokProbeRequest{Secret: "sealed", Target: googleTarget})
	if err != nil || got.Outcome != storedByokAccepted || len(signIns) != 1 {
		t.Fatalf("Google Cloud: %+v, %v", got, err)
	}
	// Control derives the stored target from the secret as gateways do, so a secret that cannot
	// serve it means that the two read it differently, which is ours to fix, and no call follows.
	before = len(seen())
	for name, c := range map[string]struct {
		provider, secret string
		target           *billing.CloudTarget
	}{
		"AWS in another Region":   {"aws", awsIAMSecret(t, "us-east-1", ""), awsTarget},
		"Google without Claude":   {"google-cloud", googleSecret(t, ""), googleTarget},
		"AWS without a workspace": {"aws", awsIAMSecret(t, "eu-west-1", ""), &billing.CloudTarget{Hosting: []string{"amazon", "anthropic"}, Region: "eu-west-1"}},
	} {
		opener.secret = c.secret
		got, err := probeStoredByok(ctx, opener, checker, storedTestGrant(c.provider, billing.StoredByokProbe), StoredByokProbeRequest{Secret: "sealed", Target: c.target})
		if got != nil || !errors.Is(err, billing.ErrStoredByokTarget) {
			t.Fatalf("%s: %+v, %v", name, got, err)
		}
	}
	if len(seen()) != before || len(signIns) != 1 {
		t.Fatal("a secret that cannot serve its target reached the provider")
	}
	// Control reads only the form of a new secret, so a secret that is not its provider's credential
	// is refused as the member's to replace, without a call. Control's contract takes this Google key,
	// which is base64 but not an RSA key.
	notRSA := cloudSecret(t, map[string]string{
		"schema": googleCloudByokSchema, "projectId": "stogas-test", "clientEmail": "runner@stogas-test.iam.gserviceaccount.com",
		"privateKeyId": testGoogleKeyID, "privateKey": base64.StdEncoding.EncodeToString([]byte("not an RSA key")),
	})
	before = len(seen())
	for provider, test := range map[string]struct {
		secret, want string
		target       *billing.CloudTarget
	}{
		"aws":          {"not json", "The secret is not a valid AWS credential", awsTarget},
		"google-cloud": {notRSA, "The secret is not a valid Google Cloud credential", googleTarget},
		"openai":       {"sk stored", "The secret is not a valid OpenAI API key", nil},
	} {
		opener.secret = test.secret
		got, err := probeStoredByok(ctx, opener, checker, storedTestGrant(provider, billing.StoredByokProbe), StoredByokProbeRequest{Secret: "sealed", Target: test.target})
		if err != nil || got.Outcome != storedByokRejected || got.Message == nil || *got.Message != test.want {
			t.Fatalf("an invalid %s secret: %+v, %v", provider, got, err)
		}
	}
	if len(seen()) != before || len(signIns) != 1 {
		t.Fatal("an invalid secret reached the provider")
	}
}

// OpenAI refuses a restricted key that may not list models with a 401 that names the missing
// permission. It knows the key, which serves what its permissions allow, so the check accepts it,
// with or without the refusal's code, and still rejects a key that OpenAI does not know.
func TestByokCheckAcceptsAnOpenAIKeyThatMayNotListModels(t *testing.T) {
	body := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	checker := newTestByokChecker(server, nil, time.Now())
	for name, test := range map[string]struct {
		body     string
		rejected bool
	}{
		"a missing permission":              {`{"error":{"message":"You have insufficient permissions for this operation. Missing scopes: api.model.read.","type":"invalid_request_error","code":"missing_scope"}}`, false},
		"a missing permission without code": {`{"error":{"message":"You have insufficient permissions for this operation. Missing scopes: api.model.read.","type":"invalid_request_error"}}`, false},
		"an unknown key":                    {`{"error":{"message":"Incorrect API key provided: sk-store*.","type":"invalid_request_error","code":"invalid_api_key"}}`, true},
		"no JSON":                           {`unauthorized`, true},
	} {
		body = test.body
		failure := checker.check(context.Background(), "0196f0f4-0000-7000-8000-000000000001", "openai", "sk-stored", nil)
		if failure.rejected != test.rejected || (failure.message == "") == test.rejected {
			t.Fatalf("%s: %+v", name, failure)
		}
	}
	// Other providers' refusals with the same words stay refusals.
	body = `{"error":{"message":"You have insufficient permissions for this operation.","code":"missing_scope"}}`
	if failure := checker.check(context.Background(), "0196f0f4-0000-7000-8000-000000000001", "anthropic", "sk-ant-stored", nil); !failure.rejected {
		t.Fatalf("Anthropic: %+v", failure)
	}
}

// A probe of an Azure application signs in anew and reads the account that it would connect, and
// leaves the account's targets to the check that follows the save.
func TestProbeStoredByokReadsTheAzureAccount(t *testing.T) {
	status := http.StatusOK
	server, _ := byokCheckTestServer(t, &status)
	grant := storedTestGrant("azure", billing.StoredByokProbe)
	probe := func(name, plaintext string, signIn *fakeAzureSignIn) (*StoredByokProbe, azureDiscoveryCase, *azureDiscoveryARM) {
		t.Helper()
		entry := azureDiscoveryCaseNamed(t, name)
		arm, client := serveAzureDiscoveryCase(t, entry)
		checker := newTestByokChecker(server, nil, time.Now())
		checker.arm, checker.azure = client, signIn
		got, err := probeStoredByok(context.Background(), &fakeStoredOpener{secret: plaintext}, checker, grant,
			StoredByokProbeRequest{Secret: "sealed", AzureAccountID: entry.AccountID})
		if err != nil {
			t.Fatal(err)
		}
		return got, entry, arm
	}

	signIn := &fakeAzureSignIn{}
	got, entry, arm := probe("named-deployments", storedTestApp, signIn)
	if got.Outcome != storedByokAccepted || got.Message != nil || got.AccountName == nil || *got.AccountName != entry.Outcome.Result.Name {
		t.Fatalf("named deployments: %s", encodeJSON(t, got))
	}
	if len(signIn.calls) != 1 || signIn.calls[0].ClientID != "00000000-0000-4000-8000-000000000002" || signIn.calls[0].Scope != armScope {
		t.Fatalf("sign-ins = %+v", signIn.calls)
	}
	if answered, unexpected := arm.counts(); answered != 1 || len(unexpected) > 0 {
		t.Fatalf("a probe made %d Azure reads, and %v unexpected", answered, unexpected)
	}

	for _, test := range []struct {
		name, plaintext string
		signIn          *fakeAzureSignIn
		outcome, want   string
	}{
		{"account-denied", storedTestApp, &fakeAzureSignIn{}, storedByokRejected, azureAccountDenied},
		{"account-outage", storedTestApp, &fakeAzureSignIn{}, storedByokUnavailable, azureDiscoveryUnavailable},
		{"named-deployments", storedTestApp, &fakeAzureSignIn{err: azureauth.ErrCredential}, storedByokRejected, azureAppRejected},
		{"named-deployments", storedTestApp, &fakeAzureSignIn{err: azureauth.ErrUnavailable}, storedByokUnavailable, azureAppUnavailable},
		{"named-deployments", `{"clientId":"x"}`, &fakeAzureSignIn{}, storedByokRejected, "The secret is not a valid Azure application"},
	} {
		got, _, arm := probe(test.name, test.plaintext, test.signIn)
		answered, unexpected := arm.counts()
		if got.Outcome != test.outcome || got.Message == nil || *got.Message != test.want || got.AccountName != nil || len(unexpected) > 0 ||
			(test.name == "named-deployments" && answered != 0) {
			t.Fatalf("%s: %s after %d Azure reads", test.want, encodeJSON(t, got), answered)
		}
	}
}

// serveAzureAccounts answers each subscription's listing of Cognitive Services accounts for the
// token arm-token with list, and every other request with 418.
func serveAzureAccounts(t *testing.T, list func(w http.ResponseWriter, r *http.Request, subscriptionID string)) *http.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) != 6 || r.URL.Path != "/subscriptions/"+parts[2]+"/providers/Microsoft.CognitiveServices/accounts" ||
			!strings.HasPrefix(r.URL.RawQuery, "api-version="+armAPIVersion) || r.Header.Get("Authorization") != "Bearer arm-token" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		list(w, r, parts[2])
	}))
	t.Cleanup(server.Close)
	return &http.Client{Transport: armRedirect{server}}
}

func storedTestSubscription(index int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", index+10)
}

// armAccountJSON is a Cognitive Services account in a subscription as Azure lists it.
func armAccountJSON(subscriptionID, name, kind string, properties map[string]any) map[string]any {
	return map[string]any{
		"id":   "/subscriptions/" + subscriptionID + "/resourceGroups/Stogas/providers/Microsoft.CognitiveServices/accounts/" + name,
		"kind": kind, "location": " WestUS3 ", "name": " " + name + " ", "properties": properties,
	}
}

func foundryProperties(name string) map[string]any {
	return map[string]any{
		"customSubDomainName": name,
		"endpoints":           map[string]any{"AI Foundry API": "https://" + name + ".services.ai.azure.com/"},
	}
}

func listStoredTestAccounts(t *testing.T, client *http.Client, signIn *fakeAzureSignIn, plaintext string, subscriptionIDs ...string) *StoredAzureAccounts {
	t.Helper()
	status := http.StatusOK
	server, _ := byokCheckTestServer(t, &status)
	checker := newTestByokChecker(server, nil, time.Now())
	checker.arm, checker.azure = client, signIn
	got, err := listStoredAzureAccounts(context.Background(), &fakeStoredOpener{secret: plaintext}, checker,
		storedTestGrant("azure", billing.StoredByokAzureAccounts), StoredAzureAccountsRequest{Secret: "sealed", SubscriptionIDs: subscriptionIDs})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestListStoredAzureAccountsListsTheModelAccounts(t *testing.T) {
	first, second := storedTestSubscription(0), storedTestSubscription(1)
	var mu sync.Mutex
	var listed []string
	client := serveAzureAccounts(t, func(w http.ResponseWriter, r *http.Request, subscriptionID string) {
		mu.Lock()
		listed = append(listed, subscriptionID)
		mu.Unlock()
		var value []any
		switch {
		case subscriptionID == second:
			value = []any{
				armAccountJSON(second, "alpha", "OpenAI", map[string]any{"publicNetworkAccess": "Disabled"}),
				armAccountJSON(second, "beta", "AIServices", map[string]any{}),
				armAccountJSON(second, "gamma", "AIServices", map[string]any{"customSubDomainName": "gamma"}),
				// Azure generates a host for an Azure OpenAI account created without a subdomain.
				armAccountJSON(second, "delta", "OpenAI", map[string]any{
					"endpoints": map[string]any{"OpenAI Language Model Instance API": "https://delta.openai.azure.com/"},
				}),
			}
		case strings.Contains(r.URL.RawQuery, "$skiptoken=2"):
			value = []any{armAccountJSON(first, "eta", "aiservices", foundryProperties("eta"))}
		default:
			foreign := armAccountJSON(first, "foreign", "AIServices", foundryProperties("foreign"))
			foreign["id"] = strings.Replace(foreign["id"].(string), first, second, 1)
			value = []any{armAccountJSON(first, "zeta", "AIServices", foundryProperties("zeta")),
				armAccountJSON(first, "speech", "SpeechServices", map[string]any{}),
				foreign, 42, map[string]any{"id": "/subscriptions/" + first}}
			for _, id := range []string{
				"/subscriptions/" + first + "/resourceGroups/stogas/providers/Microsoft.Storage/accounts/stogas-east",
				"/subscriptions/" + first + "/resourceGroups/stogas/providers/Microsoft.CognitiveServices/accounts/stogas-east/extra",
				"/subscriptions/" + first + "/resourceGroups/stogas/providers/Microsoft.CognitiveServices/accounts/stogas\\east",
				"/subscriptions/" + first + "/resourceGroups/stogas/providers/Microsoft.CognitiveServices/accounts/stogas-east?query",
				"/subscriptions/" + first + "/resourceGroups/stogas/providers/Microsoft.CognitiveServices/accounts/stogas%2Feast",
			} {
				malformed := armAccountJSON(first, "malformed", "AIServices", foundryProperties("malformed"))
				malformed["id"] = id
				value = append(value, malformed)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value":    value,
				"nextLink": "https://management.azure.com/subscriptions/" + first + "/providers/Microsoft.CognitiveServices/accounts?api-version=" + armAPIVersion + "&$skiptoken=2",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": value})
	})

	signIn := &fakeAzureSignIn{}
	got := listStoredTestAccounts(t, client, signIn, storedTestApp, first, second)
	account := func(subscriptionID, name string) string {
		return "/subscriptions/" + subscriptionID + "/resourcegroups/stogas/providers/microsoft.cognitiveservices/accounts/" + name
	}
	want := fmt.Sprintf(`{"outcome":"accepted","message":null,"accounts":[`+
		`{"id":"%s","location":"westus3","name":"zeta","problem":null},`+
		`{"id":"%s","location":"westus3","name":"eta","problem":null},`+
		`{"id":"%s","location":"westus3","name":"alpha","problem":"network"},`+
		`{"id":"%s","location":"westus3","name":"beta","problem":"subdomain"},`+
		`{"id":"%s","location":"westus3","name":"gamma","problem":"endpoint"},`+
		`{"id":"%s","location":"westus3","name":"delta","problem":null}]}`,
		account(first, "zeta"), account(first, "eta"), account(second, "alpha"), account(second, "beta"), account(second, "gamma"), account(second, "delta"))
	if encoded := encodeJSON(t, got); encoded != want {
		t.Fatalf("accounts = %s\nwant %s", encoded, want)
	}
	if len(signIn.calls) != 1 || signIn.calls[0].Scope != armScope || len(listed) != 3 {
		t.Fatalf("sign-ins %+v, listings %v", signIn.calls, listed)
	}

	// An empty subscription lists no accounts, which is not a failure.
	empty := serveAzureAccounts(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		_, _ = w.Write([]byte(`{"value":[]}`))
	})
	if got := encodeJSON(t, listStoredTestAccounts(t, empty, &fakeAzureSignIn{}, storedTestApp, first)); got != `{"outcome":"accepted","message":null,"accounts":[]}` {
		t.Fatalf("empty subscription: %s", got)
	}
}

func TestListStoredAzureAccountsFailures(t *testing.T) {
	first := storedTestSubscription(0)
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		denied := serveAzureAccounts(t, func(w http.ResponseWriter, _ *http.Request, _ string) { w.WriteHeader(code) })
		want := `{"outcome":"rejected","message":"This application cannot list the accounts in subscription ` + first +
			`. Check the subscription ID and give the application the Foundry User role on the accounts.","accounts":[]}`
		if got := encodeJSON(t, listStoredTestAccounts(t, denied, &fakeAzureSignIn{}, storedTestApp, first)); got != want {
			t.Fatalf("status %d: %s", code, got)
		}
	}

	tooMany := serveAzureAccounts(t, func(w http.ResponseWriter, _ *http.Request, subscriptionID string) {
		value := make([]any, azureMaxAccounts+1)
		for index := range value {
			name := fmt.Sprintf("account-%d", index)
			value[index] = armAccountJSON(subscriptionID, name, "AIServices", foundryProperties(name))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": value})
	})
	if got := listStoredTestAccounts(t, tooMany, &fakeAzureSignIn{}, storedTestApp, first); got.Outcome != storedByokRejected ||
		*got.Message != "Azure returned too many model accounts" || len(got.Accounts) != 0 {
		t.Fatalf("too many accounts: %s", encodeJSON(t, got))
	}

	// Sign-in failures and an invalid application stop before Azure Resource Manager.
	var reads int
	var mu sync.Mutex
	unreached := serveAzureAccounts(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		mu.Lock()
		reads++
		mu.Unlock()
		_, _ = w.Write([]byte(`{"value":[]}`))
	})
	for _, test := range []struct {
		plaintext     string
		signIn        *fakeAzureSignIn
		outcome, want string
	}{
		{storedTestApp, &fakeAzureSignIn{err: azureauth.ErrCredential}, storedByokRejected, azureAppRejected},
		{storedTestApp, &fakeAzureSignIn{err: azureauth.ErrUnavailable}, storedByokUnavailable, azureAppUnavailable},
	} {
		got := listStoredTestAccounts(t, unreached, test.signIn, test.plaintext, first)
		if got.Outcome != test.outcome || got.Message == nil || *got.Message != test.want || got.Accounts == nil || len(got.Accounts) != 0 {
			t.Fatalf("%s: %s", test.want, encodeJSON(t, got))
		}
	}
	signIn := &fakeAzureSignIn{}
	idle := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(idle.Close)
	invalid := newTestByokChecker(idle, nil, time.Now())
	invalid.arm, invalid.azure = unreached, signIn
	got, err := listStoredAzureAccounts(context.Background(), &fakeStoredOpener{secret: `{"clientId":"x"}`}, invalid,
		storedTestGrant("azure", billing.StoredByokAzureAccounts), StoredAzureAccountsRequest{Secret: "sealed", SubscriptionIDs: []string{first}})
	if err != nil || got.Outcome != storedByokRejected || got.Message == nil || *got.Message != "The secret is not a valid Azure application" ||
		got.Accounts == nil || len(got.Accounts) != 0 || len(signIn.calls) != 0 {
		t.Fatalf("an invalid application: %+v, %v after %d sign-ins", got, err, len(signIn.calls))
	}
	if reads != 0 {
		t.Fatalf("%d listings after failed sign-ins", reads)
	}

	// The gateway refuses a request that does not fit its grant before it opens the secret.
	status := http.StatusOK
	server, _ := byokCheckTestServer(t, &status)
	checker := newTestByokChecker(server, nil, time.Now())
	checker.arm, checker.azure = unreached, &fakeAzureSignIn{}
	opener := &fakeStoredOpener{secret: storedTestApp}
	grant := storedTestGrant("azure", billing.StoredByokAzureAccounts)
	many := make([]string, storedAzureMaxSubscriptions+1)
	for index := range many {
		many[index] = storedTestSubscription(index)
	}
	for name, c := range map[string]struct {
		grant   *billing.StoredByokGrant
		request StoredAzureAccountsRequest
		want    error
	}{
		"no grant":                    {nil, StoredAzureAccountsRequest{Secret: "sealed", SubscriptionIDs: []string{first}}, billing.ErrStoredByokGrant},
		"a probe grant":               {storedTestGrant("azure", billing.StoredByokProbe), StoredAzureAccountsRequest{Secret: "sealed", SubscriptionIDs: []string{first}}, billing.ErrStoredByokGrant},
		"no secret":                   {grant, StoredAzureAccountsRequest{SubscriptionIDs: []string{first}}, billing.ErrStoredByokRequest},
		"no subscription":             {grant, StoredAzureAccountsRequest{Secret: "sealed", SubscriptionIDs: []string{}}, billing.ErrStoredByokRequest},
		"65 subscriptions":            {grant, StoredAzureAccountsRequest{Secret: "sealed", SubscriptionIDs: many}, billing.ErrStoredByokRequest},
		"a repeated subscription":     {grant, StoredAzureAccountsRequest{Secret: "sealed", SubscriptionIDs: []string{first, first}}, billing.ErrStoredByokRequest},
		"an uppercase subscription":   {grant, StoredAzureAccountsRequest{Secret: "sealed", SubscriptionIDs: []string{strings.ToUpper("0000000a-0000-4000-8000-00000000000b")}}, billing.ErrStoredByokRequest},
		"a path for a subscription":   {grant, StoredAzureAccountsRequest{Secret: "sealed", SubscriptionIDs: []string{first + "/resourceGroups/stogas"}}, billing.ErrStoredByokRequest},
		"another credential's secret": {grant, StoredAzureAccountsRequest{Secret: "other", SubscriptionIDs: []string{first}}, billing.ErrStoredByokSecret},
	} {
		if _, err := listStoredAzureAccounts(context.Background(), opener, checker, c.grant, c.request); !errors.Is(err, c.want) {
			t.Fatalf("%s: %v, want %v", name, err, c.want)
		}
	}
	if opener.opened != 0 || reads != 0 {
		t.Fatal("a refused request opened its secret or reached Azure")
	}
	if got, err := listStoredAzureAccounts(context.Background(), opener, checker, grant,
		StoredAzureAccountsRequest{Secret: "sealed", SubscriptionIDs: many[:storedAzureMaxSubscriptions]}); err != nil || got.Outcome != storedByokAccepted || reads != storedAzureMaxSubscriptions {
		t.Fatalf("64 subscriptions: %+v, %v after %d listings", got, err, reads)
	}
}

// A listing keeps at most eight reads of Azure Resource Manager in flight across subscriptions.
// Reads wait until eight are in flight, so a slow machine cannot make the listing look narrower.
func TestListStoredAzureAccountsBoundsItsReads(t *testing.T) {
	var mu sync.Mutex
	var full sync.Once
	active, most, allIn := 0, 0, make(chan struct{})
	client := serveAzureAccounts(t, func(w http.ResponseWriter, _ *http.Request, subscriptionID string) {
		mu.Lock()
		active++
		most = max(most, active)
		if active == azureDiscoveryConcurrency {
			full.Do(func() { close(allIn) })
		}
		mu.Unlock()
		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()
		select {
		case <-allIn:
		case <-time.After(10 * time.Second):
		}
		time.Sleep(20 * time.Millisecond)
		value := make([]any, 4)
		for index := range value {
			name := fmt.Sprintf("account-%d", index)
			value[index] = armAccountJSON(subscriptionID, name, "AIServices", foundryProperties(name))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": value})
	})
	subscriptions := make([]string, 12)
	for index := range subscriptions {
		subscriptions[index] = storedTestSubscription(index)
	}
	got := listStoredTestAccounts(t, client, &fakeAzureSignIn{}, storedTestApp, subscriptions...)
	if got.Outcome != storedByokAccepted || len(got.Accounts) != 48 || most != azureDiscoveryConcurrency {
		t.Fatalf("%s: %d accounts with at most %d reads at once", got.Outcome, len(got.Accounts), most)
	}
	for _, account := range got.Accounts {
		if account.Problem != nil {
			t.Fatalf("account %s: %s", account.ID, *account.Problem)
		}
	}
}

// The first failure ends the listing at once: reads in flight close and queued ones never start.
func TestListStoredAzureAccountsStopsAtTheFirstFailure(t *testing.T) {
	for _, test := range []struct {
		status        int
		body, message string
	}{
		{http.StatusServiceUnavailable, `{}`, azureDiscoveryUnavailable},
		{http.StatusOK, `{"value":false}`, "Azure returned invalid management data"},
	} {
		var mu sync.Mutex
		started, closed := 0, 0
		release := make(chan struct{})
		client := serveAzureAccounts(t, func(w http.ResponseWriter, r *http.Request, _ string) {
			mu.Lock()
			started++
			first := started == 1
			if started == azureDiscoveryConcurrency {
				close(release)
			}
			mu.Unlock()
			if first {
				<-release
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[`))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			mu.Lock()
			closed++
			mu.Unlock()
		})
		subscriptions := make([]string, 12)
		for index := range subscriptions {
			subscriptions[index] = storedTestSubscription(index)
		}
		begun := time.Now()
		got := listStoredTestAccounts(t, client, &fakeAzureSignIn{}, storedTestApp, subscriptions...)
		if got.Outcome != storedByokUnavailable || *got.Message != test.message || time.Since(begun) > 5*time.Second {
			t.Fatalf("status %d: %s after %s", test.status, encodeJSON(t, got), time.Since(begun))
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			done := closed == started-1
			count := started
			mu.Unlock()
			if done {
				if count < azureDiscoveryConcurrency || count > azureDiscoveryConcurrency+1 {
					t.Fatalf("status %d: %d reads started", test.status, count)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("status %d: reads in flight stayed open", test.status)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
