package stogas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// azureDiscoveryCase is one case in testdata/azure-discovery, which Control's discovery runs too:
// what Azure Resource Manager answers, and what the discovery makes of it.
type azureDiscoveryCase struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	AccountID   string `json:"accountId"`
	Responses   []struct {
		Path   string          `json:"path"`
		Query  string          `json:"query"`
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
		Text   *string         `json:"text"`
	} `json:"responses"`
	Outcome azureDiscoveryCaseOutcome `json:"outcome"`
}

type azureDiscoveryCaseOutcome struct {
	Result *struct {
		Name        string                    `json:"name"`
		CheckError  *string                   `json:"checkError"`
		Bindings    []azureDiscoveredBinding  `json:"bindings"`
		Deployments []billing.AzureDeployment `json:"deployments"`
	} `json:"result,omitempty"`
	Error *struct {
		Message string `json:"message"`
		Status  int    `json:"status"`
	} `json:"error,omitempty"`
}

func loadAzureDiscoveryCases(t *testing.T) []azureDiscoveryCase {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "azure-discovery", "*.json"))
	if err != nil || len(files) < 50 {
		t.Fatalf("Azure discovery cases: %d files, %v", len(files), err)
	}
	cases := make([]azureDiscoveryCase, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var entry azureDiscoveryCase
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&entry); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if filepath.Base(file) != entry.Name+".json" || (entry.Outcome.Result == nil) == (entry.Outcome.Error == nil) {
			t.Fatalf("%s: malformed case", file)
		}
		cases = append(cases, entry)
	}
	return cases
}

// azureDiscoveryARM answers Azure Resource Manager requests with the token arm-token as a case
// does. It counts the requests for each answer and lists those that the case does not answer.
type azureDiscoveryARM struct {
	mu         sync.Mutex
	entry      azureDiscoveryCase
	requested  []int
	unexpected []string
}

func serveAzureDiscoveryCase(t *testing.T, entry azureDiscoveryCase) (*azureDiscoveryARM, *http.Client) {
	t.Helper()
	arm := &azureDiscoveryARM{entry: entry, requested: make([]int, len(entry.Responses))}
	server := httptest.NewServer(arm)
	t.Cleanup(server.Close)
	return arm, &http.Client{Transport: armRedirect{server}}
}

func (a *azureDiscoveryARM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path, query := strings.ToLower(r.URL.Path), r.URL.RawQuery
	a.mu.Lock()
	defer a.mu.Unlock()
	for index, response := range a.entry.Responses {
		if response.Path != path || response.Query != query || r.Header.Get("Authorization") != "Bearer arm-token" {
			continue
		}
		a.requested[index]++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.Status)
		switch {
		case response.Text != nil:
			_, _ = w.Write([]byte(*response.Text))
		case len(response.Body) > 0:
			_, _ = w.Write(response.Body)
		}
		return
	}
	a.unexpected = append(a.unexpected, path+"?"+query)
	w.WriteHeader(http.StatusTeapot)
}

// counts returns how many requests the case answered and how many it did not.
func (a *azureDiscoveryARM) counts() (answered int, unexpected []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, count := range a.requested {
		answered += count
	}
	return answered, append([]string(nil), a.unexpected...)
}

func azureDiscoveryCaseNamed(t *testing.T, name string) azureDiscoveryCase {
	t.Helper()
	for _, entry := range loadAzureDiscoveryCases(t) {
		if entry.Name == name {
			return entry
		}
	}
	t.Fatalf("no Azure discovery case %s", name)
	return azureDiscoveryCase{}
}

// TestAzureDiscoveryCases runs the gateway's discovery on the cases that Control's discovery
// runs, so both save the same targets from the same answers, fail with the same messages, and
// make the same requests.
func TestAzureDiscoveryCases(t *testing.T) {
	for _, entry := range loadAzureDiscoveryCases(t) {
		t.Run(entry.Name, func(t *testing.T) {
			arm, client := serveAzureDiscoveryCase(t, entry)
			found, err := discoverAzure(context.Background(), client, "arm-token", entry.AccountID, time.Now())

			arm.mu.Lock()
			defer arm.mu.Unlock()
			requested, unexpected := arm.requested, arm.unexpected
			if len(unexpected) > 0 {
				t.Fatalf("unexpected Azure requests: %v", unexpected)
			}
			if expected := entry.Outcome.Error; expected != nil {
				status := http.StatusServiceUnavailable
				var problem *azureDiscoveryError
				if errors.As(err, &problem) && problem.rejected {
					status = http.StatusBadRequest
				}
				if err == nil || azureDiscoveryMessage(err) != expected.Message || status != expected.Status {
					t.Fatalf("discovery = %v, %v (%d); want error %q (%d)", found, err, status, expected.Message, expected.Status)
				}
				return
			}
			if err != nil {
				t.Fatalf("discovery failed: %v", err)
			}
			expected := entry.Outcome.Result
			checkError := (*string)(nil)
			if found.CheckError != "" {
				checkError = &found.CheckError
			}
			if found.Name != expected.Name || !equalOptional(checkError, expected.CheckError) {
				t.Errorf("name, check error = %q, %v; want %q, %v", found.Name, checkError, expected.Name, expected.CheckError)
			}
			assertSameJSON(t, "bindings", found.Bindings, expected.Bindings)
			assertSameJSON(t, "deployments", found.Deployments, expected.Deployments)
			for index, count := range requested {
				if count != 1 {
					t.Errorf("answer %s?%s was requested %d times; a discovery reads each once", entry.Responses[index].Path, entry.Responses[index].Query, count)
				}
			}
		})
	}
}

// assertSameJSON compares values as the database receives them: an empty list either way, and a
// date as its instant.
func assertSameJSON[T any](t *testing.T, name string, actual, expected []T) {
	t.Helper()
	if actual == nil {
		actual = []T{}
	}
	if expected == nil {
		expected = []T{}
	}
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualJSON, expectedJSON) {
		t.Errorf("%s differ\n got: %s\nwant: %s", name, actualJSON, expectedJSON)
	}
}

// azureDiscoveryAtScale answers a discovery of an account with deployments, or with Foundry
// projects that each offer every Instant model, as Azure Resource Manager lists them: pages of 200,
// each deployment and project as large as ARM's, and a region's thousand models.
type azureDiscoveryAtScale struct {
	account     string
	deployments int
	projects    int
	instant     int
	pageSize    int
	requests    atomic.Int32
}

const azureScaleSubscription = "00000000-0000-4000-8000-000000000003"

func newAzureDiscoveryAtScale(instant bool) *azureDiscoveryAtScale {
	name := "stogas-east"
	if instant {
		name = "stogas-west"
	}
	return &azureDiscoveryAtScale{
		account:  "/subscriptions/" + azureScaleSubscription + "/resourcegroups/stogas/providers/microsoft.cognitiveservices/accounts/" + name,
		pageSize: 200,
	}
}

func (a *azureDiscoveryAtScale) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.requests.Add(1)
	path, query := strings.ToLower(r.URL.Path), r.URL.Query()
	west := strings.HasSuffix(a.account, "stogas-west")
	page := func(total int, item func(int) any) {
		index, _ := strconv.Atoi(query.Get("page"))
		values := []any{}
		for position := index * a.pageSize; position < total && position < (index+1)*a.pageSize; position++ {
			values = append(values, item(position))
		}
		listing := map[string]any{"value": values}
		if (index+1)*a.pageSize < total {
			listing["nextLink"] = "https://" + armHost + r.URL.Path + "?api-version=" + query.Get("api-version") + "&page=" + strconv.Itoa(index+1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(listing)
	}
	systemData := map[string]any{
		"createdBy": "owner@example.com", "createdByType": "User", "createdAt": "2026-07-10T10:00:00.0000000Z",
		"lastModifiedBy": "owner@example.com", "lastModifiedByType": "User", "lastModifiedAt": "2026-07-10T10:00:00.0000000Z",
	}
	host := strings.TrimPrefix(a.account[strings.LastIndexByte(a.account, '/'):], "/")
	switch {
	case path == a.account && query.Get("api-version") == armInstantAPIVersion:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": a.account, "properties": map[string]any{"instant": map[string]any{}}})
	case path == a.account:
		location := "eastus"
		if west {
			location = azureInstantLocation
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": a.account, "kind": "AIServices", "location": location, "name": host,
			"properties": map[string]any{
				"customSubDomainName": host,
				"endpoints": map[string]any{
					"AI Foundry API":                     "https://" + host + ".services.ai.azure.com/",
					"OpenAI Language Model Instance API": "https://" + host + ".openai.azure.com/",
				},
				"publicNetworkAccess": "Enabled",
			},
		})
	case path == a.account+"/deployments":
		page(a.deployments, func(index int) any {
			name := fmt.Sprintf("deployment-%05d", index)
			return map[string]any{
				"id": a.account + "/deployments/" + name, "type": "Microsoft.CognitiveServices/accounts/deployments", "name": name,
				"sku": map[string]any{"name": "GlobalStandard", "capacity": 450},
				"properties": map[string]any{
					"model":                map[string]any{"format": "OpenAI", "name": fmt.Sprintf("model-%05d", index), "version": "2026-07-09"},
					"versionUpgradeOption": "OnceNewDefaultVersionAvailable", "currentCapacity": 450,
					"capabilities": map[string]any{
						"area": "US", "chatCompletion": "true", "jsonObjectResponse": "true", "maxContextToken": "400000",
						"maxOutputToken": "128000", "responses": "true", "assistants": "true", "agentsV2": "true",
					},
					"provisioningState": "Succeeded",
					"rateLimits": []any{
						map[string]any{"key": "request", "renewalPeriod": 10, "count": 450},
						map[string]any{"key": "token", "renewalPeriod": 60, "count": 450000},
					},
					"raiPolicyName": "Microsoft.DefaultV2", "deploymentState": "Running",
				},
				"systemData": systemData, "etag": `"00000000-0000-0000-0000-000000000000"`,
			}
		})
	case path == a.account+"/projects":
		page(a.projects, func(index int) any {
			name := fmt.Sprintf("project-%04d", index)
			return map[string]any{
				"id": a.account + "/projects/" + name, "type": "Microsoft.CognitiveServices/accounts/projects",
				"name": host + "/" + name, "location": azureInstantLocation,
				"properties": map[string]any{"provisioningState": "Succeeded", "displayName": name, "isDefault": false},
				"systemData": systemData, "etag": `"00000000-0000-0000-0000-000000000000"`,
			}
		})
	case strings.HasSuffix(path, "/providers/microsoft.authorization/permissions"):
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{map[string]any{"actions": []any{}, "dataActions": []any{"Microsoft.CognitiveServices/*"}}}})
	case path == "/subscriptions/"+azureScaleSubscription+"/locations":
		locations := []any{}
		for index := range 90 {
			name := fmt.Sprintf("region%d", index)
			switch index {
			case 0:
				name = "eastus"
			case 1:
				name = azureInstantLocation
			}
			locations = append(locations, map[string]any{
				"id": "/subscriptions/" + azureScaleSubscription + "/locations/" + name, "name": name,
				"metadata": map[string]any{"geography": "United States", "geographyGroup": "US", "regionType": "Physical"},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": locations})
	case strings.HasSuffix(path, "/models"):
		page(1000, func(index int) any {
			name, capabilities := fmt.Sprintf("regional-%d", index), map[string]any{"chatCompletion": "true", "responses": "true"}
			if west && index < a.instant {
				name, capabilities["instant"] = fmt.Sprintf("instant-%d", index), "true"
			}
			skus := []any{}
			for _, sku := range []string{"GlobalStandard", "DataZoneStandard", "Standard", "GlobalBatch", "ProvisionedManaged"} {
				skus = append(skus, map[string]any{
					"name": sku, "usageName": "OpenAI." + sku + "." + name, "deprecationDate": "2027-07-09T00:00:00Z",
					"capacity": map[string]any{"maximum": 30000, "minimum": 1, "step": 1, "default": 100},
				})
			}
			return map[string]any{"kind": "AIServices", "skuName": "S0", "model": map[string]any{
				"format": "OpenAI", "name": name, "version": "2026-07-09", "publisher": "OpenAI", "capabilities": capabilities,
				"deprecation":     map[string]any{"fineTune": "2027-07-09T00:00:00Z", "inference": "2027-07-09T00:00:00Z"},
				"lifecycleStatus": "GenerallyAvailable", "skus": skus,
			}}
		})
	default:
		w.WriteHeader(http.StatusTeapot)
	}
}

// TestAzureDiscoveryAtItsLimits discovers the most targets that a discovery keeps, 20,000, as an
// account's deployments and as Instant models in Foundry projects, and one more of each. Control's
// discovery runs the same cases.
func TestAzureDiscoveryAtItsLimits(t *testing.T) {
	type outcome struct {
		bindings, deployments int
		message               string
		status                int
	}
	for _, entry := range []struct {
		name                    string
		instant                 bool
		deployments, projects   int
		instantModels, pageSize int
		want                    outcome
	}{
		{name: "20,000 deployments", deployments: 20_000, pageSize: 200, want: outcome{bindings: 20_000, deployments: 20_000}},
		{name: "20,000 Instant targets", instant: true, projects: 2_000, instantModels: 10, pageSize: 200, want: outcome{bindings: 20_000}},
		{name: "a page more", deployments: 20_001, pageSize: 200, want: outcome{message: "Azure discovery returned too many pages", status: http.StatusServiceUnavailable}},
		{name: "a deployment more", deployments: 20_001, pageSize: 500, want: outcome{message: "Azure discovery returned too many resources", status: http.StatusBadRequest}},
		{name: "an Instant target more", instant: true, projects: 2_001, instantModels: 10, pageSize: 200, want: outcome{message: "Azure discovery returned too many deployments", status: http.StatusBadRequest}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			arm := newAzureDiscoveryAtScale(entry.instant)
			arm.deployments, arm.projects, arm.instant, arm.pageSize = entry.deployments, entry.projects, entry.instantModels, entry.pageSize
			server := httptest.NewServer(arm)
			t.Cleanup(server.Close)
			started := time.Now()
			found, err := discoverAzure(context.Background(), &http.Client{Transport: armRedirect{server}}, "arm-token", arm.account, started)
			elapsed := time.Since(started)
			var got outcome
			if err != nil {
				got.message, got.status = azureDiscoveryMessage(err), http.StatusServiceUnavailable
				var problem *azureDiscoveryError
				if errors.As(err, &problem) && problem.rejected {
					got.status = http.StatusBadRequest
				}
			} else {
				got.bindings, got.deployments = len(found.Bindings), len(found.Deployments)
			}
			if got != entry.want {
				t.Fatalf("discovery = %+v; want %+v", got, entry.want)
			}
			// A discovery has 25 seconds, the claim that it holds for the fleet less five.
			if limit := 10 * time.Second * raceSlowdown; elapsed > limit {
				t.Fatalf("discovery took %s, more than %s", elapsed, limit)
			}
			t.Logf("%s in %s with %d requests", entry.name, elapsed.Round(time.Millisecond), arm.requests.Load())
		})
	}
}

func TestAzureModelRoleSubtractsEachRolesExcludedDataActions(t *testing.T) {
	for _, test := range []struct {
		name, permissions string
		want              bool
	}{
		{"Foundry User", `[{"dataActions":["Microsoft.CognitiveServices/*"],"notDataActions":[]}]`, true},
		{"absent exclusions", `[{"dataActions":["Microsoft.CognitiveServices/accounts/OpenAI/*"]}]`, true},
		{"Reader", `[{"actions":["*/read"],"dataActions":[],"notDataActions":[]}]`, false},
		{"all excluded", `[{"dataActions":["Microsoft.CognitiveServices/*"],"notDataActions":["microsoft.cognitiveservices/*"]}]`, false},
		{"everything but Cognitive Services", `[{"dataActions":["*"],"notDataActions":["Microsoft.CognitiveServices/*"]}]`, false},
		{"narrower exclusion", `[{"dataActions":["Microsoft.CognitiveServices/*"],"notDataActions":["Microsoft.CognitiveServices/accounts/OpenAI/*"]}]`, true},
		{"exact exclusion", `[{"dataActions":["Microsoft.CognitiveServices/accounts/OpenAI/deployments/chat/completions/action"],"notDataActions":["Microsoft.CognitiveServices/accounts/OpenAI/deployments/chat/completions/action"]}]`, false},
		{"inner wildcard never hides", `[{"dataActions":["Microsoft.CognitiveServices/accounts/OpenAI/deployments/chat/completions/action"],"notDataActions":["Microsoft.CognitiveServices/*/action"]}]`, true},
		{"another role's exclusion", `[{"dataActions":["Microsoft.CognitiveServices/*"],"notDataActions":[]},{"dataActions":[],"notDataActions":["Microsoft.CognitiveServices/*"]}]`, true},
		{"unexpected exclusions", `[{"dataActions":[],"notDataActions":"Microsoft.CognitiveServices/*"}]`, true},
		{"null exclusions", `[{"dataActions":[],"notDataActions":null}]`, true},
		{"unexpected actions", `[{"dataActions":"*"}]`, true},
	} {
		var values []json.RawMessage
		if err := json.Unmarshal([]byte(test.permissions), &values); err != nil {
			t.Fatal(err)
		}
		if got := azureGrantsModelRequests(values); got != test.want {
			t.Errorf("%s: model role = %v, want %v", test.name, got, test.want)
		}
	}
}
