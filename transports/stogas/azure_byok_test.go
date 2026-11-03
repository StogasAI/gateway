package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	azureprovider "github.com/maximhq/bifrost/core/providers/azure"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/azureauth"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func azureTestCredential(t *testing.T) string {
	t.Helper()
	encoded, err := json.Marshal(azureByokCredential{
		ClientID:     "00000000-0000-4000-8000-000000000002",
		ClientSecret: "azure-client-secret",
		Schema:       azureByokSchema,
		TenantID:     "00000000-0000-4000-8000-000000000001",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func azureTestBinding() billing.AzureBinding {
	return billing.AzureBinding{
		DeploymentName:     "customer-sol",
		DeploymentType:     "global_standard",
		Endpoint:           "https://stogas-ai.openai.azure.com",
		Hosting:            "azure",
		ModelFormat:        "OpenAI",
		ModelName:          "gpt-5.6-sol",
		ModelVersion:       "2026-07-09",
		ProcessingLocation: "world",
		StorageLocation:    "US",
		TokenScope:         azureDataScope,
	}
}

func azureTestResolution() *catalog.ResolvedRequest {
	return &catalog.ResolvedRequest{
		Deployment: catalog.Deployment{
			ID:      "azure-gpt-5.6-sol",
			ModelID: "gpt-5.6-sol",
			DataHandling: catalog.DataHandling{
				ProcessingLocation: "world",
				StorageLocation:    "unknown",
			},
			Locations: testPlaces,
			Upstream: catalog.Upstream{
				DeploymentType: "global_standard",
				Hosting:        "azure",
				Model:          "gpt-5.6-sol",
				ModelFormat:    "OpenAI",
				ModelVersion:   "2026-07-09",
				ServiceTier:    catalog.TierStandard,
			},
		},
		Provider: schemas.Azure,
		Route:    catalog.RouteChat,
	}
}

func TestAzureCredentialEligibilityUsesOnlyLiveCompatibleBindings(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		change  func(*billing.AzureBinding)
		expired bool
		want    error
	}{
		{"compatible", func(*billing.AzureBinding) {}, false, nil},
		{"expired", func(*billing.AzureBinding) {}, true, billing.ErrByokTarget},
		{"wrong model", func(b *billing.AzureBinding) { b.ModelName = "other" }, false, billing.ErrByokTarget},
		{"wrong version", func(b *billing.AzureBinding) { b.ModelVersion = "2026-07-10" }, false, billing.ErrByokTarget},
		{"wrong format", func(b *billing.AzureBinding) { b.ModelFormat = "Anthropic" }, false, billing.ErrByokTarget},
		{"wrong hosting", func(b *billing.AzureBinding) { b.Hosting = "anthropic" }, false, billing.ErrByokTarget},
		{"wrong deployment type", func(b *billing.AzureBinding) { b.DeploymentType = "data_zone_standard_us" }, false, billing.ErrByokTarget},
		{"untrusted endpoint", func(b *billing.AzureBinding) { b.Endpoint = "https://example.com" }, false, billing.ErrByokTarget},
		{"wrong scope", func(b *billing.AzureBinding) { b.TokenScope = "https://example.com/.default" }, false, billing.ErrByokTarget},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := azureTestBinding()
			test.change(&binding)
			var expires *time.Time
			if test.expired {
				value := now.Add(-time.Second)
				expires = &value
			}
			binding.ModelDeprecationAt = expires
			snapshot := &billing.KeyConfigSnapshot{Credentials: map[string][]billing.CredentialSelection{"azure": {{Credential: &billing.CachedCredential{Bindings: []billing.AzureCredentialBinding{{AzureBinding: binding}}}}}}}
			eligible := CredentialDeploymentFilter(snapshot, now)
			if got := eligible(schemas.Azure, 0, catalog.RouteChat, azureTestResolution().Deployment); got != (test.want == nil) {
				t.Fatalf("eligible=%v want=%v", got, test.want == nil)
			}
			if !eligible(schemas.OpenAI, 0, catalog.RouteChat, catalog.Deployment{}) {
				t.Fatal("Azure target metadata affected another provider")
			}
		})
	}
}

func TestAzureCredentialEligibilityRetainsMultipleTargetsAndRequestVariants(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	bindings := []billing.AzureCredentialBinding{
		{AzureBinding: azureTestBinding()},
		{AzureBinding: azureTestBinding()},
	}
	bindings[0].ModelDeprecationAt = &now
	bindings[1].DeploymentName = "another-target"
	snapshot := &billing.KeyConfigSnapshot{Credentials: map[string][]billing.CredentialSelection{
		"azure": {{Credential: &billing.CachedCredential{Bindings: bindings}}},
	}}
	eligible := CredentialDeploymentFilter(snapshot, now)
	deployment := azureTestResolution().Deployment
	deployment.Upstream.ServiceTier = catalog.TierFast
	deployment.Upstream.ReasoningMode = "pro"
	if !eligible(schemas.Azure, 0, catalog.RouteChat, deployment) {
		t.Fatal("an expired target hid a live target supporting the same request variants")
	}
	deployment.DataHandling.ProcessingLocation = "eu"
	if eligible(schemas.Azure, 0, catalog.RouteChat, deployment) {
		t.Fatal("matching model identity bypassed the requested processing boundary")
	}
}

func TestAzureOnlyCredentialSelectsItsConfiguredDeploymentWithoutSecretAccess(t *testing.T) {
	snapshot := &billing.KeyConfigSnapshot{Credentials: map[string][]billing.CredentialSelection{
		"azure": {{Mode: "stored", Credential: &billing.CachedCredential{Bindings: []billing.AzureCredentialBinding{{AzureBinding: azureTestBinding()}}}}},
	}}
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		body := `{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hello"}]}`
		if path == "/v1/responses" {
			body = `{"model":"gpt-5.6-sol","input":"hello"}`
		}
		resolved, err := catalog.ResolveRequest(catalog.RequestInput{
			Body: []byte(body), Method: "POST", Path: path,
			AvailableCredentials: map[string][]int{"azure": {0}},
			DeploymentEligible:   CredentialDeploymentFilter(snapshot, time.Now()),
		})
		if err != nil || resolved == nil || resolved.Deployment.ID != "azure-gpt-5.6-sol" {
			t.Fatalf("result=%v error=%v", resolved, err)
		}
	}
}

func TestAzureTargetThatChangedNamesTheCauseWhenNothingElseServes(t *testing.T) {
	upstream := azureTestResolution().Deployment.Upstream
	changed := billing.AzureTarget{
		ModelFormat: upstream.ModelFormat, Model: upstream.Model, ModelVersion: upstream.ModelVersion,
		Hosting: upstream.Hosting, DeploymentType: upstream.DeploymentType,
	}
	otherVersion := changed
	otherVersion.ModelVersion = "2026-10-28"
	credential := func(binding *billing.AzureBinding, changed ...billing.AzureTarget) billing.CredentialSelection {
		value := &billing.CachedCredential{ChangedTargets: changed}
		if binding != nil {
			value.Bindings = []billing.AzureCredentialBinding{{AzureBinding: *binding}}
		}
		return billing.CredentialSelection{Mode: "stored", Credential: value}
	}
	serving := azureTestBinding()
	for _, test := range []struct {
		name        string
		credentials []billing.CredentialSelection
		want        error
	}{
		{"moved", []billing.CredentialSelection{credential(nil, changed)}, catalog.ErrByokTargetChanged},
		// The credential that used to serve names the cause, whichever comes first.
		{"moved after one without a target", []billing.CredentialSelection{credential(nil), credential(nil, changed)}, catalog.ErrByokTargetChanged},
		{"no target", []billing.CredentialSelection{credential(nil)}, catalog.ErrByokTargetUnavailable},
		{"another version moved", []billing.CredentialSelection{credential(nil, otherVersion)}, catalog.ErrByokTargetUnavailable},
		{"another credential serves", []billing.CredentialSelection{credential(nil, changed), credential(&serving)}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := &billing.KeyConfigSnapshot{Credentials: map[string][]billing.CredentialSelection{"azure": test.credentials}}
			indexes := make([]int, len(test.credentials))
			for index := range indexes {
				indexes[index] = index
			}
			for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
				body := `{"model":"azure-gpt-5.6-sol","messages":[{"role":"user","content":"hello"}]}`
				if path == "/v1/responses" {
					body = `{"model":"azure-gpt-5.6-sol","input":"hello"}`
				}
				_, err := catalog.ResolveRequest(catalog.RequestInput{
					Body: []byte(body), Method: "POST", Path: path,
					AvailableCredentials: map[string][]int{"azure": indexes},
					DeploymentEligible:   CredentialDeploymentFilter(snapshot, time.Now()),
					DeploymentChanged:    CredentialTargetChanged(snapshot),
				})
				if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
					t.Fatalf("%s: error = %v, want %v", path, err, test.want)
				}
			}
		})
	}
}

func TestAzureRepliesNameVersionWhereAzureReportsIt(t *testing.T) {
	for _, test := range []struct {
		route  catalog.Route
		format string
		want   bool
	}{
		{catalog.RouteResponses, "OpenAI", true},
		{catalog.RouteResponses, "DeepSeek", true},
		{catalog.RouteChat, "OpenAI", true},
		{catalog.RouteChat, "DeepSeek", false},
		{catalog.RouteChat, "OpenAI-OSS", false},
		{catalog.RouteChat, "Anthropic", false},
		{catalog.RouteResponses, "Anthropic", false},
	} {
		deployment := catalog.Deployment{Upstream: catalog.Upstream{ModelFormat: test.format}}
		if got := azureRepliesNameVersion(test.route, deployment); got != test.want {
			t.Errorf("%s %s: names version = %v, want %v", test.route, test.format, got, test.want)
		}
	}
}

func TestAzureKeepsVersionUntilItsRetirementDateBeginsAnywhere(t *testing.T) {
	retires := time.Date(2026, 12, 1, 9, 0, 0, 0, time.UTC)
	begins := time.Date(2026, 11, 30, 10, 0, 0, 0, time.UTC)
	if got := azureRetirementBegins(retires); !got.Equal(begins) {
		t.Fatalf("retirement begins %s, want %s", got, begins)
	}
	for _, test := range []struct {
		upgrade string
		retires *time.Time
		at      time.Time
		want    bool
	}{
		{"none", nil, begins, true},
		{"at_retirement", nil, begins, true},
		{"at_retirement", &retires, begins.Add(-time.Second), true},
		{"at_retirement", &retires, begins, false},
		// Azure force-upgrades a preview version whatever the option says.
		{"none", &retires, begins, false},
		{"new_default", nil, begins.Add(-48 * time.Hour), false},
		{"", nil, begins, false},
	} {
		binding := azureTestBinding()
		binding.AutoUpgrade, binding.ModelDeprecationAt = test.upgrade, test.retires
		if got := azureKeepsVersion(binding, test.at); got != test.want {
			t.Errorf("%q retiring %v at %s: keeps = %v, want %v", test.upgrade, test.retires, test.at, got, test.want)
		}
	}
}

func TestAzureUnreportedRepliesUseOnlyTargetsWhoseVersionAzureKeeps(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	binding := azureTestBinding()
	binding.ModelFormat, binding.ModelName, binding.ModelVersion = "DeepSeek", "DeepSeek-V4-Flash", "2026-04-23"
	binding.Endpoint = "https://stogas-ai.services.ai.azure.com"
	binding.AutoUpgrade = "new_default"
	deployment := azureTestResolution().Deployment
	deployment.Upstream.ModelFormat, deployment.Upstream.Model, deployment.Upstream.ModelVersion = "DeepSeek", "DeepSeek-V4-Flash", "2026-04-23"
	snapshot := func(binding billing.AzureBinding) *billing.KeyConfigSnapshot {
		return &billing.KeyConfigSnapshot{Credentials: map[string][]billing.CredentialSelection{
			"azure": {{Credential: &billing.CachedCredential{Bindings: []billing.AzureCredentialBinding{{AzureBinding: binding}}}}},
		}}
	}
	if CredentialDeploymentFilter(snapshot(binding), now)(schemas.Azure, 0, catalog.RouteChat, deployment) {
		t.Fatal("Chat Completions used a DeepSeek target that Azure moves to each new default version")
	}
	resolution := azureTestResolution()
	resolution.Deployment = deployment
	authorization := &billing.Authorization{AzureBinding: &binding, UpstreamByok: "00000000-0000-8000-8000-000000000001", UpstreamByokSecret: azureTestCredential(t)}
	if _, _, err := azureDirectKey(authorization, resolution, now); !errors.Is(err, billing.ErrByokTarget) {
		t.Fatalf("direct key for a movable target = %v", err)
	}
	if target := billingUpstreamTarget(resolution); target == nil || !target.VersionUnreported {
		t.Fatalf("the hold was not told that the reply names no version: %#v", target)
	}
	binding.AutoUpgrade = "at_retirement"
	if !CredentialDeploymentFilter(snapshot(binding), now)(schemas.Azure, 0, catalog.RouteChat, deployment) {
		t.Fatal("a target that keeps its version until retirement was refused")
	}
	if _, _, err := azureDirectKey(authorization, resolution, now); err != nil {
		t.Fatal(err)
	}
	// Replies that name their version catch a move themselves.
	openAI := azureTestBinding()
	openAI.AutoUpgrade = "new_default"
	if !CredentialDeploymentFilter(snapshot(openAI), now)(schemas.Azure, 0, catalog.RouteChat, azureTestResolution().Deployment) {
		t.Fatal("an OpenAI target was refused for Chat Completions, whose replies name the version")
	}
	if target := billingUpstreamTarget(azureTestResolution()); target == nil || target.VersionUnreported {
		t.Fatalf("an OpenAI Chat Completions hold = %#v", target)
	}
}

func TestAzureServedModelChangedReadsTheReplysModel(t *testing.T) {
	binding := azureTestBinding()
	authorization := &billing.Authorization{AzureBinding: &binding}
	for _, test := range []struct {
		served, want string
		changed      bool
	}{
		{"gpt-5.6-sol-2026-07-09", "", false},
		{"GPT-5.6-SOL-2026-07-09", "", false},
		{" gpt-5.6-sol ", "", false},
		{"", "", false},
		{"gpt-5.6-sol-2026-10-28", "gpt-5.6-sol-2026-10-28", true},
		{"gpt-5.7-sol-2026-10-28", "gpt-5.7-sol-2026-10-28", true},
		{".odd model/1", "xodd_model_1", true},
		{strings.Repeat("a", 300), strings.Repeat("a", 255), true},
	} {
		served, changed := AzureServedModelChanged(authorization, test.served)
		if served != test.want || changed != test.changed {
			t.Errorf("%q: served %q changed %v", test.served, served, changed)
		}
	}
	if _, changed := AzureServedModelChanged(&billing.Authorization{}, "gpt-5.6-sol-2026-10-28"); changed {
		t.Fatal("a request without an Azure target was judged")
	}
}

func TestParseAzureByokCredential(t *testing.T) {
	valid := azureTestCredential(t)
	parsed, err := parseAzureByokCredential(valid)
	if err != nil || parsed.ClientSecret != "azure-client-secret" {
		t.Fatalf("valid Azure credential = %#v, err=%v", parsed, err)
	}

	tests := map[string]string{
		"empty client secret": strings.Replace(valid, "azure-client-secret", "", 1),
		"secret with space":   strings.Replace(valid, "azure-client-secret", "azure secret", 1),
		"unknown schema":      strings.Replace(valid, azureByokSchema, "unknown", 1),
		"unknown field":       strings.Replace(valid, `"schema"`, `"extra":true,"schema"`, 1),
		"invalid client ID":   strings.Replace(valid, "00000000-0000-4000-8000-000000000002", "client", 1),
		"trailing JSON":       valid + `{}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, parseErr := parseAzureByokCredential(raw); parseErr == nil {
				t.Fatal("expected Azure credential validation failure")
			}
		})
	}
}

func TestAzureDirectKeyUsesOnlyTheAuthorizedExactBinding(t *testing.T) {
	binding := azureTestBinding()
	authorization := &billing.Authorization{
		AzureBinding:       &binding,
		UpstreamByok:       "00000000-0000-8000-8000-000000000001",
		UpstreamByokSecret: azureTestCredential(t),
	}
	key, deploymentName, err := azureDirectKey(authorization, azureTestResolution(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if deploymentName != "customer-sol" || !key.Models.IsAllowed("customer-sol") {
		t.Fatalf("wire model was not bound: key=%#v model=%q", key, deploymentName)
	}
	if key.Value.GetValue() != "" || key.AzureKeyConfig == nil ||
		key.AzureKeyConfig.Endpoint.GetValue() != binding.Endpoint ||
		key.AzureKeyConfig.ClientSecret.GetValue() != "azure-client-secret" ||
		len(key.AzureKeyConfig.Scopes) != 1 || key.AzureKeyConfig.Scopes[0] != azureDataScope {
		t.Fatalf("unexpected Azure direct key: %#v", key)
	}

	for _, upstream := range []catalog.Upstream{
		{DeploymentType: "global_standard", Hosting: "azure", Model: "gpt-5.6-sol", ModelFormat: "OpenAI", ModelVersion: "2026-07-09", ServiceTier: catalog.TierFast},
		{DeploymentType: "global_standard", Hosting: "azure", Model: "gpt-5.6-sol", ModelFormat: "OpenAI", ModelVersion: "2026-07-09", ReasoningMode: "pro"},
	} {
		resolution := azureTestResolution()
		resolution.Deployment.Upstream = upstream
		if _, selected, variantErr := azureDirectKey(authorization, resolution, time.Now()); variantErr != nil || selected != "customer-sol" {
			t.Fatalf("request control variant selected %q, err=%v", selected, variantErr)
		}
	}
}

func TestAzureDirectKeyRejectsTargetOrEndpointSubstitution(t *testing.T) {
	baseBinding := azureTestBinding()
	baseResolution := azureTestResolution()
	tests := map[string]func(*billing.AzureBinding, *catalog.ResolvedRequest){
		"deployment type": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.DeploymentType = "data_zone_standard_us"
		},
		"hosting":       func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) { binding.Hosting = "fireworks" },
		"model format":  func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) { binding.ModelFormat = "Fireworks" },
		"model name":    func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) { binding.ModelName = "gpt-5.6-terra" },
		"model version": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) { binding.ModelVersion = "2026-07-10" },
		"processing location": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.ProcessingLocation = "ZZ"
		},
		"storage location": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.StorageLocation = "multi-region"
		},
		"processing outside catalog boundary": func(_ *billing.AzureBinding, resolution *catalog.ResolvedRequest) {
			resolution.Deployment.DataHandling.ProcessingLocation = "eu"
		},
		"storage outside catalog boundary": func(_ *billing.AzureBinding, resolution *catalog.ResolvedRequest) {
			resolution.Deployment.DataHandling.StorageLocation = "SE"
		},
		"arbitrary host": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.Endpoint = "https://attacker.example"
		},
		"nested account": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.Endpoint = "https://a.b.openai.azure.com"
		},
		"userinfo": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.Endpoint = "https://user@stogas-ai.openai.azure.com"
		},
		"query": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) { binding.Endpoint += "?x=1" },
		"project on deployment": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.Endpoint = "https://stogas-ai.services.ai.azure.com/api/projects/project"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			binding := baseBinding
			resolution := *baseResolution
			resolution.Deployment = baseResolution.Deployment
			mutate(&binding, &resolution)
			_, _, err := azureDirectKey(&billing.Authorization{
				AzureBinding:       &binding,
				UpstreamByok:       "00000000-0000-8000-8000-000000000001",
				UpstreamByokSecret: azureTestCredential(t),
			}, &resolution, time.Now())
			if err == nil {
				t.Fatal("expected exact Azure binding rejection")
			}
		})
	}
}

func TestAzureDirectKeyAcceptsNarrowerDiscoveredLocations(t *testing.T) {
	binding := azureTestBinding()
	binding.ProcessingLocation = "eu"
	binding.StorageLocation = "SE"
	resolution := azureTestResolution()
	resolution.Deployment.DataHandling.ProcessingLocation = "eu"
	resolution.Deployment.DataHandling.StorageLocation = "europe"

	_, deploymentName, err := azureDirectKey(&billing.Authorization{
		AzureBinding:       &binding,
		UpstreamByok:       "00000000-0000-8000-8000-000000000001",
		UpstreamByokSecret: azureTestCredential(t),
	}, resolution, time.Now())
	if err != nil || deploymentName != binding.DeploymentName {
		t.Fatalf("narrower Azure binding was rejected: deployment=%q err=%v", deploymentName, err)
	}
}

func TestAzureDirectKeyAcceptsResolvedNoStorageGuarantee(t *testing.T) {
	binding := azureTestBinding()
	binding.StorageLocation = "unknown"
	resolution := azureTestResolution()
	resolution.Deployment.DataHandling.StorageLocation = "none"
	// ARM records only where the account is, so a catalog no-storage guarantee replaces it.
	served := servingBinding(binding, resolution.Deployment)
	if served.StorageLocation != "none" || !validAzureBinding(served, resolution.Deployment) {
		t.Fatalf("resolved catalog no-storage guarantee was rejected: %#v", served)
	}
	if validAzureBinding(binding, resolution.Deployment) {
		t.Fatal("unresolved unknown storage must not establish a no-storage guarantee")
	}
	resolution.Deployment.DataHandling.StorageLocation = "europe"
	if servingBinding(binding, resolution.Deployment).StorageLocation != "unknown" {
		t.Fatal("a storage boundary replaced the account's storage location")
	}
	served.ProcessingLocation = "none"
	resolution.Deployment.DataHandling.StorageLocation = "none"
	if validAzureBinding(served, resolution.Deployment) {
		t.Fatal("no-storage must not be accepted as a processing location")
	}
}

func TestAzureBindingLocationsMustBeCatalogPlaces(t *testing.T) {
	resolution := azureTestResolution()
	for _, test := range []struct {
		processing, storage string
		want                bool
	}{
		{"world", "US", true},
		// A place that the catalog does not list lies within no boundary but world and unknown, and
		// even there it is refused, so a misspelled place never passes as a known one.
		{"world", "ZZ", false},
		{"ZZ", "US", false},
		{"unknown", "unknown", true},
	} {
		binding := azureTestBinding()
		binding.ProcessingLocation, binding.StorageLocation = test.processing, test.storage
		if got := validAzureBinding(binding, resolution.Deployment); got != test.want {
			t.Errorf("binding processing %s, storage %s: valid = %v, want %v", test.processing, test.storage, got, test.want)
		}
	}
}

func TestAzureDirectKeySupportsInstantProjectBinding(t *testing.T) {
	binding := azureTestBinding()
	binding.DeploymentName = "gpt-5.6-sol-2026-07-09"
	binding.DeploymentType = "instant"
	binding.Endpoint = "https://stogas-ai.services.ai.azure.com/api/projects/Project_1"
	resolution := azureTestResolution()
	resolution.Deployment.ID = "azure-gpt-5.6-sol-instant"
	resolution.Deployment.Upstream.DeploymentType = "instant"
	key, wireModel, err := azureDirectKey(&billing.Authorization{
		AzureBinding:       &binding,
		UpstreamByok:       "00000000-0000-8000-8000-000000000001",
		UpstreamByokSecret: azureTestCredential(t),
	}, resolution, time.Now())
	if err != nil || wireModel != binding.DeploymentName || key.AzureKeyConfig == nil ||
		key.AzureKeyConfig.Endpoint.GetValue() != binding.Endpoint {
		t.Fatalf("instant binding = %#v, model=%q, err=%v", key, wireModel, err)
	}

	binding.Endpoint = "https://stogas-ai.services.ai.azure.com"
	if _, _, err = azureDirectKey(&billing.Authorization{
		AzureBinding:       &binding,
		UpstreamByok:       "00000000-0000-8000-8000-000000000001",
		UpstreamByokSecret: azureTestCredential(t),
	}, resolution, time.Now()); err == nil {
		t.Fatal("instant binding accepted a non-project endpoint")
	}
}

type azureTokenFunc func(context.Context, azureauth.Credential) (string, error)

func (f azureTokenFunc) Token(ctx context.Context, credential azureauth.Credential) (string, error) {
	return f(ctx, credential)
}

func TestApplyUpstreamCredentialsInstallsAzureBoundKey(t *testing.T) {
	binding := azureTestBinding()
	state := &State{
		Pair: Pair{
			Authorization: &billing.Authorization{
				AzureBinding:       &binding,
				UpstreamByok:       "00000000-0000-8000-8000-000000000001",
				UpstreamByokSecret: azureTestCredential(t),
			},
			Resolution: azureTestResolution(),
		},
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	if err := applyUpstreamCredentials(ctx, state, azureTokenFunc(func(_ context.Context, credential azureauth.Credential) (string, error) {
		if credential.Scope != azureDataScope || credential.Secret != "azure-client-secret" {
			t.Fatal("incorrect Azure token credential")
		}
		return "test-access-token", nil
	}), nil, nil); err != nil {
		t.Fatal(err)
	}
	directKey, ok := ctx.Value(schemas.BifrostContextKeyDirectKey).(schemas.Key)
	if !ok || directKey.AzureKeyConfig == nil || state.Resolution.Model != "customer-sol" ||
		!directKey.Models.IsAllowed("customer-sol") {
		t.Fatalf("Azure bound key was not installed: key=%#v resolution=%#v", directKey, state.Resolution)
	}
	if directKey.AzureKeyConfig.ClientID != nil || directKey.AzureKeyConfig.ClientSecret != nil || directKey.AzureKeyConfig.TenantID != nil || ctx.Value(azureprovider.AzureAuthorizationTokenKey) != "test-access-token" {
		t.Fatal("Azure SDK credentials retained or access token missing")
	}
}
