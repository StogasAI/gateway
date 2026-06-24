package catalog

import (
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

type Route string

const (
	RouteChat      Route = "chat-completions"
	RouteResponses Route = "responses"

	canonicalAuthHeader = "authorization"
)

type Deployment struct {
	ID                  string
	ModelID             string
	Model               string
	ContextWindowTokens int
	ImpliedServiceTier  *schemas.BifrostServiceTier
	MaxOutputTokens     int
	Pricing             Pricing
	ReasoningSupported  bool
	ServiceTier         string
}

type Pricing = billing.Pricing
type MeterEstimate = billing.MeterEstimate

type snapshot struct {
	graph                    compiledGraph
	providerNativeModelSlugs map[string]string
	responseMetadataFields   map[string]struct{}
	raw                      []byte
}

type compiledCatalog struct {
	Graph   compiledGraph   `json:"graph"`
	Indexes compiledIndexes `json:"indexes"`
}

type compiledIndexes struct {
	ProviderNativeModelSlugs map[string]string `json:"provider_native_model_slugs"`
}

type compiledGraph struct {
	Authors           map[string]compiledAuthor           `json:"authors"`
	Deployments       map[string]compiledDeployment       `json:"deployments"`
	Models            map[string]compiledModel            `json:"models"`
	ProviderEndpoints map[string]compiledProviderEndpoint `json:"providerEndpoints"`
	Providers         map[string]compiledProvider         `json:"providers"`
	StogasEndpoints   map[string]compiledStogasEndpoint   `json:"stogasEndpoints"`
	Stogas            compiledStogas                      `json:"stogas"`
}

type compiledAuthor struct {
	AuthorSlugs []string `json:"authorSlugs"`
}

type compiledStogas struct {
	ResponseMetadataFields []string `json:"responseMetadataFields"`
}

type compiledDeployment struct {
	AliasSlugs                  []string       `json:"aliasSlugs"`
	ContextWindowTokens         int            `json:"contextWindowTokens"`
	MaxOutputTokens             int            `json:"maxOutputTokens"`
	ProviderID                  string         `json:"providerId"`
	ParentProviderEndpointNodes []string       `json:"parentProviderEndpointNodes"`
	ModelID                     string         `json:"modelId"`
	ServiceTier                 string         `json:"serviceTier"`
	Pricing                     Pricing        `json:"pricing"`
	UpstreamModelSlug           string         `json:"upstreamModelSlug"`
}

type compiledModel struct {
	ModelSlugs          []string `json:"modelSlugs"`
	AuthorID            string   `json:"authorId"`
	ContextWindowTokens int      `json:"contextWindowTokens"`
	MaxOutputTokens     int      `json:"maxOutputTokens"`
	ReasoningSupport    bool     `json:"reasoning"`
}

type compiledProviderEndpoint struct {
	ID              string   `json:"-"`
	DeploymentIDs   []string `json:"deploymentIds"`
	ProviderID      string   `json:"providerId"`
	Pricing         Pricing  `json:"pricing"`
	StogasEndpoints []string `json:"stogasEndpoints"`
}

type compiledProvider struct {
	ProviderSlugs []string `json:"providerSlugs"`
	Pricing       Pricing  `json:"pricing"`
}

type compiledStogasEndpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}
