package catalog

import (
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/providers"
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
	ProfileIDs          []string
	ReasoningSupported  bool
	ServiceTier         string
	ParameterPolicies   map[string]compiledParameter
}

type Pricing = providers.Pricing

type SlugProjection struct {
	ExpandAttributeWithEnumeratedPrefixes [][]string `json:"expandAttributeWithEnumeratedPrefixes"`
	ExpandAttributeWithEnumeratedSuffixes []string   `json:"expandAttributeWithEnumeratedSuffixes"`
	Value                                 []string   `json:"value"`
}

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
	ConcreteSlugs               SlugProjection               `json:"concreteSlugs"`
	ModelSlugs                  SlugProjection               `json:"modelSlugs"`
	ContextWindowTokens         int                          `json:"contextWindowTokens"`
	MaxOutputTokens             int                          `json:"maxOutputTokens"`
	ProviderID                  string                       `json:"providerId"`
	ParentProviderEndpointNodes []string                     `json:"parentProviderEndpointNodes"`
	ModelID                     string                       `json:"modelId"`
	ServiceTier                 string                       `json:"serviceTier"`
	PolicyProfiles              []string                     `json:"policyProfiles"`
	Schema                      compiledSchemaPatch          `json:"schema"`
	ParameterPolicies           map[string]compiledParameter `json:"-"`
	Pricing                     Pricing                      `json:"pricing"`
}

type compiledModel struct {
	ModelSlugs          []string `json:"modelSlugs"`
	AuthorID            string   `json:"authorId"`
	ContextWindowTokens int      `json:"contextWindowTokens"`
	MaxOutputTokens     int      `json:"maxOutputTokens"`
	ReasoningSupport    bool     `json:"reasoning"`
}

type compiledProviderEndpoint struct {
	ID                string                       `json:"-"`
	DeploymentIDs     []string                     `json:"deploymentIds"`
	ProviderID        string                       `json:"providerId"`
	PolicyProfiles    []string                     `json:"policyProfiles"`
	Schema            compiledSchemaPatch          `json:"schema"`
	ParameterPolicies map[string]compiledParameter `json:"-"`
	Pricing           Pricing                      `json:"pricing"`
	StogasEndpointID  string                       `json:"stogasEndpointId"`
}

type compiledProvider struct {
	ProviderSlugs []string `json:"providerSlugs"`
	Pricing       Pricing  `json:"pricing"`
}

type compiledStogasEndpoint struct {
	Schema compiledStogasEndpointSchema `json:"schema"`
}

type compiledStogasEndpointSchema struct {
	Parameters map[string]compiledParameter `json:"parameters"`
	Headers    map[string]compiledParameter `json:"headers"`
	Method     string                       `json:"method"`
	Path       string                       `json:"path"`
}

type compiledSchemaPatch struct {
	Parameters map[string]compiledParameter `json:"parameters"`
}

type compiledParameter = providers.Parameter
type compiledRejectRule = providers.RejectRule
