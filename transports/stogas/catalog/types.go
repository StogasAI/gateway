package catalog

import (
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

type Route string

const (
	RouteChat      Route = "chat-completions"
	RouteResponses Route = "responses"

	defaultRefreshInterval = 5 * time.Minute
	canonicalAuthHeader    = "authorization"
)

type Source struct {
	Path            string
	RefreshInterval time.Duration
	URL             string
}

type Deployment struct {
	ID                  string
	ModelID             string
	Model               string
	ContextWindowTokens int
	ImpliedServiceTier  *schemas.BifrostServiceTier
	AllowedServiceTier  *schemas.BifrostServiceTier
	MaxOutputTokens     int
	Pricing             Pricing
	ReasoningSupported  bool
	ParameterPolicies   map[string]compiledParameter
}

type Pricing map[string]map[string]string

type SlugProjection struct {
	ExpandAttributeWithEnumeratedPrefixes  [][]string `json:"expandAttributeWithEnumeratedPrefixes"`
	ExpandAttributeWithEnumeratedSuffixes  []string   `json:"expandAttributeWithEnumeratedSuffixes"`
	From                                   string     `json:"from"`
	IncludeReferencedSlugs                 bool       `json:"includeReferencedSlugs"`
	Value                                  []string   `json:"value"`
}

type snapshot struct {
	graph                    compiledGraph
	providerNativeModelSlugs map[string]string
	responseMetadataFields   map[string]struct{}
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
	ConcreteSlugs       SlugProjection              `json:"concreteSlugs"`
	ModelSlugs          SlugProjection              `json:"modelSlugs"`
	ContextWindowTokens  int                         `json:"contextWindowTokens"`
	MaxOutputTokens      int                         `json:"maxOutputTokens"`
	ProviderID           string                      `json:"providerId"`
	ProviderEndpointIDs  []string                    `json:"providerEndpointIds"`
	ModelID              string                      `json:"modelId"`
	ServiceTier          string                      `json:"serviceTier"`
	Schema               compiledSchemaPatch         `json:"schema"`
	ParameterPolicies    map[string]compiledParameter `json:"-"`
	Pricing              Pricing                     `json:"pricing"`
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

type compiledParameter struct {
	Alias             string               `json:"alias"`
	DeleteAttribute   bool                 `json:"deleteAttribute"`
	ImplyValue        any                  `json:"implyValue"`
	Max               *float64             `json:"max"`
	Min               *float64             `json:"min"`
	OverrideAttribute bool                 `json:"overrideAttribute"`
	Reject            []compiledRejectRule `json:"reject"`
	RejectConflict    bool                 `json:"rejectConflict"`
	RejectUnsupported string               `json:"rejectUnsupported"`
	Values            []string             `json:"values"`
}

type compiledRejectRule struct {
	AllowedKeys  []string `json:"allowedKeys"`
	Exists       bool     `json:"exists"`
	Missing      bool     `json:"missing"`
	Path         string   `json:"path"`
	Prefixes     []string `json:"prefixes"`
	RequiredKeys []string `json:"requiredKeys"`
	Values       []any    `json:"values"`
	ValuesExcept []any    `json:"valuesExcept"`
}
