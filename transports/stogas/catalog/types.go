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

type Pricing map[string]PricingMeter

type PricingMeter struct {
	Rates map[string]string `json:"rates"`
}

type AttributeStringList struct {
	Value []string       `json:"value"`
	Rules AttributeRules `json:"rules"`
}

type AttributeRules struct {
	Compile CompileRules `json:"compile"`
}

type CompileRules struct {
	Action string `json:"action"`
}

type snapshot struct {
	graph                  compiledGraph
	modelAliases           map[string]string
	responseMetadataFields map[string]struct{}
}

type compiledCatalog struct {
	Graph compiledGraph `json:"graph"`
}

type compiledGraph struct {
	Deployments       map[string]compiledDeployment       `json:"deployments"`
	Models            map[string]compiledModel            `json:"models"`
	ProviderEndpoints map[string]compiledProviderEndpoint `json:"providerEndpoints"`
	StogasEndpoints   map[string]compiledStogasEndpoint   `json:"stogasEndpoints"`
	Stogas            compiledStogas                      `json:"stogas"`
}

type compiledStogas struct {
	ResponseMetadataFields []string `json:"responseMetadataFields"`
}

type compiledDeployment struct {
	AliasSlugs          AttributeStringList          `json:"aliasSlugs"`
	ContextWindowTokens int                          `json:"contextWindowTokens"`
	MaxOutputTokens     int                          `json:"maxOutputTokens"`
	ProviderID          string                       `json:"providerId"`
	ModelID             string                       `json:"modelId"`
	ServiceTier         string                       `json:"serviceTier"`
	Schema              compiledSchemaPatch          `json:"schema"`
	ParameterPolicies   map[string]compiledParameter `json:"-"`
	Pricing             Pricing                      `json:"pricing"`
}

type compiledModel struct {
	AliasSlugs          []string `json:"aliasSlugs"`
	CanonicalSlug       string   `json:"canonicalSlug"`
	ContextWindowTokens int      `json:"contextWindowTokens"`
	MaxOutputTokens     int      `json:"maxOutputTokens"`
	ReasoningSupport    bool     `json:"reasoningSupported"`
}

type compiledProviderEndpoint struct {
	DeploymentIDs     []string                     `json:"deploymentIds"`
	ProviderID        string                       `json:"providerId"`
	Schema            compiledSchemaPatch          `json:"schema"`
	ParameterPolicies map[string]compiledParameter `json:"-"`
	Pricing           Pricing                      `json:"pricing"`
	StogasEndpointID  string                       `json:"stogasEndpointId"`
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
	Rules  compiledParameterRules `json:"rules"`
	Values []string               `json:"values"`
	Min    *float64               `json:"min"`
	Max    *float64               `json:"max"`
}

type compiledParameterRules struct {
	Compile CompileRules                  `json:"compile"`
	Gateway compiledParameterGatewayRules `json:"gateway"`
}

type compiledParameterGatewayRules struct {
	Directives []compiledGatewayDirective `json:"directives"`
	Canonical  string                     `json:"canonical"`
}

type compiledGatewayDirective struct {
	AllowedKeys  []string `json:"allowedKeys"`
	Exists       bool     `json:"exists"`
	Missing      bool     `json:"missing"`
	Op           string   `json:"op"`
	Path         string   `json:"path"`
	Prefixes     []string `json:"prefixes"`
	RequiredKeys []string `json:"requiredKeys"`
	Source       string   `json:"source"`
	Target       string   `json:"target"`
	Value        any      `json:"value"`
	Values       []any    `json:"values"`
	ValuesExcept []any    `json:"valuesExcept"`
}
