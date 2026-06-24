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
	Locations         map[string]any                      `json:"locations"`
	Models            map[string]compiledModel            `json:"models"`
	ProviderEndpoints map[string]compiledProviderEndpoint `json:"providerEndpoints"`
	Providers         map[string]compiledProvider         `json:"providers"`
	StogasEndpoints   map[string]compiledStogasEndpoint   `json:"stogasEndpoints"`
	Stogas            compiledStogas                      `json:"stogas"`
}

type compiledAuthor struct {
	AuthorSlugs []string       `json:"authorSlugs"`
	Description string         `json:"description"`
	Name        string         `json:"name"`
	Region      map[string]any `json:"region"`
}

type compiledStogas struct {
	ResponseMetadataFields []string `json:"responseMetadataFields"`
}

type compiledDeployment struct {
	AliasSlugs                  []string       `json:"aliasSlugs"`
	ContextWindowTokens         *int           `json:"contextWindowTokens,omitempty"`
	MaxOutputTokens             *int           `json:"maxOutputTokens,omitempty"`
	ProviderID                  string         `json:"providerId"`
	ParentProviderEndpointNodes []string       `json:"parentProviderEndpointNodes"`
	ModelID                     string         `json:"modelId"`
	ServiceTier                 string         `json:"serviceTier"`
	Pricing                     Pricing        `json:"pricing"`
	StreamCancellation          string         `json:"streamCancellation,omitempty"`
	Streaming                   string         `json:"streaming,omitempty"`
	TEE                         map[string]any `json:"tee,omitempty"`
	Tokenizer                   string         `json:"tokenizer,omitempty"`
	UpstreamModelSlug           string         `json:"upstreamModelSlug"`
}

type compiledModel struct {
	AuthorID            string   `json:"authorId"`
	ContextWindowTokens int      `json:"contextWindowTokens"`
	Family              string   `json:"family"`
	Flavors             []string `json:"flavors"`
	InputModalities     []string `json:"inputModalities"`
	KnowledgeCutoff     *string  `json:"knowledgeCutoff"`
	MaxOutputTokens     int      `json:"maxOutputTokens"`
	Name                string   `json:"name"`
	OutputModalities    []string `json:"outputModalities"`
	ReleaseDate         *string  `json:"releaseDate"`
	ReasoningSupport    bool     `json:"reasoning"`
	Series              string   `json:"series"`
	Snapshot            *string  `json:"snapshot"`
	Tokenizer           string   `json:"tokenizer"`
}

type compiledProviderEndpoint struct {
	ID                        string   `json:"-"`
	Class                     string   `json:"class"`
	DeploymentIDs             []string `json:"deploymentIds"`
	E2EE                      string   `json:"e2ee"`
	Endpoint                  string   `json:"endpoint"`
	FallbackBehavior          string   `json:"fallbackBehavior"`
	GDPR                      string   `json:"gdpr"`
	ProviderID                string   `json:"providerId"`
	Pricing                   Pricing  `json:"pricing"`
	RegionID                  string   `json:"regionId"`
	RegionalProcessingClaimed bool     `json:"regionalProcessingClaimed"`
	RegionalStorageClaimed    bool     `json:"regionalStorageClaimed"`
	StogasEndpoints           []string `json:"stogasEndpoints"`
}

type compiledProvider struct {
	CancellationSupported                         bool     `json:"cancellationSupported"`
	CountTokensEndpoints                          []string `json:"countTokensEndpoints"`
	DatacenterLocationIDs                         []string `json:"datacenterLocationIds"`
	DataRetentionDaysClaimed                      int      `json:"dataRetentionDaysClaimed"`
	DataSharedForCrossContextBehavioralAdsClaimed bool     `json:"dataSharedForCrossContextBehavioralAdsClaimed"`
	DataSoldClaimed                               bool     `json:"dataSoldClaimed"`
	DataStorageRegionPinnedByDefaultClaimed       bool     `json:"dataStorageRegionPinnedByDefaultClaimed"`
	DataUsedForTrainingClaimed                    bool     `json:"dataUsedForTrainingClaimed"`
	FunctionCallingSupported                      bool     `json:"functionCallingSupported"`
	HeadquarteredLocationID                       string   `json:"headquarteredLocationId"`
	Moderated                                     bool     `json:"moderated"`
	Name                                          string   `json:"name"`
	Pricing                                       Pricing  `json:"pricing"`
	PromptCachingSupported                        bool     `json:"promptCachingSupported"`
	ProviderSlugs                                 []string `json:"providerSlugs"`
	StreamCancellationSupported                   bool     `json:"streamCancellationSupported"`
	StreamingSupported                            bool     `json:"streamingSupported"`
	SystemMessagesSupported                       bool     `json:"systemMessagesSupported"`
	ToolChoiceSupported                           bool     `json:"toolChoiceSupported"`
	UsesPseudoanonymousUserID                     bool     `json:"usesPseudoanonymousUserId"`
	WebSearchSupported                            bool     `json:"webSearchSupported"`
}

type compiledStogasEndpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}
