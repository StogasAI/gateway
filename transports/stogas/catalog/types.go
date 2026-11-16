package catalog

import (
	"slices"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/location"
)

type Route string

const (
	RouteChat           Route                 = "chat-completions"
	RouteResponses      Route                 = "responses"
	ProviderChutes      schemas.ModelProvider = "chutes"
	ProviderAzure       schemas.ModelProvider = schemas.Azure
	ProviderAWS         schemas.ModelProvider = "aws"
	ProviderGoogleCloud schemas.ModelProvider = "google-cloud"

	canonicalAuthHeader = "authorization"
)

// UsesClaudeWire reports whether a provider serves the model over Anthropic's Messages API, which
// bills cache writes by duration and takes a manual thinking budget. AWS and Google Cloud serve
// only Claude.
func UsesClaudeWire(provider schemas.ModelProvider, modelID string) bool {
	switch provider {
	case schemas.Anthropic, ProviderAWS, ProviderGoogleCloud:
		return true
	case schemas.Azure:
		return schemas.IsAnthropicModel(modelID)
	}
	return false
}

// Interface is the catalog interface that a route serves, such as chat_completions.
func (r Route) Interface() string { return strings.ReplaceAll(string(r), "-", "_") }

// RouteForInterface reads an interface as policies and route.interfaces spell it.
func RouteForInterface(name string) (Route, bool) {
	for _, route := range []Route{RouteChat, RouteResponses} {
		if route.Interface() == name {
			return route, true
		}
	}
	return "", false
}

type Identity struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}

// Deployment is a deployment as it serves one route.
type Deployment struct {
	ID        string
	ChainHash string
	ModelID   string
	RouteID   string
	// Hosting is the company that runs the model: the provider's own, another whose service the
	// provider resells, or HostingUnknown.
	Hosting             string
	Upstream            Upstream
	Capabilities        Capabilities
	DocumentFormats     DocumentFormats
	InputModalities     []string
	OutputModalities    []string
	ContextWindowTokens int
	MaxInputTokens      int
	MaxOutputTokens     int
	Pricing             Pricing
	Reasoning           string
	ReasoningEfforts    []string
	ReasoningMaxTokens  *ReasoningMaxTokens
	ReasoningSupported  bool
	DataHandling        DataHandling
	// HostedTools are the tools that the route runs for the deployment. Each can only make
	// DataHandling worse, for requests that let the model call it.
	HostedTools map[HostedTool]HostedToolOffer
	// Locations are the places of the catalog that the deployment belongs to, which say what
	// lies within each data handling location.
	Locations        *location.Places
	ApprovalRequired bool
	WeightPrecision  string
	// snapshot is the catalog state in effect when the request started, so the hold and the
	// charge use the same facts.
	snapshot  *snapshot
	startedAt time.Time
}

type DataHandling struct {
	ProcessingLocation string `json:"processingLocation"`
	StorageLocation    string `json:"storageLocation"`
	EndToEndEncrypted  bool   `json:"endToEndEncrypted"`
	RetentionDays      *int   `json:"retentionDays"`
	// TrainingUse is nil when the provider does not say whether it trains on the data.
	TrainingUse       *bool `json:"trainingUse"`
	ZeroDataRetention bool  `json:"zeroDataRetention"`
	TEE               bool  `json:"tee"`
	TEEVerified       bool  `json:"teeVerified"`
	// SharedWith lists, in order, each company other than the provider's and the hosting that
	// receives requests, or HostingUnknown for companies that the provider does not name.
	SharedWith []string `json:"sharedWith"`
}

func (d DataHandling) equal(other DataHandling) bool {
	same := func(a, b *int) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
	known := func(a, b *bool) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
	return d.ProcessingLocation == other.ProcessingLocation && d.StorageLocation == other.StorageLocation &&
		d.EndToEndEncrypted == other.EndToEndEncrypted && same(d.RetentionDays, other.RetentionDays) &&
		known(d.TrainingUse, other.TrainingUse) && d.ZeroDataRetention == other.ZeroDataRetention &&
		d.TEE == other.TEE && d.TEEVerified == other.TEEVerified && slices.Equal(d.SharedWith, other.SharedWith)
}

// CompanyAnthropic is Anthropic's company, which runs Claude on its own API and behind the sign-in
// and billing of other providers.
const CompanyAnthropic = "anthropic"

// HostingUnknown stands for a company that a provider does not name, as a hosting or as one that
// requests are shared with.
const HostingUnknown = "unknown"

type Upstream struct {
	Model          string
	ModelFormat    string
	ModelVersion   string
	ChuteID        string
	GPUCount       *int
	InferenceGeo   string
	ReasoningMode  string
	ServiceTier    string
	DeploymentType string
}

type ReasoningMaxTokens struct {
	Maximum int `json:"maximum"`
	Minimum int `json:"minimum"`
}

type Pricing = billing.Pricing
type MeterEstimate = billing.MeterEstimate

// A snapshot is one catalog state of a release. The base state also holds the dated states
// that follow it.
type snapshot struct {
	graph    compiledGraph
	identity Identity
	// modelSelectors maps each model ID and alias to its model, for /v1/models.
	modelSelectors map[string]string
	// index finds the IDs that a request's model field names.
	index *selectorIndex
	// served is the root with the identity of its release, as readers fetch it.
	served []byte
	// parts holds each part of the root that the release came with, by SHA-256 in hex.
	parts    map[string][]byte
	schedule []datedState
	// places are the catalog's locations, and companies its companies, which every state shares.
	places    *location.Places
	companies map[string]company
}

type datedState struct {
	start time.Time
	state *snapshot
}

type compiledGraph struct {
	Authors map[string]compiledAuthor `json:"authors"`
	// A dated state copies the map of each kind that it changes, and deployments are the most
	// numerous and the most often changed, so their map holds pointers.
	Deployments map[string]*compiledDeployment `json:"deployments"`
	Models      map[string]compiledModel       `json:"models"`
	Providers   map[string]compiledProvider    `json:"providers"`
	Routes      map[string]compiledRoute       `json:"routes"`
}

// The root holds each author and provider whole. The gateway tells when records retire, and
// whether Stogas serves them, from their deployments, so it skips both.
type compiledAuthor struct {
	Notes           shown    `json:"notes"`
	RetirementDate  shown    `json:"retirementDate"`
	StogasSupported shown    `json:"stogasSupported"`
	Aliases         []string `json:"aliases"`
	// CompanyID names the author's company, whose headquarters HeadquarteredCountry repeats.
	CompanyID            string `json:"companyId"`
	HeadquarteredCountry string `json:"headquarteredCountry"`
	Name                 string `json:"name"`
}

// A compiled deployment holds the facts that hold on all its routes, and for each route the
// facts that combine the route with the model and deployment.
type compiledDeployment struct {
	ApprovalRequired    bool     `json:"approvalRequired"`
	ContextWindowTokens int      `json:"contextWindowTokens"`
	Hosting             string   `json:"hosting"`
	MaxInputTokens      int      `json:"maxInputTokens"`
	MaxOutputTokens     int      `json:"maxOutputTokens"`
	ModelID             string   `json:"modelId"`
	Notes               shown    `json:"notes"`
	OutputModalities    []string `json:"outputModalities"`
	Pricing             Pricing  `json:"pricing"`
	// PromptCacheMinimumTokens is the fewest prompt tokens that the provider caches, and
	// ReasoningDefault what a request that sets no reasoning gets. Policies read both, and the
	// gateway sends nothing because of either.
	PromptCacheMinimumTokens *int                               `json:"promptCacheMinimumTokens"`
	Reasoning                string                             `json:"reasoning"`
	ReasoningDefault         *string                            `json:"reasoningDefault"`
	ReasoningMaxTokens       *ReasoningMaxTokens                `json:"reasoningMaxTokens"`
	RetirementDate           *string                            `json:"retirementDate"`
	Routes                   map[string]compiledDeploymentRoute `json:"routes"`
	StogasSupported          shown                              `json:"stogasSupported"`
	Upstream                 compiledUpstream                   `json:"upstream"`
	WeightPrecision          string                             `json:"weightPrecision"`
}

type compiledDeploymentRoute struct {
	Capabilities Capabilities `json:"capabilities"`
	ChainHash    string       `json:"chainHash"`
	DataHandling DataHandling `json:"dataHandling"`
	// HostedTools are the tools that the route runs for this deployment, each with its call meters.
	HostedTools map[HostedTool]HostedToolOffer `json:"hostedTools"`
	// InputLimits are the provider's limits on a request and its files. The provider enforces
	// them, and policies read them.
	InputLimits     InputLimits `json:"inputLimits"`
	InputModalities []string    `json:"inputModalities"`
	// Pricing holds every meter that the deployment bills on the route: the deployment's own
	// and the call meters of the route's hosted tools. The loader derives it.
	Pricing          Pricing  `json:"-"`
	ReasoningEfforts []string `json:"reasoningEfforts"`
	// Sampling says which sampling parameters the deployment accepts on the route. Policies read
	// it, and the gateway forwards those parameters unchanged.
	Sampling Sampling `json:"sampling"`
}

// InputLimits holds each limit in bytes before encoding, or nil where the provider states none.
type InputLimits struct {
	Documents    DocumentLimits `json:"documents"`
	Images       ImageLimits    `json:"images"`
	RequestBytes *int           `json:"requestBytes"`
}

type DocumentLimits struct {
	Bytes      *int `json:"bytes"`
	Count      *int `json:"count"`
	Pages      *int `json:"pages"`
	TotalBytes *int `json:"totalBytes"`
}

type ImageLimits struct {
	Bytes      *int `json:"bytes"`
	Count      *int `json:"count"`
	Pixels     *int `json:"pixels"`
	TotalBytes *int `json:"totalBytes"`
}

// Sampling says, for each parameter, whether a value other than the default is accepted in at
// least one reasoning setting.
type Sampling struct {
	FrequencyPenalty  bool `json:"frequencyPenalty"`
	LogitBias         bool `json:"logitBias"`
	PresencePenalty   bool `json:"presencePenalty"`
	RepetitionPenalty bool `json:"repetitionPenalty"`
	Seed              bool `json:"seed"`
	Temperature       bool `json:"temperature"`
	TopK              bool `json:"topK"`
	TopP              bool `json:"topP"`
}

type Capabilities struct {
	FunctionCalling         bool `json:"functionCalling"`
	ParallelFunctionCalling bool `json:"parallelFunctionCalling"`
	ImplicitPromptCaching   bool `json:"implicitPromptCaching"`
	ExplicitPromptCaching   bool `json:"explicitPromptCaching"`
	Streaming               bool `json:"streaming"`
	StructuredOutputs       bool `json:"structuredOutputs"`
	SystemMessages          bool `json:"systemMessages"`
	ToolChoice              bool `json:"toolChoice"`
}

type compiledUpstream struct {
	Model          string `json:"model"`
	ModelFormat    string `json:"modelFormat,omitempty"`
	ModelVersion   string `json:"modelVersion,omitempty"`
	ChuteID        string `json:"chuteId,omitempty"`
	GPUCount       *int   `json:"gpuCount,omitempty"`
	InferenceGeo   string `json:"inferenceGeo,omitempty"`
	ReasoningMode  string `json:"reasoningMode,omitempty"`
	ServiceTier    string `json:"serviceTier"`
	DeploymentType string `json:"deploymentType,omitempty"`
}

type compiledModel struct {
	// Readers show these. A model's limits, modalities and capabilities are defaults that its
	// deployments and their routes already hold.
	Capabilities                shown `json:"capabilities"`
	ContextWindowTokens         shown `json:"contextWindowTokens"`
	InputLimits                 shown `json:"inputLimits"`
	InputModalities             shown `json:"inputModalities"`
	KnowledgeCutoff             shown `json:"knowledgeCutoff"`
	MaxInputTokens              shown `json:"maxInputTokens"`
	Notes                       shown `json:"notes"`
	OutputModalities            shown `json:"outputModalities"`
	PromptCacheMinimumTokens    shown `json:"promptCacheMinimumTokens"`
	ReasoningDefault            shown `json:"reasoningDefault"`
	ReasoningEffortsByInterface shown `json:"reasoningEffortsByInterface"`
	Sampling                    shown `json:"sampling"`
	Snapshot                    shown `json:"snapshot"`

	Aliases            []string            `json:"aliases"`
	AuthorID           string              `json:"authorId"`
	GroupIDs           []string            `json:"groupIds"`
	MaxOutputTokens    int                 `json:"maxOutputTokens"`
	Name               string              `json:"name"`
	OpenWeights        bool                `json:"openWeights"`
	Reasoning          string              `json:"reasoning"`
	ReasoningEfforts   []string            `json:"reasoningEfforts"`
	ReasoningMaxTokens *ReasoningMaxTokens `json:"reasoningMaxTokens"`
	ReleaseDate        string              `json:"releaseDate"`
}

type compiledProvider struct {
	// AccountLocations are the places where an account's resources can keep data. A credential
	// narrows storage to its resource's place, which the gateway checks against the catalog's places.
	AccountLocations shown    `json:"accountLocations"`
	Notes            shown    `json:"notes"`
	RetirementDate   shown    `json:"retirementDate"`
	StogasSupported  shown    `json:"stogasSupported"`
	Aliases          []string `json:"aliases"`
	// CompanyID names the provider's company, whose headquarters HeadquarteredCountry repeats.
	CompanyID            string   `json:"companyId"`
	CredentialModes      []string `json:"credentialModes"`
	HeadquarteredCountry string   `json:"headquarteredCountry"`
	Name                 string   `json:"name"`
}

type compiledRoute struct {
	// Readers show these. A route's capabilities, data handling, modalities and hosted tools
	// are defaults and offers that each deployment's route already holds.
	Capabilities    shown `json:"capabilities"`
	DataHandling    shown `json:"dataHandling"`
	Batch           shown `json:"batch"`
	HostedTools     shown `json:"hostedTools"`
	InputLimits     shown `json:"inputLimits"`
	InputModalities shown `json:"inputModalities"`
	Notes           shown `json:"notes"`
	Sampling        shown `json:"sampling"`
	// Stogas does not serve a route, so none of its deployments either.
	StogasSupported shown `json:"stogasSupported"`

	ID              string          `json:"-"`
	DeploymentIDs   []string        `json:"-"`
	DocumentFormats DocumentFormats `json:"documentFormats"`
	Interfaces      []string        `json:"interfaces"`
	ProviderID      string          `json:"providerId"`
	// The day that the provider names for shutting the route down, or for its own end.
	RetirementDate *string `json:"retirementDate"`
}
