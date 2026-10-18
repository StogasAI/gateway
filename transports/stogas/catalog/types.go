package catalog

import (
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

type Route string

const (
	RouteChat      Route                 = "chat-completions"
	RouteResponses Route                 = "responses"
	ProviderChutes schemas.ModelProvider = "chutes"
	ProviderAzure  schemas.ModelProvider = schemas.Azure

	canonicalAuthHeader = "authorization"
)

// Interface is the catalog interface that a route serves, such as chat_completions.
func (r Route) Interface() string { return strings.ReplaceAll(string(r), "-", "_") }

type Identity struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}

// Deployment is a deployment as it serves one route.
type Deployment struct {
	ID                  string
	ChainHash           string
	ModelID             string
	RouteID             string
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
	ApprovalRequired    bool
	WeightPrecision     string
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
	TrainingUse        bool   `json:"trainingUse"`
	ZeroDataRetention  bool   `json:"zeroDataRetention"`
	TEE                bool   `json:"tee"`
	TEEVerified        bool   `json:"teeVerified"`
}

type Upstream struct {
	Model          string
	ModelFormat    string
	ModelVersion   string
	ChuteID        string
	GPUCount       *int
	InferenceGeo   string
	ReasoningMode  string
	ServiceTier    string
	Hosting        string
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
	graph compiledGraph
	// groups holds every model group. Each is a request selector for its newest model.
	groups         map[string]bool
	identity       Identity
	modelSelectors map[string]string
	publicDigest   string
	publicRaw      []byte
	raw            []byte
	schedule       []datedState
}

type datedState struct {
	start time.Time
	state *snapshot
}

type compiledCatalog struct {
	Schema       string          `json:"schema"`
	PublicDigest string          `json:"publicDigest"`
	Graph        compiledGraph   `json:"graph"`
	Schedule     []scheduleEntry `json:"schedule"`
}

// A schedule entry lists every node that differs from the base graph from Start until the
// next entry starts.
type scheduleEntry struct {
	Start time.Time     `json:"start"`
	Graph compiledGraph `json:"graph"`
}

type compiledGraph struct {
	Authors     map[string]compiledAuthor     `json:"authors"`
	Deployments map[string]compiledDeployment `json:"deployments"`
	Models      map[string]compiledModel      `json:"models"`
	Providers   map[string]compiledProvider   `json:"providers"`
	Routes      map[string]compiledRoute      `json:"routes"`
}

type compiledAuthor struct {
	Aliases              []string `json:"aliases"`
	HeadquarteredCountry string   `json:"headquarteredCountry,omitempty"`
	Name                 string   `json:"name"`
}

// A compiled deployment holds the facts that hold on all its routes, and for each route the
// facts that combine the route with the model and deployment.
type compiledDeployment struct {
	ApprovalRequired    bool                               `json:"approvalRequired"`
	ContextWindowTokens int                                `json:"contextWindowTokens"`
	MaxInputTokens      int                                `json:"maxInputTokens"`
	MaxOutputTokens     int                                `json:"maxOutputTokens"`
	ModelID             string                             `json:"modelId"`
	OutputModalities    []string                           `json:"outputModalities"`
	Reasoning           string                             `json:"reasoning"`
	ReasoningMaxTokens  *ReasoningMaxTokens                `json:"reasoningMaxTokens"`
	RetirementDate      *string                            `json:"retirementDate"`
	Routes              map[string]compiledDeploymentRoute `json:"routes"`
	Upstream            compiledUpstream                   `json:"upstream"`
	WeightPrecision     string                             `json:"weightPrecision"`
}

type compiledDeploymentRoute struct {
	Capabilities     Capabilities `json:"capabilities"`
	ChainHash        string       `json:"chainHash"`
	DataHandling     DataHandling `json:"dataHandling"`
	InputModalities  []string     `json:"inputModalities"`
	Pricing          Pricing      `json:"pricing"`
	ReasoningEfforts []string     `json:"reasoningEfforts"`
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
	Hosting        string `json:"hosting,omitempty"`
	DeploymentType string `json:"deploymentType,omitempty"`
}

type compiledModel struct {
	Aliases            []string            `json:"aliases"`
	AuthorID           string              `json:"authorId"`
	GroupIDs           []string            `json:"groupIds"`
	MaxOutputTokens    int                 `json:"maxOutputTokens"`
	Name               string              `json:"name"`
	Reasoning          string              `json:"reasoning"`
	ReasoningEfforts   []string            `json:"reasoningEfforts"`
	ReasoningMaxTokens *ReasoningMaxTokens `json:"reasoningMaxTokens"`
	ReleaseDate        string              `json:"releaseDate"`
}

type compiledProvider struct {
	Aliases              []string `json:"aliases"`
	CredentialModes      []string `json:"credentialModes"`
	HeadquarteredCountry string   `json:"headquarteredCountry,omitempty"`
	Name                 string   `json:"name"`
}

type compiledRoute struct {
	ID              string          `json:"-"`
	DeploymentIDs   []string        `json:"-"`
	DocumentFormats DocumentFormats `json:"documentFormats"`
	Interfaces      []string        `json:"interfaces"`
	ProviderID      string          `json:"providerId"`
}
