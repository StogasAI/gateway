package catalog

import (
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

type Identity struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}

type Deployment struct {
	ID                    string
	ModelID               string
	Upstream              Upstream
	Capabilities          Capabilities
	ContextWindowTokens   int
	ImpliedServiceTier    *schemas.BifrostServiceTier
	MaxOutputTokens       int
	Pricing               Pricing
	RouteIDs              []string
	ReasoningAvailability string
	ReasoningEfforts      []string
	ReasoningMaxTokens    *ReasoningMaxTokens
	ReasoningSupported    bool
	TEE                   *TEE
	snapshot              *snapshot
}

type TEE struct {
	ExternalNetworkEgress string `json:"externalNetworkEgress"`
	Mechanism             string `json:"mechanism"`
	Status                string `json:"status"`
}

type Upstream struct {
	Model         string
	ChuteID       string
	GPUCount      int
	InferenceGeo  string
	ReasoningMode string
	ServiceTier   string
	Speed         string
}

type ReasoningMaxTokens struct {
	Maximum int `json:"maximum"`
	Minimum int `json:"minimum"`
}

type Pricing = billing.Pricing
type MeterEstimate = billing.MeterEstimate

type snapshot struct {
	deploymentSelectors map[string]string
	graph               compiledGraph
	identity            Identity
	modelSelectors      map[string]string
	publicDigest        string
	publicRaw           []byte
	raw                 []byte
	routeDeployments    map[string][]string
}

type compiledCatalog struct {
	Schema string        `json:"schema"`
	Graph  compiledGraph `json:"graph"`
}

type compiledGraph struct {
	Authors     map[string]compiledAuthor     `json:"authors"`
	Deployments map[string]compiledDeployment `json:"deployments"`
	Models      map[string]compiledModel      `json:"models"`
	Providers   map[string]compiledProvider   `json:"providers"`
	Routes      map[string]compiledRoute      `json:"routes"`
}

type compiledAuthor struct {
	Aliases []string `json:"aliases"`
	Name    string   `json:"name"`
}

type compiledDeployment struct {
	Aliases               []string            `json:"aliases"`
	Capabilities          Capabilities        `json:"capabilities"`
	ContextWindowTokens   int                 `json:"contextWindowTokens"`
	InputModalities       []string            `json:"inputModalities"`
	MaxOutputTokens       int                 `json:"maxOutputTokens"`
	ModelID               string              `json:"modelId"`
	OutputModalities      []string            `json:"outputModalities"`
	Pricing               Pricing             `json:"pricing"`
	ReasoningAvailability string              `json:"reasoningAvailability"`
	ReasoningEfforts      []string            `json:"reasoningEfforts"`
	ReasoningMaxTokens    *ReasoningMaxTokens `json:"reasoningMaxTokens"`
	DeprecationDate       *string             `json:"deprecationDate"`
	RouteIDs              []string            `json:"routeIds"`
	TEE                   *TEE                `json:"tee,omitempty"`
	Upstream              compiledUpstream    `json:"upstream"`
}

type Capabilities struct {
	Cancellation            bool     `json:"cancellation"`
	FunctionCalling         bool     `json:"functionCalling"`
	InputModalities         []string `json:"inputModalities"`
	OutputModalities        []string `json:"outputModalities"`
	ParallelFunctionCalling bool     `json:"parallelFunctionCalling"`
	PDFInput                bool     `json:"pdfInput"`
	ImplicitPromptCaching   bool     `json:"implicitPromptCaching"`
	ExplicitPromptCaching   bool     `json:"explicitPromptCaching"`
	Streaming               bool     `json:"streaming"`
	StructuredOutputs       bool     `json:"structuredOutputs"`
	SystemMessages          bool     `json:"systemMessages"`
	ToolChoice              bool     `json:"toolChoice"`
	URLContext              bool     `json:"urlContext"`
	WebSearch               bool     `json:"webSearch"`
}

type compiledUpstream struct {
	Model         string `json:"model"`
	ChuteID       string `json:"chuteId,omitempty"`
	GPUCount      int    `json:"gpuCount,omitempty"`
	InferenceGeo  string `json:"inferenceGeo,omitempty"`
	ReasoningMode string `json:"reasoningMode,omitempty"`
	ServiceTier   string `json:"serviceTier,omitempty"`
	Speed         string `json:"speed,omitempty"`
}

type compiledModel struct {
	Aliases               []string            `json:"aliases"`
	AuthorID              string              `json:"authorId"`
	MaxOutputTokens       int                 `json:"maxOutputTokens"`
	Name                  string              `json:"name"`
	ReasoningAvailability string              `json:"reasoningAvailability"`
	ReasoningEfforts      []string            `json:"reasoningEfforts"`
	ReasoningMaxTokens    *ReasoningMaxTokens `json:"reasoningMaxTokens"`
	ReleaseDate           string              `json:"releaseDate"`
}

type compiledProvider struct {
	Aliases         []string `json:"aliases"`
	CredentialModes []string `json:"credentialModes"`
	Name            string   `json:"name"`
}

type compiledRoute struct {
	ID            string   `json:"-"`
	DeploymentIDs []string `json:"-"`
	Interfaces    []string `json:"interfaces"`
	ProviderID    string   `json:"providerId"`
}

type signedEnvelope struct {
	Schema    string          `json:"schema"`
	KeyID     string          `json:"keyId"`
	Manifest  releaseManifest `json:"manifest"`
	Signature string          `json:"signature"`
}

type releaseManifest struct {
	Schema        string               `json:"schema"`
	Sequence      uint64               `json:"sequence"`
	CatalogSchema int                  `json:"catalogSchema"`
	Runtime       string               `json:"runtime"`
	Public        string               `json:"public"`
	Source        catalogReleaseSource `json:"source"`
}

type catalogReleaseSource struct {
	Commit     string `json:"commit"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Tree       string `json:"tree"`
}
