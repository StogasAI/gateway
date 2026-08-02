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

type Identity struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}

type Deployment struct {
	ID                  string
	ModelID             string
	Upstream            Upstream
	ContextWindowTokens int
	ImpliedServiceTier  *schemas.BifrostServiceTier
	MaxOutputTokens     int
	Pricing             Pricing
	RouteIDs            []string
	ReasoningEfforts    []string
	ReasoningSupported  bool
	snapshot            *snapshot
}

type Upstream struct {
	Model        string
	FixedRequest UpstreamFixedRequest
}

type UpstreamFixedRequest struct {
	InferenceGeo string
	ServiceTier  string
	Speed        string
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
	Aliases          []string             `json:"aliases"`
	Capabilities     compiledCapabilities `json:"capabilities"`
	Default          bool                 `json:"default"`
	Limits           compiledLimits       `json:"limits"`
	ModelID          string               `json:"modelId"`
	Pricing          Pricing              `json:"pricing"`
	ReasoningEfforts []string             `json:"reasoningEfforts"`
	DeprecationDate  *string              `json:"deprecationDate"`
	RouteIDs         []string             `json:"routeIds"`
	Upstream         compiledUpstream     `json:"upstream"`
}

type compiledCapabilities struct {
	Cancellation            bool     `json:"cancellation"`
	FunctionCalling         bool     `json:"functionCalling"`
	InputModalities         []string `json:"inputModalities"`
	OutputModalities        []string `json:"outputModalities"`
	ParallelFunctionCalling bool     `json:"parallelFunctionCalling"`
	PDFInput                bool     `json:"pdfInput"`
	PromptCaching           bool     `json:"promptCaching"`
	Streaming               bool     `json:"streaming"`
	StructuredOutputs       bool     `json:"structuredOutputs"`
	SystemMessages          bool     `json:"systemMessages"`
	ToolChoice              bool     `json:"toolChoice"`
	URLContext              bool     `json:"urlContext"`
	WebSearch               bool     `json:"webSearch"`
}

type compiledLimits struct {
	ContextTokens int `json:"contextTokens"`
	OutputTokens  int `json:"outputTokens"`
}

type compiledUpstream struct {
	Model        string                       `json:"model"`
	FixedRequest compiledUpstreamFixedRequest `json:"fixedRequest"`
}

type compiledUpstreamFixedRequest struct {
	InferenceGeo string `json:"inference_geo,omitempty"`
	ServiceTier  string `json:"service_tier,omitempty"`
	Speed        string `json:"speed,omitempty"`
}

type compiledModel struct {
	Aliases     []string `json:"aliases"`
	AuthorID    string   `json:"authorId"`
	Name        string   `json:"name"`
	ReleaseDate string   `json:"releaseDate"`
}

type compiledProvider struct {
	Aliases []string `json:"aliases"`
	Name    string   `json:"name"`
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
