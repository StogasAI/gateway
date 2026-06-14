package catalog

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

type openAIPairsFixture struct {
	Pairs []openAIPairFixture `json:"pairs"`
}

type openAIPairFixture struct {
	ID                    string            `json:"id"`
	Endpoint              string            `json:"endpoint"`
	Request               json.RawMessage   `json:"request"`
	Response              json.RawMessage   `json:"response"`
	StreamFrames          []json.RawMessage `json:"stream_frames"`
	StreamEvents          []json.RawMessage `json:"stream_events"`
	ExpectedCostUSDAtoms  string            `json:"stogas_expected_cost_usd_atoms"`
	ExpectedHoldFloorOnly bool              `json:"stogas_hold_floor_only"`
	KnownPriceNanoUSD     string            `json:"known_price_nano_usd"`
	KnownPriceSource      string            `json:"known_price_source"`
}

type openAIUsageEnvelope struct {
	Usage    *openAIUsage         `json:"usage"`
	Response *openAIUsageEnvelope `json:"response"`
}

type openAIUsage struct {
	PromptTokens            int                       `json:"prompt_tokens"`
	CompletionTokens        int                       `json:"completion_tokens"`
	TotalTokens             int                       `json:"total_tokens"`
	PromptTokensDetails     *openAITokenUsageDetails  `json:"prompt_tokens_details"`
	InputTokens             int                       `json:"input_tokens"`
	OutputTokens            int                       `json:"output_tokens"`
	InputTokensDetails      *openAITokenUsageDetails  `json:"input_tokens_details"`
	OutputTokensDetails     *openAIOutputTokenDetails `json:"output_tokens_details"`
	CompletionTokensDetails *openAIOutputTokenDetails `json:"completion_tokens_details"`
}

type openAITokenUsageDetails struct {
	CachedTokens     int `json:"cached_tokens"`
	CachedReadTokens int `json:"cached_read_tokens"`
}

type openAIOutputTokenDetails struct {
	ReasoningTokens int `json:"reasoning_tokens"`
}

func TestOpenAIPairFixturesMatchCatalogPricing(t *testing.T) {
	loadTestCatalog(t)

	fixture := loadOpenAIPairsFixture(t)
	checked := 0
	checkedNano := 0
	for _, pair := range fixture.Pairs {
		path, ok := openAIPairPath(pair.Endpoint)
		if !ok {
			continue
		}
		usage := pairUsage(t, pair)
		if usage == nil {
			continue
		}
		resolution, err := ResolveRequest(RequestInput{
			Method: "POST",
			Path:   path,
			Body:   pair.Request,
		})
		if err != nil {
			if strings.Contains(err.Error(), "Invalid JSON body") {
				continue
			}
			if pair.ExpectedCostUSDAtoms == "" {
				continue
			}
			t.Fatalf("%s: expected priced fixture to resolve: %v", pair.ID, err)
		}

		settlement := SettlementCost(resolution, usage)
		if pair.KnownPriceNanoUSD != "" && atomsToNanoUSD(settlement) != pair.KnownPriceNanoUSD {
			t.Fatalf("%s: expected external exact cost %s nanoUSD from %s, got %s nanoUSD from catalog settlement %s atoms", pair.ID, pair.KnownPriceNanoUSD, pair.KnownPriceSource, atomsToNanoUSD(settlement), settlement)
		}
		if pair.ExpectedCostUSDAtoms != "" && !pair.ExpectedHoldFloorOnly && settlement != pair.ExpectedCostUSDAtoms {
			t.Fatalf("%s: expected settlement %s, got %s", pair.ID, pair.ExpectedCostUSDAtoms, settlement)
		}
		if compareDecimalStrings(resolution.Hold.MaxUSDAtoms, settlement) < 0 {
			t.Fatalf("%s: hold %s is below settlement %s", pair.ID, resolution.Hold.MaxUSDAtoms, settlement)
		}
		checked++
		if resolution.Deployment.ID == "gpt-5-nano" {
			checkedNano++
		}
	}
	if checked == 0 {
		t.Fatalf("expected at least one OpenAI fixture to be checked")
	}
	if checkedNano == 0 {
		t.Fatalf("expected at least one gpt-5-nano OpenAI fixture to be checked")
	}
}

func loadOpenAIPairsFixture(t *testing.T) openAIPairsFixture {
	t.Helper()
	path := findRepoFile(t, filepath.Join("apps", "tests", "fixtures", "openai-pairs.json"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var fixture openAIPairsFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return fixture
}

func findRepoFile(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	for range 10 {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
		if filepath.Base(dir) == "apps" {
			path = filepath.Join(dir, "..", name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	t.Fatalf("could not find %s from test working directory", name)
	return ""
}

func openAIPairPath(endpoint string) (string, bool) {
	switch strings.TrimSpace(endpoint) {
	case "POST /v1/chat/completions", "POST /v1/chat/completions (stream)":
		return "/v1/chat/completions", true
	case "POST /v1/responses", "POST /v1/responses (stream)":
		return "/v1/responses", true
	default:
		return "", false
	}
}

func pairUsage(t *testing.T, pair openAIPairFixture) *schemas.BifrostLLMUsage {
	t.Helper()
	raw := pair.Response
	if len(pair.StreamFrames) > 0 {
		raw = nil
		for _, frame := range pair.StreamFrames {
			if usageFromRaw(frame) != nil {
				raw = frame
			}
		}
	}
	if len(pair.StreamEvents) > 0 {
		raw = nil
		for _, event := range pair.StreamEvents {
			if usageFromRaw(event) != nil {
				raw = event
			}
		}
	}
	usage := usageFromRaw(raw)
	if usage == nil {
		return nil
	}
	if strings.Contains(pair.Endpoint, "/v1/responses") {
		return usage.responses()
	}
	return usage.chat()
}

func usageFromRaw(raw json.RawMessage) *openAIUsage {
	if len(raw) == 0 {
		return nil
	}
	var envelope openAIUsageEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil
	}
	if envelope.Usage != nil {
		return envelope.Usage
	}
	if envelope.Response != nil && envelope.Response.Usage != nil {
		return envelope.Response.Usage
	}
	return nil
}

func (usage *openAIUsage) chat() *schemas.BifrostLLMUsage {
	if usage == nil {
		return nil
	}
	cachedTokens := cachedInputTokens(usage.PromptTokensDetails)
	return &schemas.BifrostLLMUsage{
		PromptTokens:     usage.PromptTokens,
		CompletionTokens: usage.CompletionTokens,
		TotalTokens:      usage.TotalTokens,
		PromptTokensDetails: &schemas.ChatPromptTokensDetails{
			CachedReadTokens: cachedTokens,
		},
	}
}

func (usage *openAIUsage) responses() *schemas.BifrostLLMUsage {
	if usage == nil {
		return nil
	}
	cachedTokens := cachedInputTokens(usage.InputTokensDetails)
	return &schemas.BifrostLLMUsage{
		PromptTokens:     usage.InputTokens,
		CompletionTokens: usage.OutputTokens,
		TotalTokens:      usage.TotalTokens,
		PromptTokensDetails: &schemas.ChatPromptTokensDetails{
			CachedReadTokens: cachedTokens,
		},
	}
}

func cachedInputTokens(details *openAITokenUsageDetails) int {
	if details == nil {
		return 0
	}
	if details.CachedReadTokens > 0 {
		return details.CachedReadTokens
	}
	return details.CachedTokens
}

func compareDecimalStrings(left string, right string) int {
	leftValue, ok := new(big.Int).SetString(left, 10)
	if !ok {
		leftValue = big.NewInt(0)
	}
	rightValue, ok := new(big.Int).SetString(right, 10)
	if !ok {
		rightValue = big.NewInt(0)
	}
	return leftValue.Cmp(rightValue)
}

func atomsToNanoUSD(atoms string) string {
	value, ok := new(big.Int).SetString(atoms, 10)
	if !ok {
		return "0"
	}
	value.Div(value, big.NewInt(1000000000))
	return value.String()
}
