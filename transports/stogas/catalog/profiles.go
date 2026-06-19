package catalog

import "fmt"

type PolicyProfileDescription struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Denies  []string `json:"denies,omitempty"`
	Allows  []string `json:"allows,omitempty"`
}

type policyProfile struct {
	description PolicyProfileDescription
	parameters  map[string]compiledParameter
}

var policyProfiles = map[string]policyProfile{
	"openai.chat.output_tokens.min_16": {
		description: PolicyProfileDescription{ID: "openai.chat.output_tokens.min_16", Summary: "Rejects Chat Completions output-token caps below 16."},
		parameters: map[string]compiledParameter{
			"max_tokens":            minParameter(16),
			"max_completion_tokens": minParameter(16),
		},
	},
	"openai.responses.output_tokens.min_16": {
		description: PolicyProfileDescription{ID: "openai.responses.output_tokens.min_16", Summary: "Rejects Responses output-token caps below 16."},
		parameters: map[string]compiledParameter{
			"max_output_tokens": minParameter(16),
		},
	},
	"openai.chat.text_only_mvp": {
		description: PolicyProfileDescription{
			ID:      "openai.chat.text_only_mvp",
			Summary: "Allows text Chat Completions input and rejects Stogas-unbilled file, image, and audio input blocks.",
			Denies:  []string{"messages[].content[type=file]", "messages[].content[type=image_url]", "messages[].content[type=input_audio]"},
		},
		parameters: map[string]compiledParameter{
			"messages": {Reject: []compiledRejectRule{
				{Path: "$[].content[][type=file]", Exists: true},
				{Path: "$[].content[][type=image_url]", Exists: true},
				{Path: "$[].content[][type=input_audio]", Exists: true},
			}},
		},
	},
	"openai.responses.text_only_mvp": {
		description: PolicyProfileDescription{
			ID:      "openai.responses.text_only_mvp",
			Summary: "Allows text and inline file data on Responses, and rejects upstream file IDs plus image/audio input blocks.",
			Denies:  []string{"input_file.file_id", "input_image", "input_audio"},
			Allows:  []string{"input_file.file_data"},
		},
		parameters: map[string]compiledParameter{
			"input": {Reject: []compiledRejectRule{
				{Path: "$[][type=input_file].file_id", Exists: true},
				{Path: "$[].content[][type=input_file].file_id", Exists: true},
				{Path: "$[][type=input_image]", Exists: true},
				{Path: "$[].content[][type=input_image]", Exists: true},
				{Path: "$[][type=input_audio]", Exists: true},
				{Path: "$[].content[][type=input_audio]", Exists: true},
			}},
		},
	},
	"openai.chat.no_hosted_tools": {
		description: PolicyProfileDescription{
			ID:      "openai.chat.no_hosted_tools",
			Summary: "Rejects OpenAI hosted tools on Chat Completions; Chat web search is exposed only through search-model deployments.",
			Denies:  []string{"image_generation", "computer-use-preview", "computer_use_preview", "file_search", "code_interpreter", "web_search", "web_search_preview", "hosted shell containers"},
		},
		parameters: map[string]compiledParameter{"tools": openAIHostedToolsPolicy([]string{"web_search", "web_search_preview"})},
	},
	"openai.responses.no_unbilled_hosted_tools": {
		description: PolicyProfileDescription{
			ID:      "openai.responses.no_unbilled_hosted_tools",
			Summary: "Rejects unbilled OpenAI hosted tools on Responses while allowing priced web-search tools.",
			Denies:  []string{"image_generation", "computer-use-preview", "computer_use_preview", "file_search", "code_interpreter", "hosted shell containers"},
			Allows:  []string{"web_search", "web_search_preview"},
		},
		parameters: map[string]compiledParameter{"tools": openAIHostedToolsPolicy(nil)},
	},
	"openai.service_tier.enforce_deployment_tier": {
		description: PolicyProfileDescription{ID: "openai.service_tier.enforce_deployment_tier", Summary: "Tiered deployment slugs imply their provider service tier and reject conflicting explicit tiers."},
	},
	"openai.chat.search_model.web_search_options": {
		description: PolicyProfileDescription{ID: "openai.chat.search_model.web_search_options", Summary: "Allows web_search_options on Chat search-model deployments and prices a guaranteed search call."},
		parameters:  map[string]compiledParameter{"web_search_options": {Type: "object"}},
	},
}

func minParameter(value float64) compiledParameter {
	return compiledParameter{Min: &value}
}

func openAIHostedToolsPolicy(extraPrefixes []string) compiledParameter {
	prefixes := append([]string{
		"image_generation",
		"computer-use-preview",
		"computer_use_preview",
		"file_search",
		"code_interpreter",
	}, extraPrefixes...)
	return compiledParameter{Reject: []compiledRejectRule{
		{Path: "$[].type", Prefixes: prefixes},
		{Path: "$[][type=shell]", AllowedKeys: []string{"type", "environment"}, RequiredKeys: []string{"type", "environment"}},
		{Path: "$[][type=shell].environment", AllowedKeys: []string{"type"}, RequiredKeys: []string{"type"}},
		{Path: "$[][type=shell].environment.type", Missing: true, ValuesExcept: []any{"local"}},
	}}
}

func profileDescriptions() []PolicyProfileDescription {
	descriptions := make([]PolicyProfileDescription, 0, len(policyProfiles))
	for _, profile := range policyProfiles {
		descriptions = append(descriptions, profile.description)
	}
	return descriptions
}

func combinedProfileIDs(groups ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, ids := range groups {
		for _, id := range ids {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return stableStrings(out)
}

func profileParameterPolicies(profileIDs []string) (map[string]compiledParameter, error) {
	out := map[string]compiledParameter{}
	for _, id := range profileIDs {
		profile, ok := policyProfiles[id]
		if !ok {
			return nil, fmt.Errorf("unknown policy profile %q", id)
		}
		mergeParameterPolicies(out, profile.parameters)
	}
	return out, nil
}
