package openai

import "github.com/maximhq/bifrost/transports/stogas/providers"

func Profiles() []providers.Profile {
	return []providers.Profile{
		{
			Description: providers.ProfileDescription{ID: "openai.chat.output_tokens.min_16", Summary: "Rejects Chat Completions output-token caps below 16."},
		},
		{
			Description: providers.ProfileDescription{ID: "openai.responses.output_tokens.min_16", Summary: "Rejects Responses output-token caps below 16."},
		},
		{
			Description: providers.ProfileDescription{
				ID:      "openai.chat.text_only_mvp",
				Summary: "Allows text Chat Completions input and rejects Stogas-unbilled file, image, and audio input blocks.",
				Denies:  []string{"messages[].content[type=file]", "messages[].content[type=image_url]", "messages[].content[type=input_audio]"},
			},
		},
		{
			Description: providers.ProfileDescription{
				ID:      "openai.responses.text_only_mvp",
				Summary: "Allows text and inline file data on Responses, and rejects upstream file IDs plus image/audio input blocks.",
				Denies:  []string{"input_file.file_id", "input_image", "input_audio"},
				Allows:  []string{"input_file.file_data"},
			},
		},
		{
			Description: providers.ProfileDescription{
				ID:      "openai.chat.no_hosted_tools",
				Summary: "Rejects OpenAI hosted tools on Chat Completions; Chat web search is exposed only through search-model deployments.",
				Denies:  []string{"image_generation", "computer-use-preview", "computer_use_preview", "file_search", "code_interpreter", "web_search", "web_search_preview", "hosted shell containers"},
			},
		},
		{
			Description: providers.ProfileDescription{
				ID:      "openai.responses.no_unbilled_hosted_tools",
				Summary: "Rejects unbilled OpenAI hosted tools on Responses while allowing priced web-search tools.",
				Denies:  []string{"image_generation", "computer-use-preview", "computer_use_preview", "file_search", "code_interpreter", "hosted shell containers"},
				Allows:  []string{"web_search", "web_search_preview"},
			},
		},
		{
			Description: providers.ProfileDescription{ID: "openai.service_tier.enforce_deployment_tier", Summary: "Tiered deployment slugs imply their provider service tier and reject conflicting explicit tiers."},
		},
		{
			Description: providers.ProfileDescription{ID: "openai.chat.search_model.web_search_options", Summary: "Allows web_search_options on Chat search-model deployments and prices a guaranteed search call."},
		},
	}
}
