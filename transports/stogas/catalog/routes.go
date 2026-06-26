package catalog

import "strings"

type routeSpec struct {
	Method      string
	Path        string
	Headers     []string
	AuthHeaders []string
	Parameters  []string
}

var routeSpecs = map[Route]routeSpec{
	RouteChat: {
		Method: "POST",
		Path:   "/v1/chat/completions",
		Headers: []string{
			"authorization",
			"api-key",
			"x-api-key",
			"x-goog-api-key",
			"content-type",
			"accept",
			"x-stogas-return-extra-fields",
		},
		AuthHeaders: []string{"authorization", "api-key", "x-api-key", "x-goog-api-key"},
		Parameters: []string{
			"model",
			"messages",
			"audio",
			"cache_control",
			"container",
			"context_management",
			"fallbacks",
			"stream",
			"frequency_penalty",
			"function_call",
			"functions",
			"inference_geo",
			"logit_bias",
			"logprobs",
			"max_tokens",
			"max_completion_tokens",
			"mcp_servers",
			"metadata",
			"modalities",
			"n",
			"parallel_tool_calls",
			"prediction",
			"presence_penalty",
			"prompt_cache_key",
			"prompt_cache_isolation_key",
			"prompt_cache_retention",
			"provider",
			"reasoning",
			"reasoning_effort",
			"reasoning_max_tokens",
			"reasoning_display",
			"response_format",
			"safety_identifier",
			"seed",
			"service_tier",
			"stream_options",
			"stop",
			"store",
			"task_budget",
			"temperature",
			"tool_choice",
			"tools",
			"web_search_options",
			"top_logprobs",
			"top_p",
			"user",
			"verbosity",
		},
	},
	RouteResponses: {
		Method: "POST",
		Path:   "/v1/responses",
		Headers: []string{
			"authorization",
			"api-key",
			"x-api-key",
			"x-goog-api-key",
			"content-type",
			"accept",
			"x-stogas-return-extra-fields",
		},
		AuthHeaders: []string{"authorization", "api-key", "x-api-key", "x-goog-api-key"},
		Parameters: []string{
			"model",
			"input",
			"stream",
			"background",
			"cache_control",
			"container",
			"context_management",
			"conversation",
			"include",
			"instructions",
			"max_output_tokens",
			"max_tool_calls",
			"metadata",
			"mcp_servers",
			"parallel_tool_calls",
			"previous_response_id",
			"prompt_cache_key",
			"reasoning",
			"safety_identifier",
			"service_tier",
			"provider",
			"stream_options",
			"store",
			"temperature",
			"text",
			"top_logprobs",
			"top_p",
			"tool_choice",
			"tools",
			"truncation",
			"task_budget",
			"user",
			"frequency_penalty",
			"presence_penalty",
			"prompt_cache_retention",
			"reasoning.effort",
		},
	},
}

var routeByPath = func() map[string]Route {
	routes := make(map[string]Route, len(routeSpecs))
	for route, spec := range routeSpecs {
		routes[spec.Path] = route
	}
	return routes
}()

var (
	allClientHeaderNamesValue = buildAllClientHeaders()
	allClientHeadersValue     = strings.Join(allClientHeaderNamesValue, ", ")
)

func specForRoute(route Route) (routeSpec, bool) {
	spec, ok := routeSpecs[route]
	return spec, ok
}

func parameterSet(route Route) map[string]bool {
	spec, ok := specForRoute(route)
	if !ok {
		return nil
	}
	fields := make(map[string]bool, len(spec.Parameters))
	for _, name := range spec.Parameters {
		fields[name] = true
	}
	return fields
}

func buildAllClientHeaders() []string {
	seen := map[string]bool{}
	names := []string{}
	for _, spec := range routeSpecs {
		for _, name := range spec.Headers {
			normalized := strings.ToLower(strings.TrimSpace(name))
			if normalized == "" || seen[normalized] {
				continue
			}
			seen[normalized] = true
			names = append(names, normalized)
		}
	}
	return stableHeaderOrder(names)
}
