package stogas

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

// A result host as a browser visits it: a domain in the form filters list, an
// address, which no filter names, or nothing a browser would open.
type resultHost struct {
	url, domain string
	address     bool
}

var resultHosts = []resultHost{
	{url: "https://example.com/a", domain: "example.com"},
	{url: "https://docs.example.com/a", domain: "docs.example.com"},
	{url: "https://blocked.example.com/a", domain: "blocked.example.com"},
	{url: "https://deep.blocked.example.com/a", domain: "deep.blocked.example.com"},
	{url: "https://notexample.com/a", domain: "notexample.com"},
	{url: "https://example.com.other.test/a", domain: "example.com.other.test"},
	{url: "https://other.test/a", domain: "other.test"},
	{url: "https://a_b.example.com/a", domain: "a_b.example.com"},
	// Spellings that open the same site as a listed domain.
	{url: "https://BLOCKED.Example.COM/a", domain: "blocked.example.com"},
	{url: "https://blocked.example.com./a", domain: "blocked.example.com"},
	{url: "http://blocked.example.com:8443/a", domain: "blocked.example.com"},
	{url: "https://blocked。example。com/a", domain: "blocked.example.com"},
	{url: "https://ｂｌｏｃｋｅｄ.example.com/a", domain: "blocked.example.com"},
	{url: "https://bl­ocked.example.com/a", domain: "blocked.example.com"},
	{url: "https://blocked​.example.com/a", domain: "blocked.example.com"},
	{url: "https://bücher.example/a", domain: "xn--bcher-kva.example"},
	{url: "https://www.BÜCHER.example/a", domain: "www.xn--bcher-kva.example"},
	{url: "https://xn--bcher-kva.example/a", domain: "xn--bcher-kva.example"},
	{url: "https://b%C3%BCcher.example/a", domain: "xn--bcher-kva.example"},
	// Addresses, in the forms browsers read as one.
	{url: "https://127.0.0.1/a", address: true},
	{url: "https://2130706433/a", address: true},
	{url: "https://0x7f.1/a", address: true},
	{url: "https://[::1]/a", address: true},
	// Hosts a browser would not open.
	{url: "https://xn--zz.example/a"},
	{url: "https://a..example.com/a"},
	{url: "https://blocked%2Eexample.com/a"},
	{url: "https://blocked.example.com\\@other.test/a"},
}

var resultFilters = []struct {
	name             string
	allowed, blocked []string
}{
	{name: "allowed", allowed: []string{"example.com"}},
	{name: "blocked", blocked: []string{"blocked.example.com"}},
	{name: "both", allowed: []string{"example.com"}, blocked: []string{"blocked.example.com"}},
	{name: "several", allowed: []string{"example.com", "xn--bcher-kva.example"}, blocked: []string{"docs.example.com"}},
	{name: "blocked IDN", blocked: []string{"xn--bcher-kva.example", "other.test"}},
}

// The documented rule: a blocked domain or subdomain never passes, and an allow
// list admits only its domains and their subdomains.
func referenceResultAllowed(host resultHost, allowed, blocked []string) bool {
	under := func(domains []string) bool {
		for _, domain := range domains {
			if host.domain == domain || strings.HasSuffix(host.domain, "."+domain) {
				return true
			}
		}
		return false
	}
	switch {
	case host.address:
		return len(allowed) == 0
	case host.domain == "":
		return false
	default:
		return !under(blocked) && (len(allowed) == 0 || under(allowed))
	}
}

func filtersJSON(allowed, blocked []string) string {
	quoted := func(domains []string) string {
		return `["` + strings.Join(domains, `","`) + `"]`
	}
	parts := []string{}
	if len(allowed) > 0 {
		parts = append(parts, `"allowed_domains":`+quoted(allowed))
	}
	if len(blocked) > 0 {
		parts = append(parts, `"blocked_domains":`+quoted(blocked))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Every place a hosted tool reports a URL applies the request's domain filters
// to the host a browser would open, however the provider spells it.
func TestHostedToolResultURLsFollowDomainFiltersHoweverTheHostIsSpelled(t *testing.T) {
	webSearch := func(state *State, target string) bool {
		response := validUnaryResponsesProviderResponse("resp_filters")
		response.Output = []schemas.ResponsesMessage{providerWebSearchOutputItem("ws_filters", target)}
		return validateProviderResponsesResponse(state, response) == nil
	}
	searchAction := func(kind string) func(*State, string) bool {
		return func(state *State, target string) bool {
			action := &schemas.ResponsesWebSearchToolCallAction{Type: kind, URL: &target}
			if kind == "find_in_page" {
				action.Pattern = schemas.Ptr("term")
			}
			return validProviderWebSearchAction(state, &schemas.ResponsesToolMessageActionStruct{ResponsesWebSearchToolCallAction: action})
		}
	}
	citation := func(state *State, target string) bool {
		annotation := &schemas.ResponsesOutputMessageContentTextAnnotation{
			Type: "url_citation", URL: &target, Title: schemas.Ptr("Source"), StartIndex: schemas.Ptr(0), EndIndex: schemas.Ptr(4),
		}
		err := validateProviderResponsesAnnotation(state, annotation)
		if err != nil && !errors.Is(err, ErrProviderResponseMalformed) {
			t.Fatalf("citation error = %v, want malformed provider response", err)
		}
		return err == nil
	}
	fetchAction := func(state *State, target string) bool {
		return validProviderWebFetchAction(state, &schemas.ResponsesToolMessageActionStruct{
			ResponsesWebFetchToolCallAction: &schemas.ResponsesWebFetchToolCallAction{Type: "fetch", URL: target},
		})
	}
	fetchResult := func(state *State, target string) bool {
		return validProviderWebFetchResult(state, &schemas.ResponsesWebFetchCall{
			ResultType: "web_fetch_result", URL: &target,
			Document: &schemas.ResponsesWebFetchDocument{
				Type:   "document",
				Source: &schemas.ResponsesWebFetchSource{Type: "text", MediaType: schemas.Ptr("text/plain"), Data: schemas.Ptr("page")},
			},
		})
	}
	locations := []struct {
		name, tool string
		check      func(*State, string) bool
	}{
		{"OpenAI web search source", `{"type":"web_search","filters":%s}`, webSearch},
		{"OpenAI open_page", `{"type":"web_search","filters":%s}`, searchAction("open_page")},
		{"OpenAI find_in_page", `{"type":"web_search","filters":%s}`, searchAction("find_in_page")},
		{"OpenAI citation", `{"type":"web_search","filters":%s}`, citation},
		{"Anthropic web search source", `{"type":"web_search_20250305","name":"web_search","filters":%s}`, webSearch},
		{"Anthropic citation", `{"type":"web_search_20250305","name":"web_search","filters":%s}`, citation},
		{"Anthropic web fetch", `{"type":"web_fetch_20250910","name":"web_fetch","filters":%s}`, fetchAction},
		{"Anthropic web fetch result", `{"type":"web_fetch_20250910","name":"web_fetch","filters":%s}`, fetchResult},
	}
	for _, location := range locations {
		model := "openai/gpt-5.5"
		if strings.HasPrefix(location.name, "Anthropic") {
			model = "anthropic-claude-sonnet-4-6"
		}
		for _, filter := range resultFilters {
			tool := fmt.Sprintf(location.tool, filtersJSON(filter.allowed, filter.blocked))
			state := resolvedResponseValidationState(t, `{"model":"`+model+`","input":"hi","tools":[`+tool+`]}`)
			for _, host := range resultHosts {
				want := referenceResultAllowed(host, filter.allowed, filter.blocked)
				if got := location.check(state, host.url); got != want {
					t.Errorf("%s with %s filters: %q allowed = %v, want %v", location.name, filter.name, host.url, got, want)
				}
			}
		}
		// Without filters, any web address the tool reports passes.
		state := resolvedResponseValidationState(t, `{"model":"`+model+`","input":"hi","tools":[`+strings.Replace(location.tool, `,"filters":%s`, "", 1)+`]}`)
		for _, host := range resultHosts {
			if host.domain != "" || host.address {
				if !location.check(state, host.url) {
					t.Errorf("%s without filters rejected %q", location.name, host.url)
				}
			}
		}
	}
}
