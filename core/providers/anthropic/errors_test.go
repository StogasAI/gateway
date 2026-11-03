package anthropic

import (
	"testing"

	"github.com/valyala/fasthttp"
)

// Anthropic's monthly spend cap shares rate_limit_error with a rate limit, and only its
// error_code tells them apart, so the parser keeps it as the error's code.
func TestParseAnthropicErrorKeepsTheErrorCode(t *testing.T) {
	for _, test := range []struct {
		body string
		code string
	}{
		{`{"type":"error","error":{"type":"rate_limit_error","message":"You have reached your API usage limits: your organization has crossed its monthly API usage threshold, set based on your organization's API tier. You will regain access on 2026-12-01 at 00:00 UTC.","details":{"error_code":"enforced_spend_limit_reached"}},"request_id":"req_1"}`, "enforced_spend_limit_reached"},
		{`{"type":"error","error":{"type":"rate_limit_error","message":"Number of request tokens has exceeded your per-minute rate limit"},"request_id":"req_2"}`, ""},
	} {
		resp := fasthttp.AcquireResponse()
		resp.SetStatusCode(fasthttp.StatusTooManyRequests)
		resp.Header.SetContentType("application/json")
		resp.SetBodyString(test.body)
		err := ParseAnthropicError(resp)
		fasthttp.ReleaseResponse(resp)
		if err.Error == nil || err.Error.Type == nil || *err.Error.Type != "rate_limit_error" {
			t.Fatalf("type = %+v, want rate_limit_error", err.Error)
		}
		got := ""
		if err.Error.Code != nil {
			got = *err.Error.Code
		}
		if got != test.code {
			t.Errorf("code = %q, want %q", got, test.code)
		}
	}
}
