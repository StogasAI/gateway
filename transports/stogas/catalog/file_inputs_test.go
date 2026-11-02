package catalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// The first deployment in the order is the one that cannot read the part, and the policy allows
// one pair, so a request reaches the second deployment only where routing skips the first.
func TestRoutingSkipsDeploymentsThatCannotReadTheAttachments(t *testing.T) {
	const (
		pdf   = `"data:application/pdf;base64,JVBERi0xLjcK"`
		text  = `"data:text/plain;base64,aGVsbG8="`
		image = `"data:image/png;base64,iVBORw0KGgo="`
	)
	chatFile := func(data string) string {
		return `{"type":"file","file":{"filename":"a","file_data":` + data + `}}`
	}
	responsesFile := func(data string) string {
		return `{"type":"input_file","filename":"a","file_data":` + data + `}`
	}
	gpt := []string{"azure-gpt-5.6-sol", "openai-gpt-5.6-sol"}
	claude := []string{"aws-claude-fable-5-1", "aws-claude-fable-5-1-anthropic-hosted"}
	for _, tc := range []struct {
		name, model, path, part, want, wantErr string
		order                                  []string
		// textOnly leaves the first deployment text only, and audio gives the second audio.
		textOnly, audio, extract bool
	}{
		{name: "chat text", part: `{"type":"text","text":"hello"}`, want: gpt[0]},
		{name: "chat PDF", part: chatFile(pdf), want: gpt[1]},
		{name: "chat image", part: `{"type":"image_url","image_url":{"url":` + image + `}}`, want: gpt[0]},
		{name: "chat image without the modality", part: `{"type":"image_url","image_url":{"url":` + image + `}}`, want: gpt[1], textOnly: true},
		{name: "chat audio", part: `{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}`, want: gpt[1], textOnly: true, audio: true},
		{name: "chat audio that no candidate reads", part: `{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}`, wantErr: "messages[0].content[1] audio input is not supported by the selected deployment", textOnly: true},
		{name: "chat file URL", part: `{"type":"file","file":{"file_url":"https://example.com/a.pdf"}}`, wantErr: "messages[0].content[1] file URLs require Responses or an Anthropic-format deployment"},
		{name: "responses PDF", path: "/v1/responses", part: responsesFile(pdf), want: gpt[0]},
		{name: "responses text file", path: "/v1/responses", part: responsesFile(text), want: gpt[1]},
		{name: "responses text file with extraction", path: "/v1/responses", part: responsesFile(text), want: gpt[0], extract: true},
		{name: "responses image without the modality", path: "/v1/responses", part: `{"type":"input_image","image_url":` + image + `}`, want: gpt[1], textOnly: true},
		{name: "two sources go to the checks", path: "/v1/responses", part: `{"type":"input_file","file_data":` + text + `,"file_url":"https://example.com/a.txt"}`, wantErr: "exactly one"},
		{name: "image URL where AWS runs Claude", model: "claude-fable-5-1", order: claude, part: `{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}`, want: claude[1]},
		{name: "inline image where AWS runs Claude", model: "claude-fable-5-1", order: claude, part: `{"type":"image_url","image_url":{"url":` + image + `}}`, want: claude[0]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := loadTestCatalog(t)
			model, order, path := tc.model, tc.order, tc.path
			if model == "" {
				model, order = "gpt-5.6-sol", gpt
			}
			if path == "" {
				path = "/v1/chat/completions"
			}
			setModalities := func(id string, modalities ...string) {
				deployment := snap.graph.Deployments[id]
				for routeID, route := range deployment.Routes {
					route.InputModalities = modalities
					deployment.Routes[routeID] = route
				}
			}
			if tc.textOnly {
				setModalities(order[0], "text")
			}
			if tc.audio {
				setModalities(order[1], "text", "image", "audio")
			}
			config := policyConfig(1)
			config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: order}
			config.Routing.Order = order
			if tc.extract {
				extract := true
				config.Plugins = &policy.Plugins{TextExtraction: &extract}
			}
			messages := `"messages":[{"role":"user","content":[{"type":"text","text":"read this"},` + tc.part + `]}]`
			if path == "/v1/responses" {
				messages = `"input":[{"role":"user","content":[{"type":"input_text","text":"read this"},` + tc.part + `]}]`
			}
			var checked []schemas.ModelProvider
			resolved, err := ResolveRequest(RequestInput{
				Body: []byte(`{"model":"` + model + `",` + messages + `}`), Method: "POST", Path: path, Policy: config,
				CheckCandidate: func(provider schemas.ModelProvider, _ int, _ Deployment) error {
					checked = append(checked, provider)
					return nil
				},
			})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || PublicError(err).StatusCode != 400 {
					t.Fatalf("want an error with %q: resolved=%v error=%v", tc.wantErr, resolved, err)
				}
				return
			}
			if err != nil || resolved.Deployment.ID != tc.want || len(checked) != 1 {
				t.Fatalf("want %s: resolved=%v checked=%v error=%v", tc.want, resolved, checked, err)
			}
		})
	}
}

// Where no candidate can read a part, routing refuses the request before it prepares a
// credential, with the error of a candidate's checks.
func TestRoutingRefusesAnAttachmentThatNoCandidateCanRead(t *testing.T) {
	snap := loadTestCatalog(t)
	route := snap.graph.Routes["openai-chat-completions"]
	route.DocumentFormats = DocumentFormats{MediaTypes: []string{"text/plain"}, Extensions: []string{".txt"}}
	snap.graph.Routes["openai-chat-completions"] = route
	config := policyConfig(3)
	config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{"azure-gpt-5.6-sol", "openai-gpt-5.6-sol"}}
	checks := 0
	_, err := ResolveRequest(RequestInput{
		Body:   []byte(`{"model":"gpt-5.6-sol","messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"file","file":{"file_data":"data:application/pdf;base64,JVBERi0xLjcK"}}]}]}`),
		Method: "POST", Path: "/v1/chat/completions", Policy: config,
		CheckCandidate: func(schemas.ModelProvider, int, Deployment) error { checks++; return nil },
	})
	public := PublicError(err)
	if public.StatusCode != 400 || checks != 0 || !strings.HasPrefix(public.Message, "messages[0].content[1] native file") {
		t.Fatalf("the request was not refused before credential preparation: %v, %d", err, checks)
	}
}

func TestAttachmentStringReadsADataURLOnlyThroughItsHeader(t *testing.T) {
	payload := strings.Repeat("QUJD", 4096)
	backslash := string(rune(92))
	for _, tc := range []struct {
		name, raw, want string
		ok              bool
	}{
		{"absent", ``, "", true},
		{"null", `null`, "", true},
		{"short", `"data:application/pdf;base64,JVBE"`, "data:application/pdf;base64,JVBE", true},
		{"long data URL", `"data:application/pdf;base64,` + payload + `"`, "data:application/pdf;base64,", true},
		{"escaped slash", `"data:application\/pdf;base64,` + payload + `"`, "data:application/pdf;base64,", true},
		{"raw base64", `"` + payload + `"`, payload[:attachmentHeadBytes-1], true},
		{"escape without a comma", `"` + backslash + "u0041" + payload + `"`, "A" + payload, true},
		{"whitespace", `"   "`, "", false},
		{"number", `12`, "", false},
	} {
		got, ok := attachmentString(json.RawMessage(tc.raw), true)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("%s: got %d bytes, %.40q, %t", tc.name, len(got), got, ok)
		}
	}
}
