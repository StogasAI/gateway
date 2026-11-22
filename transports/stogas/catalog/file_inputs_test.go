package catalog

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/inputfiles"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// The first deployment in the order is the one that cannot read the part, and the policy allows
// one pair, so a request reaches the second deployment only where routing skips the first.
func TestRoutingSkipsDeploymentsThatCannotReadTheAttachments(t *testing.T) {
	const (
		pdf   = `"data:application/pdf;base64,JVBERi0xLjcK"`
		text  = `"data:text/plain;base64,aGVsbG8="`
		image = `"data:image/png;base64,iVBORw0KGgo="`

		wordType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	)
	document, err := os.ReadFile("../inputfiles/testdata/office/report.docx")
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(document)
	word := `"data:` + wordType + `;base64,` + encoded + `"`
	invoice, err := os.ReadFile("../inputfiles/testdata/pdf/invoice.pdf")
	if err != nil {
		t.Fatal(err)
	}
	readablePDF := `"data:application/pdf;base64,` + base64.StdEncoding.EncodeToString(invoice) + `"`
	off, auto, always := policy.TextExtractionOff, policy.TextExtractionAuto, policy.TextExtractionAlways
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
		textOnly, audio bool
		// extraction is the policy's text extraction, or nil for a policy that sets none.
		extraction policy.TextExtraction
	}{
		{name: "chat text", part: `{"type":"text","text":"hello"}`, want: gpt[0]},
		{name: "chat PDF", part: chatFile(pdf), want: gpt[1]},
		{name: "chat PDF with extraction where needed", part: chatFile(readablePDF), want: gpt[0], extraction: policy.TextExtraction{"pdf": auto}},
		{name: "chat PDF with Office extraction alone", part: chatFile(readablePDF), want: gpt[1], extraction: policy.TextExtraction{"office": always}},
		{name: "chat PDF whose media type is off in its family", part: chatFile(readablePDF), want: gpt[1], extraction: policy.TextExtraction{"pdf": always, "application/pdf": off}},
		{name: "chat image", part: `{"type":"image_url","image_url":{"url":` + image + `}}`, want: gpt[0]},
		{name: "chat image without the modality", part: `{"type":"image_url","image_url":{"url":` + image + `}}`, want: gpt[1], textOnly: true},
		{name: "chat audio", part: `{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}`, want: gpt[1], textOnly: true, audio: true},
		{name: "chat audio that no candidate reads", part: `{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}`, wantErr: "messages[0].content[1] audio input is not supported by any deployment that this request can use", textOnly: true},
		{name: "chat file URL", part: `{"type":"file","file":{"file_url":"https://example.com/a.pdf"}}`, wantErr: "messages[0].content[1] file URLs on Chat Completions are not supported by any deployment that this request can use; send the file in file_data or use Responses"},
		{name: "responses PDF", path: "/v1/responses", part: responsesFile(pdf), want: gpt[0]},
		{name: "responses text file", path: "/v1/responses", part: responsesFile(text), want: gpt[1]},
		{name: "responses text file with extraction off", path: "/v1/responses", part: responsesFile(text), want: gpt[1], extraction: policy.TextExtraction{"text": off}},
		{name: "responses text file with extraction where needed", path: "/v1/responses", part: responsesFile(text), want: gpt[0], extraction: policy.TextExtraction{"text": auto}},
		{name: "responses text file with extraction", path: "/v1/responses", part: responsesFile(text), want: gpt[0], extraction: policy.TextExtraction{"text": always}},
		{name: "responses Word file", path: "/v1/responses", part: responsesFile(word), want: gpt[1]},
		{name: "responses Word file with extraction where needed", path: "/v1/responses", part: responsesFile(word), want: gpt[0], extraction: policy.TextExtraction{"office": auto}},
		{name: "chat Word file", part: chatFile(word), wantErr: "messages[0].content[1] is " + wordType + ", which is not supported by openai-gpt-5.6-sol. Set plugins.textExtraction.office to auto to send it as text"},
		{name: "chat Word file with text extraction alone", part: chatFile(word), wantErr: "Set plugins.textExtraction.office to auto", extraction: policy.TextExtraction{"text": always}},
		{name: "chat Word file with extraction where needed", part: chatFile(word), want: gpt[0], extraction: policy.TextExtraction{"office": auto}},
		{name: "chat Word file with its media type extracted", part: chatFile(word), want: gpt[0], extraction: policy.TextExtraction{wordType: auto}},
		{name: "chat Word file whose media type is off in its family", part: chatFile(word), wantErr: "Set plugins.textExtraction." + wordType + " to auto", extraction: policy.TextExtraction{"office": always, wordType: off}},
		{name: "chat Word file with another media type extracted", part: chatFile(word), wantErr: "Set plugins.textExtraction.office to auto", extraction: policy.TextExtraction{"application/vnd.oasis.opendocument.text": always}},
		{name: "chat Word file named by its extension, with its media type extracted", part: `{"type":"file","file":{"filename":"a.docx","file_data":"data:application/octet-stream;base64,` + encoded + `"}}`, want: gpt[0], extraction: policy.TextExtraction{wordType: auto}},
		{name: "chat Word file named by its extension", part: `{"type":"file","file":{"filename":"a.docx","file_data":"data:application/octet-stream;base64,` + encoded + `"}}`, want: gpt[0], extraction: policy.TextExtraction{"office": auto}},
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
			config.Routing.Deployments = &policy.Lists{Allow: order}
			config.Routing.Query = orderedQuery(t, "", order...)
			if tc.extraction != nil {
				config.Plugins = &policy.Plugins{TextExtraction: tc.extraction}
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
// credential, with each reason that the candidates give and the deployments that give it.
func TestRoutingRefusesAnAttachmentThatNoCandidateCanRead(t *testing.T) {
	snap := loadTestCatalog(t)
	routes := snap.graph.Deployments["openai-gpt-5.6-sol"].Routes
	route := routes["openai-chat-completions"]
	route.DocumentFormats = DocumentFormats{MediaTypes: []string{"text/plain"}, Extensions: []string{".txt"}}
	routes["openai-chat-completions"] = route
	config := policyConfig(3)
	config.Routing.Deployments = &policy.Lists{Allow: []string{"azure-gpt-5.6-sol", "openai-gpt-5.6-sol"}}
	checks := 0
	_, err := ResolveRequest(RequestInput{
		Body:   []byte(`{"model":"gpt-5.6-sol","messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"file","file":{"file_data":"data:application/pdf;base64,JVBERi0xLjcK"}}]}]}`),
		Method: "POST", Path: "/v1/chat/completions", Policy: config,
		CheckCandidate: func(schemas.ModelProvider, int, Deployment) error { checks++; return nil },
	})
	public := PublicError(err)
	if public.StatusCode != 400 || checks != 0 || public.Message != "messages[0].content[1] documents are not supported by azure-gpt-5.6-sol. messages[0].content[1] is application/pdf, which is not supported by openai-gpt-5.6-sol. Set plugins.textExtraction.pdf to auto to send it as text" ||
		public.Code != AttachmentUnsupported || public.Param != "messages[0].content[1]" {
		t.Fatalf("the request was not refused before credential preparation: %+v, %d", public, checks)
	}
}

// Provider file IDs resolve only through a customer's own credential, and only where one such
// credential can serve the request, since a file ID names a file in one account. A Stogas
// credential leaves without using the request's one pair, even where it shares the customer
// credential's policy, and refusals come before any credential is prepared.
func TestRoutingSendsProviderFileIDsOnlyThroughCustomerCredentials(t *testing.T) {
	// Stogas serves this deployment with its own account too, so its credentials reach it.
	loadTestCatalog(t).graph.Deployments["openai-gpt-5.6-sol"].StogasManaged = true
	const (
		part   = "input[0].content[1]"
		shared = part + " is a provider file ID, which only the credential of the account that holds the file can read, and this request can use "
	)
	for _, tc := range []struct {
		name, model string
		// credentials are the key's credentials by provider, and byok marks the customer's own.
		credentials map[string][]int
		byok        map[string][]bool
		want        int
		wantErr     string
	}{
		{name: "a customer credential after a Stogas one", model: "openai-gpt-5.6-sol", credentials: map[string][]int{"openai": {0, 1}},
			byok: map[string][]bool{"openai": {false, true}}, want: 1},
		{name: "Stogas credentials only", model: "openai-gpt-5.6-sol", credentials: map[string][]int{"openai": {0, 1}},
			byok: map[string][]bool{"openai": {false, false}}, wantErr: part + " is a provider file ID, which only a BYOK credential can read"},
		{name: "two customer credentials of a provider", model: "openai-gpt-5.6-sol", credentials: map[string][]int{"openai": {0, 1}},
			byok: map[string][]bool{"openai": {true, true}}, wantErr: shared + "2 credentials; use a key with one credential for this model"},
		{name: "customer credentials of two providers", model: "gpt-5.6-sol", credentials: map[string][]int{"azure": {0}, "openai": {0, 1}},
			byok:    map[string][]bool{"azure": {true}, "openai": {true, true}},
			wantErr: shared + "3 credentials; name the provider in the model, such as provider:azure, or use a key with one credential for this model"},
		{name: "a provider named in the model", model: "provider:azure gpt-5.6-sol", credentials: map[string][]int{"azure": {0}, "openai": {0, 1}},
			byok: map[string][]bool{"azure": {true}, "openai": {true, true}}, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := policyConfig(1)
			var checked []int
			resolved, err := ResolveRequest(RequestInput{
				Body:   []byte(`{"model":"` + tc.model + `","input":[{"role":"user","content":[{"type":"input_text","text":"read this"},{"type":"input_file","file_id":"file-abc"}]}]}`),
				Method: "POST", Path: "/v1/responses", Policy: config, AvailableCredentials: tc.credentials,
				CredentialKind: func(provider schemas.ModelProvider, index int) string {
					if tc.byok[string(provider)][index] {
						return CredentialStored
					}
					return CredentialManaged
				},
				CheckCandidate: func(_ schemas.ModelProvider, index int, _ Deployment) error {
					checked = append(checked, index)
					return nil
				},
			})
			if tc.wantErr == "" {
				if err != nil || resolved.CredentialIndex != tc.want || len(checked) != 1 {
					t.Fatalf("want credential %d: resolved=%v checked=%v error=%v", tc.want, resolved, checked, err)
				}
				return
			}
			public := PublicError(err)
			if public.StatusCode != 400 || public.Code != AttachmentUnsupported || public.Param != part || public.Message != tc.wantErr || len(checked) != 0 {
				t.Fatalf("want a refusal before any credential is prepared: %+v, checked=%v", public, checked)
			}
		})
	}
}

// A deny period removes only a pair that could otherwise serve the request, so a client that waits
// for the period to end is not refused for another reason then.
func TestRoutingDeniesOnlyPairsThatReadTheAttachments(t *testing.T) {
	loadTestCatalog(t)
	const week = `[{"days":["mon","tue","wed","thu","fri","sat","sun"],"start":"00:00","end":"24:00","timeZone":"UTC"}]`
	for _, tc := range []struct{ name, input, code string }{
		{"a pair that reads the attachment", `{}`, "schedule_denied"},
		{"a pair whose policy cannot check the attachment", `{"asciiOnly":true}`, AttachmentUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, err := policy.CompileSource([]byte(`{"input":` + tc.input + `,"rules":{"closed":{"when":"provider.id == 'openai'","access":{"schedule":{"deny":` + week + `}}}}}`))
			if err != nil {
				t.Fatal(err)
			}
			config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ResolveRequest(RequestInput{
				Body:   []byte(`{"model":"openai-gpt-5.6-sol","messages":[{"role":"user","content":[{"type":"text","text":"read this"},{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,JVBERi0xLjcK"}}]}]}`),
				Method: "POST", Path: "/v1/chat/completions", Policy: config,
			})
			if code := PublicError(err).Code; code != tc.code {
				t.Fatalf("want %s: %v", tc.code, err)
			}
		})
	}
}

// An attachment stays opaque where text extraction does not turn it into prompt text, and a
// policy that inspects input refuses an opaque attachment. Routing skips a pair with such a
// policy as it skips a deployment that cannot read the attachment.
func TestRoutingSkipsPairsWhosePolicyRefusesOpaqueAttachments(t *testing.T) {
	loadTestCatalog(t)
	gpt := []string{"azure-gpt-5.6-sol", "openai-gpt-5.6-sol"}
	const (
		pdf  = `{"type":"input_file","filename":"a.pdf","file_data":"data:application/pdf;base64,JVBERi0xLjcK"}`
		text = `{"type":"input_file","filename":"a.txt","file_data":"data:text/plain;base64,aGVsbG8="}`
	)
	document, err := os.ReadFile("../inputfiles/testdata/office/report.docx")
	if err != nil {
		t.Fatal(err)
	}
	word := `{"type":"input_file","filename":"a.docx","file_data":"data:application/octet-stream;base64,` + base64.StdEncoding.EncodeToString(document) + `"}`
	type setting func(*policy.Config)
	asciiOnly := func(config *policy.Config) { config.Input = &policy.Input{ASCIIOnly: true} }
	redaction := func(config *policy.Config) {
		config.Plugins = &policy.Plugins{Redaction: &policy.Redaction{Presets: []string{"ip_address"}}}
	}
	extraction := func(text, office string) setting {
		return func(config *policy.Config) {
			if config.Plugins == nil {
				config.Plugins = &policy.Plugins{}
			}
			config.Plugins.TextExtraction = policy.TextExtraction{}
			if text != "" {
				config.Plugins.TextExtraction["text"] = text
			}
			if office != "" {
				config.Plugins.TextExtraction["office"] = office
			}
		}
	}
	for _, tc := range []struct {
		name, part, want, wantErr string
		azure, openai             []setting
	}{
		{name: "input limited to ASCII", part: pdf, azure: []setting{asciiOnly}, want: gpt[1]},
		{name: "redaction", part: pdf, azure: []setting{redaction}, want: gpt[1]},
		{name: "inspection on every pair", part: pdf, azure: []setting{asciiOnly}, openai: []setting{redaction},
			wantErr: "input[0].content[1] is an attachment, which input.asciiOnly cannot check. input[0].content[1] is an attachment, which plugins.redaction cannot check. Set plugins.textExtraction.pdf to auto to send it as text"},
		{name: "an extracted text file", part: text, azure: []setting{asciiOnly, extraction("always", "")}, want: gpt[0]},
		{name: "a text file extracted where inspection needs it", part: text, azure: []setting{asciiOnly, extraction("auto", "")}, openai: []setting{redaction}, want: gpt[0]},
		{name: "a Word file extracted where inspection needs it", part: word, azure: []setting{asciiOnly}, openai: []setting{redaction, extraction("", "auto")}, want: gpt[1]},
		{name: "a Word file that no pair extracts", part: word, azure: []setting{asciiOnly, extraction("auto", "")}, openai: []setting{redaction, extraction("", "off")},
			wantErr: "input[0].content[1] has no media type, and its filename extension is not supported by azure-gpt-5.6-sol. input[0].content[1] is an attachment, which plugins.redaction cannot check. Set plugins.textExtraction.office to auto to send it as text"},
		{name: "a text file that no pair extracts", part: text, azure: []setting{asciiOnly}, openai: []setting{redaction, extraction("off", "auto")},
			wantErr: "input[0].content[1] is text/plain, which is not supported by azure-gpt-5.6-sol. input[0].content[1] is an attachment, which plugins.redaction cannot check. Set plugins.textExtraction.text to auto to send it as text"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configure := func(settings []setting) *policy.Config {
				config := policyConfig(1)
				config.Routing.Deployments = &policy.Lists{Allow: gpt}
				config.Routing.Query = orderedQuery(t, "", gpt...)
				for _, set := range settings {
					set(config)
				}
				return config
			}
			azure, openai := configure(tc.azure), configure(tc.openai)
			resolved, err := ResolveRequest(RequestInput{
				Body:   []byte(`{"model":"gpt-5.6-sol","input":[{"role":"user","content":[{"type":"input_text","text":"read this"},` + tc.part + `]}]}`),
				Method: "POST", Path: "/v1/responses", Policy: configure(nil),
				CredentialPolicy: func(provider schemas.ModelProvider, _ int) (RequestPolicy, error) {
					if provider == ProviderAzure {
						return RequestPolicy{Config: azure}, nil
					}
					return RequestPolicy{Config: openai}, nil
				},
			})
			if tc.wantErr != "" {
				public := PublicError(err)
				if public.StatusCode != 400 || public.Code != AttachmentUnsupported || public.Message != tc.wantErr {
					t.Fatalf("want %q: %+v", tc.wantErr, public)
				}
				return
			}
			if err != nil || resolved.Deployment.ID != tc.want {
				t.Fatalf("want %s: resolved=%v error=%v", tc.want, resolved, err)
			}
		})
	}
}

// A policy's input.mediaTypes refuse attachments by the type that their part and the start of
// their content show. Routing skips a pair whose policy refuses one, and a type that the gateway
// cannot check is refused wherever it could decide.
func TestRoutingSkipsPairsWhosePolicyRefusesMediaTypes(t *testing.T) {
	loadTestCatalog(t)
	gpt := []string{"azure-gpt-5.6-sol", "openai-gpt-5.6-sol"}
	const (
		pdf     = `{"type":"input_file","filename":"a.pdf","file_data":"data:application/pdf;base64,JVBERi0xLjcK"}`
		fakePDF = `{"type":"input_file","filename":"a.txt","file_data":"data:text/plain;base64,JVBERi0xLjcK"}`
		text    = `{"type":"input_file","filename":"a.txt","file_data":"data:text/plain;base64,aGVsbG8="}`
		linked  = `{"type":"input_file","file_url":"https://example.com/a.pdf"}`
		image   = `{"type":"input_image","image_url":"https://example.com/a.png"}`
	)
	types := func(allow, deny []string) *policy.Input {
		return &policy.Input{MediaTypes: &policy.MediaTypes{Allow: allow, Deny: deny}}
	}
	for _, tc := range []struct {
		name, part, want, wantErr string
		azure, openai             *policy.Input
	}{
		{name: "one pair denies", part: pdf, azure: types(nil, []string{"application/pdf"}), want: gpt[1]},
		{name: "one pair allows other types", part: pdf, azure: types([]string{"image/*"}, nil), want: gpt[1]},
		{name: "every pair denies", part: pdf, azure: types(nil, []string{"application/*"}), openai: types(nil, []string{"application/pdf"}),
			wantErr: "input[0].content[1] is application/pdf, which input.mediaTypes refuses"},
		{name: "a declared type that the content contradicts", part: fakePDF, azure: types(nil, []string{"application/pdf"}), openai: types(nil, []string{"application/pdf"}),
			wantErr: "input[0].content[1] declares text/plain, but its content is application/pdf"},
		{name: "a URL that a deny list could cover", part: linked, azure: types(nil, []string{"audio/*"}), openai: types(nil, []string{"audio/*"}),
			wantErr: "input[0].content[1] has no media type that input.mediaTypes can check; send it inline with its media type"},
		{name: "an image URL that a class allows", part: image, azure: types([]string{"image/*"}, nil), want: gpt[0]},
		{name: "an image URL that a deny list of other classes leaves", part: image, azure: types(nil, []string{"audio/*"}), want: gpt[0]},
		{name: "an image URL that a type could deny", part: image, azure: types(nil, []string{"image/gif"}), want: gpt[1]},
		{name: "a refused text file gets no extraction hint", part: text, azure: types(nil, []string{"text/*"}), openai: types(nil, []string{"text/plain"}),
			wantErr: "input[0].content[1] is text/plain, which input.mediaTypes refuses"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configure := func(input *policy.Input) *policy.Config {
				config := policyConfig(1)
				config.Routing.Deployments = &policy.Lists{Allow: gpt}
				config.Routing.Query = orderedQuery(t, "", gpt...)
				config.Input = input
				return config
			}
			azure, openai := configure(tc.azure), configure(tc.openai)
			resolved, err := ResolveRequest(RequestInput{
				Body:   []byte(`{"model":"gpt-5.6-sol","input":[{"role":"user","content":[{"type":"input_text","text":"read this"},` + tc.part + `]}]}`),
				Method: "POST", Path: "/v1/responses", Policy: configure(nil),
				CredentialPolicy: func(provider schemas.ModelProvider, _ int) (RequestPolicy, error) {
					if provider == ProviderAzure {
						return RequestPolicy{Config: azure}, nil
					}
					return RequestPolicy{Config: openai}, nil
				},
			})
			if tc.wantErr != "" {
				public := PublicError(err)
				if public.StatusCode != 400 || public.Code != AttachmentUnsupported || public.Message != tc.wantErr {
					t.Fatalf("want %q: %+v", tc.wantErr, public)
				}
				return
			}
			if err != nil || resolved.Deployment.ID != tc.want {
				t.Fatalf("want %s: resolved=%v error=%v", tc.want, resolved, err)
			}
		})
	}
}

// Routing reads a data URL's header and the start of its payload, however the JSON escapes it,
// so that it sniffs the bytes that the request's preparation sniffs.
func TestStringHeadKeepsTheBytesThatSniffingReads(t *testing.T) {
	payload := strings.Repeat("ab/c", 400)
	escaped := strings.ReplaceAll(payload, "/", `\/`)
	for _, raw := range []string{`"data:text/plain;base64,` + escaped + `"`, `"` + escaped + `"`} {
		var head string
		if err := json.Unmarshal(stringHead(json.RawMessage(raw)), &head); err != nil {
			t.Fatal(err)
		}
		_, got, _ := strings.Cut(head, ",")
		if !strings.HasPrefix(raw, `"data:`) {
			got = head
		}
		if len(got) < inputfiles.SniffChars || !strings.HasPrefix(payload, got) {
			t.Fatalf("head keeps %d characters", len(got))
		}
	}
}

// Each attachment has a deployment that reads it, but none reads both, so the refusal names the
// attachments to send apart.
func TestRoutingNamesAttachmentsThatNoDeploymentReadsTogether(t *testing.T) {
	snap := loadTestCatalog(t)
	gpt := []string{"azure-gpt-5.6-sol", "openai-gpt-5.6-sol"}
	for id, modalities := range map[string][]string{gpt[0]: {"text", "image"}, gpt[1]: {"text", "audio"}} {
		deployment := snap.graph.Deployments[id]
		for routeID, route := range deployment.Routes {
			route.InputModalities = modalities
			deployment.Routes[routeID] = route
		}
	}
	config := policyConfig(2)
	config.Routing.Deployments = &policy.Lists{Allow: gpt}
	_, err := ResolveRequest(RequestInput{
		Body: []byte(`{"model":"gpt-5.6-sol","messages":[{"role":"user","content":[{"type":"text","text":"x"},` +
			`{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}},` +
			`{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`),
		Method: "POST", Path: "/v1/chat/completions", Policy: config,
	})
	public := PublicError(err)
	const want = "messages[0].content[1], messages[0].content[2] are not supported together by any deployment that this request can use; send them in separate requests"
	if public.StatusCode != 400 || public.Code != AttachmentUnsupported || public.Param != "messages[0].content[1]" || public.Message != want {
		t.Fatalf("want %q: %+v", want, public)
	}
}

// A pair that leaves for another reason reports that reason only where its deployment reads the
// attachments, since fixing the reason serves the request only there.
func TestRoutingReportsTheErrorOfAPairThatCouldReadTheAttachments(t *testing.T) {
	disabled := APIError{StatusCode: 403, Code: "credential_disabled", Type: "permission_error", Message: "The credential is disabled"}
	for _, tc := range []struct {
		name     string
		audio    bool
		wantCode string
	}{
		{"the deployment reads the attachment", true, disabled.Code},
		{"no deployment reads the attachment", false, AttachmentUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := loadTestCatalog(t)
			gpt := []string{"azure-gpt-5.6-sol", "openai-gpt-5.6-sol"}
			modalities := map[string][]string{gpt[0]: {"text"}, gpt[1]: {"text"}}
			if tc.audio {
				modalities[gpt[1]] = []string{"text", "audio"}
			}
			for id, values := range modalities {
				deployment := snap.graph.Deployments[id]
				for routeID, route := range deployment.Routes {
					route.InputModalities = values
					deployment.Routes[routeID] = route
				}
			}
			config := policyConfig(2)
			config.Routing.Deployments = &policy.Lists{Allow: gpt}
			_, err := ResolveRequest(RequestInput{
				Body:   []byte(`{"model":"gpt-5.6-sol","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`),
				Method: "POST", Path: "/v1/chat/completions", Policy: config,
				CredentialPolicy: func(provider schemas.ModelProvider, _ int) (RequestPolicy, error) {
					if provider == ProviderAzure {
						return RequestPolicy{Config: config}, nil
					}
					return RequestPolicy{}, disabled
				},
			})
			if code := PublicError(err).Code; code != tc.wantCode {
				t.Fatalf("want %s: %v", tc.wantCode, err)
			}
		})
	}
}

// Routing reads a long value only in part: a data URL's header and as much of its payload as
// content sniffing reads, and as much of another value.
func TestAttachmentStringReadsTheStartOfALongValue(t *testing.T) {
	payload := strings.Repeat("QUJD", 4096)
	backslash := string(rune(92))
	for _, tc := range []struct {
		name, raw, want string
		ok              bool
	}{
		{"absent", ``, "", true},
		{"null", `null`, "", false},
		{"short", `"data:application/pdf;base64,JVBE"`, "data:application/pdf;base64,JVBE", true},
		{"long data URL", `"data:application/pdf;base64,` + payload + `"`, "data:application/pdf;base64," + payload[:attachmentHeadBytes], true},
		{"escaped slash", `"data:application\/pdf;base64,` + payload + `"`, "data:application/pdf;base64," + payload[:attachmentHeadBytes], true},
		{"raw base64", `"` + payload + `"`, payload[:attachmentHeadBytes-1], true},
		{"escape without a comma", `"` + backslash + "u0041" + payload + `"`, "A" + payload[:attachmentHeadBytes-7], true},
		{"long data URL header", `"data:text/plain;name=` + strings.Repeat("a", 2*attachmentHeadBytes) + `;base64,` + payload + `"`, "data:text/plain;name=" + strings.Repeat("a", 2*attachmentHeadBytes) + ";base64," + payload[:attachmentHeadBytes], true},
		{"escaped slashes in raw base64", `"` + strings.Repeat("QUJ"+backslash+"/", 2*attachmentHeadBytes) + `"`, strings.Repeat("QUJ/", (attachmentHeadBytes-1)/5) + "QUJ", true},
		{"short escape at the cut", `"` + strings.Repeat("A", attachmentHeadBytes-2) + backslash + "/" + payload + `"`, strings.Repeat("A", attachmentHeadBytes-2), true},
		{"unicode escape at the cut", `"` + strings.Repeat("A", attachmentHeadBytes-4) + backslash + "u0041" + payload + `"`, strings.Repeat("A", attachmentHeadBytes-4), true},
		{"two-byte character at the cut", `"` + strings.Repeat("A", attachmentHeadBytes-2) + "é" + payload + `"`, strings.Repeat("A", attachmentHeadBytes-2), true},
		{"three-byte character at the cut", `"` + strings.Repeat("A", attachmentHeadBytes-3) + "€" + payload + `"`, strings.Repeat("A", attachmentHeadBytes-3), true},
		{"whitespace", `"   "`, "", false},
		{"number", `12`, "", false},
	} {
		got, ok := attachmentString(json.RawMessage(tc.raw), true)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("%s: got %d bytes, %.40q, %t", tc.name, len(got), got, ok)
		}
	}
}
