package redaction

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func partsPolicy(t *testing.T, options ...Options) *Policy {
	t.Helper()
	policies := make([]*Policy, len(options))
	for i, option := range options {
		policies[i] = mustCompilePolicy(t, option)
	}
	if len(policies) == 1 {
		return policies[0]
	}
	combined, err := CombinePolicies(policies)
	if err != nil {
		t.Fatal(err)
	}
	return combined
}

func redactFields(t *testing.T, policy *Policy, surface Surface, body string) (map[string]json.RawMessage, *Redactor, error) {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &fields); err != nil {
		t.Fatal(err)
	}
	redactor := NewWithPolicy(policy)
	return fields, redactor, redactor.RedactRequestFields(fields, surface, nil)
}

var emails = []Pattern{PatternEmailAddress}

func TestRequestPartsSelectWhatARedactionReads(t *testing.T) {
	t.Parallel()
	const chat = `{"messages":[
		{"role":"system","content":"sys s@corp.io"},
		{"role":"developer","content":"dev d@corp.io"},
		{"role":"user","content":[{"type":"text","text":"user u@corp.io"}]},
		{"role":"assistant","content":"model a@corp.io","tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{\"to\":\"call@corp.io\"}"}}]},
		{"role":"tool","tool_call_id":"c","content":"result r@corp.io"},
		{"role":"critic","content":"other o@corp.io"}],
		"tools":[{"type":"function","function":{"name":"f","description":"mail t@corp.io"}}],
		"prediction":{"type":"content","content":"p@corp.io"}}`
	const responses = `{"instructions":"sys s@corp.io","input":[
		{"role":"user","content":"user u@corp.io"},
		{"type":"message","role":"assistant","content":[{"type":"output_text","text":"model a@corp.io"}]},
		{"type":"function_call","call_id":"c","name":"f","arguments":"{\"to\":\"call@corp.io\"}"},
		{"type":"function_call_output","call_id":"c","output":"result r@corp.io"},
		{"type":"reasoning","summary":[{"type":"summary_text","text":"think z@corp.io"}]},
		{"type":"mcp_list_tools","id":"l","server_label":"crm","tools":[{"name":"find","description":"listed w@corp.io"}]},
		{"type":"mcp_call","id":"m","server_label":"crm","name":"find","arguments":"{\"q\":\"asked q@corp.io\"}","output":"found m@corp.io","error":null},
		{"type":"code_interpreter_call","id":"k","code":"print('code k@corp.io')","outputs":[{"type":"logs","logs":"ran x@corp.io"}]},
		{"type":"future_item","text":"other o@corp.io"}],
		"tools":[{"type":"function","name":"f","description":"mail t@corp.io"}],
		"text":{"format":{"type":"json_schema","name":"n","schema":{"description":"fmt f@corp.io"}}}}`
	cases := []struct {
		name     string
		surface  Surface
		body     string
		part     Part
		redacted []string
	}{
		{"chat system", SurfaceChat, chat, PartSystem, []string{"s@corp.io", "d@corp.io", "o@corp.io"}},
		{"chat user", SurfaceChat, chat, PartUser, []string{"u@corp.io", "p@corp.io", "o@corp.io"}},
		{"chat assistant", SurfaceChat, chat, PartAssistant, []string{"a@corp.io", "call@corp.io", "o@corp.io"}},
		{"chat tool results", SurfaceChat, chat, PartToolResults, []string{"r@corp.io", "o@corp.io"}},
		{"chat tools", SurfaceChat, chat, PartTools, []string{"t@corp.io", "o@corp.io"}},
		{"responses system", SurfaceResponses, responses, PartSystem, []string{"s@corp.io", "o@corp.io"}},
		{"responses user", SurfaceResponses, responses, PartUser, []string{"u@corp.io", "o@corp.io"}},
		{"responses assistant", SurfaceResponses, responses, PartAssistant, []string{"a@corp.io", "call@corp.io", "z@corp.io", "q@corp.io", "k@corp.io", "o@corp.io"}},
		// A call that the provider ran holds its result, which is a tool result.
		{"responses tool results", SurfaceResponses, responses, PartToolResults, []string{"r@corp.io", "w@corp.io", "m@corp.io", "x@corp.io", "o@corp.io"}},
		{"responses tools", SurfaceResponses, responses, PartTools, []string{"t@corp.io", "f@corp.io", "o@corp.io"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			policy := partsPolicy(t, Options{Patterns: emails, Parts: PartsOf(test.part)})
			fields, redactor, err := redactFields(t, policy, test.surface, test.body)
			if err != nil {
				t.Fatal(err)
			}
			out, _ := json.Marshal(fields)
			for _, email := range strings.FieldsFunc(test.body, func(r rune) bool { return !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz@.", r) }) {
				if !strings.HasSuffix(email, "@corp.io") {
					continue
				}
				want := false
				for _, redacted := range test.redacted {
					want = want || redacted == email
				}
				if got := !strings.Contains(string(out), email); got != want {
					t.Errorf("%s redacted=%t, want %t in %s", email, got, want, out)
				}
			}
			if count := int(redactor.Summary().ItemsRedacted); count != len(test.redacted) {
				t.Errorf("items=%d, want %d", count, len(test.redacted))
			}
		})
	}
}

// A message that names its role twice, or with an escaped key, is read by every redaction of
// the request, since parsers disagree on which of two keys counts.
func TestAnUnclearRoleIsReadAsEveryPart(t *testing.T) {
	t.Parallel()
	policy := partsPolicy(t, Options{Patterns: emails, Parts: PartsOf(PartUser)})
	for name, test := range map[string]struct {
		message  string
		redacted bool
	}{
		"assistant":    {`{"role":"assistant","content":"x@corp.io"}`, false},
		"duplicate":    {`{"role":"assistant","content":"x@corp.io","role":"user"}`, true},
		"reversed":     {`{"role":"user","content":"x@corp.io","role":"assistant"}`, true},
		"escaped key":  {`{"role":"user","content":"x@corp.io"}`, true},
		"escaped role": {`{"role":"user","content":"x@corp.io"}`, true},
		"both escaped": {`{"role":"assistant","role":"assistant","content":"x@corp.io"}`, true},
		"number":       {`{"role":7,"content":"x@corp.io"}`, true},
		"no role":      {`{"content":"x@corp.io"}`, true},
		"late role":    {`{"content":"x@corp.io","role":"assistant"}`, false},
	} {
		fields, _, err := redactFields(t, policy, SurfaceChat, `{"messages":[`+test.message+`]}`)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := !strings.Contains(string(fields["messages"]), "x@corp.io"); got != test.redacted {
			t.Errorf("%s: redacted=%t, want %t", name, got, test.redacted)
		}
	}
	// A Responses item with a role and the type of a call is no known item.
	fields, _, err := redactFields(t, policy, SurfaceResponses, `{"input":[{"type":"function_call","role":"assistant","arguments":"x@corp.io"}]}`)
	if err != nil || strings.Contains(string(fields["input"]), "x@corp.io") {
		t.Fatalf("mixed item stayed: %s err=%v", fields["input"], err)
	}
}

func TestTheStrictestActionWinsWherePartsOverlap(t *testing.T) {
	t.Parallel()
	policy := partsPolicy(t,
		Options{Patterns: emails, Action: ActionRestore},
		Options{Patterns: []Pattern{PatternPhoneNumber}, Parts: PartsOf(PartUser)},
		Options{CustomPatterns: []CustomPattern{{Expression: `SECRET-\d+`}}, Parts: PartsOf(PartToolResults), Action: ActionRefuse},
	)
	fields, redactor, err := redactFields(t, policy, SurfaceChat, `{"messages":[
		{"role":"system","content":"a@corp.io then b@corp.io then a@corp.io"},
		{"role":"user","content":"call +44 20 7123 4567 or b@corp.io, SECRET-1"},
		{"role":"assistant","content":"+44 20 7123 4567"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	var messages []struct{ Content string }
	if err := json.Unmarshal(fields["messages"], &messages); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"<EMAIL_ADDRESS_1> then <EMAIL_ADDRESS_2> then <EMAIL_ADDRESS_1>",
		"call <PHONE_NUMBER> or <EMAIL_ADDRESS_2>, SECRET-1",
		"+44 20 7123 4567",
	}
	for i, message := range messages {
		if message.Content != want[i] {
			t.Errorf("message %d = %q, want %q", i, message.Content, want[i])
		}
	}
	if redactor.Restorer() == nil || redactor.Summary().ItemsRedacted != 5 {
		t.Fatalf("summary=%+v restorer=%v", redactor.Summary(), redactor.Restorer())
	}

	// The same value under a replacing and a restoring redaction is replaced for good.
	both := partsPolicy(t, Options{Patterns: emails, Action: ActionRestore}, Options{Patterns: emails, Parts: PartsOf(PartUser)})
	fields, redactor, err = redactFields(t, both, SurfaceChat, `{"messages":[{"role":"user","content":"a@corp.io"},{"role":"system","content":"a@corp.io"}]}`)
	if err != nil || string(fields["messages"]) != `[{"role":"user","content":"<EMAIL_ADDRESS>"},{"role":"system","content":"<EMAIL_ADDRESS_1>"}]` {
		t.Fatalf("messages=%s err=%v", fields["messages"], err)
	}

	// A refusal names the kind of value and leaves the request as it was.
	var refused *RefusedError
	body := `{"messages":[{"role":"user","content":"a@corp.io"},{"role":"tool","tool_call_id":"c","content":"SECRET-22 a@corp.io"}]}`
	fields, redactor, err = redactFields(t, policy, SurfaceChat, body)
	if !errors.As(err, &refused) || refused.Placeholder() != "<CUSTOM_PII>" || strings.Contains(err.Error(), "SECRET-22") {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(string(fields["messages"]), "a@corp.io") || redactor.Summary().ItemsRedacted != 0 {
		t.Fatalf("a refused request changed: %s %+v", fields["messages"], redactor.Summary())
	}
}

func TestPartsAndActionsAreChecked(t *testing.T) {
	t.Parallel()
	for name, options := range map[string]Options{
		"restore reads responses": {Patterns: emails, Parts: PartsOf(PartUser, PartResponse), Action: ActionRestore},
		"unknown part":            {Patterns: emails, Parts: 1 << partCount},
		"unknown action":          {Patterns: emails, Action: actionCount},
	} {
		if _, err := CompilePolicy(options); err == nil {
			t.Errorf("%s compiled", name)
		}
	}
	policy := partsPolicy(t, Options{Patterns: emails, Parts: PartsOf(PartResponse)})
	if policy.ReadsRequest() || !policy.ReadsResponse() || policy.Restores() {
		t.Fatalf("response policy: request=%t response=%t restores=%t", policy.ReadsRequest(), policy.ReadsResponse(), policy.Restores())
	}
	fields, redactor, err := redactFields(t, policy, SurfaceChat, `{"messages":[{"role":"user","content":"a@corp.io"}]}`)
	if err != nil || !strings.Contains(string(fields["messages"]), "a@corp.io") || redactor.InputTextBytes() != len("a@corp.io") {
		t.Fatalf("a redaction of responses changed a request: %s err=%v", fields["messages"], err)
	}
	if NewReply(mustCompilePolicy(t, Options{Patterns: emails}), nil) != nil {
		t.Fatal("a redaction of requests alone changes replies")
	}
}

func TestReplyRestoresAndRedacts(t *testing.T) {
	t.Parallel()
	policy := partsPolicy(t,
		Options{Patterns: emails, CustomPatterns: []CustomPattern{{Expression: `ID-"\w+"`}}, Action: ActionRestore},
		Options{Patterns: []Pattern{PatternPhoneNumber}, Parts: PartsOf(PartResponse)},
	)
	_, request, err := redactFields(t, policy, SurfaceChat, `{"messages":[{"role":"user","content":"I am ID-\"q\" and b@corp.io"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	reply := NewReply(policy, request.Restorer())
	const chat = `{"id":"chatcmpl-<CUSTOM_PII_1>","model":"<CUSTOM_PII_1>","choices":[{"index":0,"finish_reason":"tool_calls","logprobs":{"content":[{"token":"+44 20 7123 4567"}]},
		"message":{"role":"assistant","content":"Write to <CUSTOM_PII_1>, not <EMAIL_ADDRESS_9>. Call +44 20 7123 4567.",
		"annotations":[{"type":"url_citation","url_citation":{"url":"https://x.test/+44 20 7123 4567","title":"<EMAIL_ADDRESS_1>"}}],
		"audio":{"id":"a","data":"<EMAIL_ADDRESS_1>","transcript":"<EMAIL_ADDRESS_1>"},
		"tool_calls":[{"id":"c","type":"function","function":{"name":"send","arguments":"{\"to\":\"<CUSTOM_PII_1>\",\"phone\":\"+44 20 7123 4567\"}"}}],
		"reasoning":"sealed <EMAIL_ADDRESS_1>","reasoning_details":[{"type":"reasoning.text","index":0,"text":"sealed <EMAIL_ADDRESS_1>","signature":"sig"}]}}],
		"usage":{"prompt_tokens":1}}`
	out, err := reply.RedactReply([]byte(chat), ReplyChat, nil)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		ID      string
		Model   string
		Choices []struct {
			LogProbs json.RawMessage
			Message  struct {
				Content     string
				Annotations json.RawMessage
				Audio       struct{ Data, Transcript string }
				ToolCalls   []struct{ Function struct{ Arguments string } } `json:"tool_calls"`
				Reasoning   string
			}
		}
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatalf("%v in %s", err, out)
	}
	message := response.Choices[0].Message
	if message.Content != `Write to ID-"q", not <EMAIL_ADDRESS_9>. Call <PHONE_NUMBER>.` {
		t.Errorf("content=%q", message.Content)
	}
	var arguments struct{ To, Phone string }
	if err := json.Unmarshal([]byte(message.ToolCalls[0].Function.Arguments), &arguments); err != nil || arguments.To != `ID-"q"` || arguments.Phone != "<PHONE_NUMBER>" {
		t.Errorf("arguments=%s err=%v", message.ToolCalls[0].Function.Arguments, err)
	}
	if response.ID != "chatcmpl-<CUSTOM_PII_1>" || response.Model != "<CUSTOM_PII_1>" ||
		!strings.Contains(string(response.Choices[0].LogProbs), "+44 20 7123 4567") ||
		!strings.Contains(string(message.Annotations), "+44 20 7123 4567") || !strings.Contains(string(message.Annotations), "<EMAIL_ADDRESS_1>") ||
		message.Audio.Data != "<EMAIL_ADDRESS_1>" || message.Audio.Transcript != "b@corp.io" || message.Reasoning != "sealed <EMAIL_ADDRESS_1>" {
		t.Errorf("protocol values, provider data or sealed reasoning changed: %s", out)
	}
	if summary := reply.Summary(); summary.ItemsRedacted != 2 || summary.ItemsRestored != 3 {
		t.Errorf("summary=%+v", summary)
	}

	const responses = `{"id":"resp_1","instructions":"<CUSTOM_PII_1>","output":[
		{"type":"reasoning","id":"rs_1","encrypted_content":"abc","summary":[{"type":"summary_text","text":"<CUSTOM_PII_1>"}]},
		{"type":"reasoning","id":"rs_2","summary":[{"type":"summary_text","text":"<CUSTOM_PII_1> +44 20 7123 4567"}]},
		{"type":"image_generation_call","id":"ig_1","result":"<CUSTOM_PII_1>"},
		{"type":"message","role":"assistant","content":[{"type":"output_text","text":"<EMAIL_ADDRESS_1> +44 20 7123 4567","annotations":[],"logprobs":[]}]},
		{"type":"function_call","call_id":"c","name":"send","arguments":"{\"to\":\"<CUSTOM_PII_1>\"}"}]}`
	out, err = NewReply(policy, request.Restorer()).RedactReply([]byte(responses), ReplyResponses, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.NewReplacer(
		// Reasoning gets no value back, and the response's own redaction still reads it.
		`"rs_2","summary":[{"type":"summary_text","text":"<CUSTOM_PII_1> +44 20 7123 4567"`, `"rs_2","summary":[{"type":"summary_text","text":"<CUSTOM_PII_1> <PHONE_NUMBER>"`,
		`"text":"<EMAIL_ADDRESS_1> +44 20 7123 4567"`, `"text":"b@corp.io <PHONE_NUMBER>"`,
		`"arguments":"{\"to\":\"<CUSTOM_PII_1>\"}"`, `"arguments":"{\"to\":\"ID-\\\"q\\\"\"}"`,
	).Replace(responses)
	if string(out) != want {
		t.Errorf("responses reply\n got %s\nwant %s", out, want)
	}

	event := `{"type":"response.output_text.done","item_id":"<CUSTOM_PII_1>","output_index":0,"text":"<EMAIL_ADDRESS_1>","logprobs":[]}`
	out, err = NewReply(policy, request.Restorer()).RedactReply([]byte(event), ReplyResponsesEvent, nil)
	if err != nil || string(out) != `{"type":"response.output_text.done","item_id":"<CUSTOM_PII_1>","output_index":0,"text":"b@corp.io","logprobs":[]}` {
		t.Errorf("event=%s err=%v", out, err)
	}

	text, err := NewReply(policy, request.Restorer()).RedactReplyText(`{"to":"<CUSTOM_PII_1>"} +44 20 7123 4567`, true, true, nil)
	if err != nil || text != `{"to":"ID-\"q\""} <PHONE_NUMBER>` {
		t.Errorf("text=%q err=%v", text, err)
	}
}

func TestReplyRefusesAndBoundsGrowth(t *testing.T) {
	t.Parallel()
	refusing := partsPolicy(t, Options{Patterns: emails, Parts: PartsOf(PartResponse), Action: ActionRefuse})
	var refused *RefusedError
	_, err := NewReply(refusing, nil).RedactReply([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"a@corp.io"}}]}`), ReplyChat, nil)
	if !errors.As(err, &refused) || refused.Placeholder() != "<EMAIL_ADDRESS>" {
		t.Fatalf("err=%v", err)
	}
	// Signed reasoning stays as the provider wrote it, so its text refuses nothing.
	sealed := `{"choices":[{"index":0,"message":{"role":"assistant","content":"ok","reasoning":"a@corp.io","reasoning_details":[{"type":"reasoning.text","index":0,"text":"a@corp.io","signature":"s"}]}}]}`
	if out, err := NewReply(refusing, nil).RedactReply([]byte(sealed), ReplyChat, nil); err != nil || string(out) != sealed {
		t.Fatalf("out=%s err=%v", out, err)
	}

	restoring := partsPolicy(t, Options{CustomPatterns: []CustomPattern{{Expression: `K-[a-z]+`}}, Action: ActionRestore})
	value := "K-" + strings.Repeat("a", 4000)
	_, request, err := redactFields(t, restoring, SurfaceChat, `{"messages":[{"role":"user","content":"`+value+`"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	limit := errors.New("too large")
	reserve := func(total int) error {
		if total > 10_000 {
			return limit
		}
		return nil
	}
	body := `{"choices":[{"index":0,"message":{"role":"assistant","content":"` + strings.Repeat("<CUSTOM_PII_1> ", 3) + `"}}]}`
	if _, err := NewReply(nil, request.Restorer()).RedactReply([]byte(body), ReplyChat, reserve); !errors.Is(err, limit) {
		t.Fatalf("err=%v", err)
	}
	if _, err := NewReply(nil, request.Restorer()).RedactReplyText(strings.Repeat("<CUSTOM_PII_1> ", 3), false, true, reserve); !errors.Is(err, limit) {
		t.Fatalf("text err=%v", err)
	}
}
