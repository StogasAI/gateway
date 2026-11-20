package stogas

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

// replyRedactionFor returns the redaction of a reply to a request that held the text, under a
// redaction that restores email addresses and one that replaces phone numbers in responses.
func replyRedactionFor(t *testing.T, action redaction.Action, requestText string) *ReplyRedaction {
	t.Helper()
	return replyRedactionOf(t, requestText, redaction.Options{Patterns: []redaction.Pattern{redaction.PatternPhoneNumber}, Parts: redaction.PartsOf(redaction.PartResponse), Action: action})
}

// replyRedactionOf returns the redaction of a reply to a request that held the text, under a
// redaction that restores email addresses and the others given.
func replyRedactionOf(t *testing.T, requestText string, others ...redaction.Options) *ReplyRedaction {
	t.Helper()
	compile := func(options redaction.Options) *redaction.Policy {
		policy, err := redaction.CompilePolicy(options)
		if err != nil {
			t.Fatal(err)
		}
		return policy
	}
	policies := []*redaction.Policy{compile(redaction.Options{Patterns: []redaction.Pattern{redaction.PatternEmailAddress}, Action: redaction.ActionRestore})}
	for _, options := range others {
		policies = append(policies, compile(options))
	}
	policy, err := redaction.CombinePolicies(policies)
	if err != nil {
		t.Fatal(err)
	}
	request := redaction.NewWithPolicy(policy)
	encoded, _ := json.Marshal(requestText)
	fields := map[string]json.RawMessage{"messages": json.RawMessage(`[{"role":"user","content":` + string(encoded) + `}]`)}
	if err := request.RedactRequestFields(fields, redaction.SurfaceChat, nil); err != nil {
		t.Fatal(err)
	}
	return &ReplyRedaction{state: &State{}, redactor: redaction.NewReply(policy, request.Restorer())}
}

func chatDelta(choice int, delta schemas.ChatStreamResponseChoiceDelta) *schemas.BifrostStreamChunk {
	return &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{
		Index: choice, ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &delta},
	}}}}
}

func toolDelta(index uint16, arguments string) schemas.ChatStreamResponseChoiceDelta {
	return schemas.ChatStreamResponseChoiceDelta{ToolCalls: []schemas.ChatAssistantMessageToolCall{{Index: index, Function: schemas.ChatAssistantMessageToolCallFunction{Arguments: arguments}}}}
}

// A value that spans chunks is changed whole: the first delta of its text gets the text and
// the later ones get none. A text without a match keeps its deltas.
func TestReplyRedactionChangesAStreamedChatReply(t *testing.T) {
	t.Parallel()
	reply := replyRedactionFor(t, redaction.ActionReplace, "I am a@corp.io")
	chunks := []*schemas.BifrostStreamChunk{
		chatDelta(0, schemas.ChatStreamResponseChoiceDelta{Role: schemas.Ptr("assistant"), Content: schemas.Ptr("Call +44 20 ")}),
		chatDelta(1, schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("Second ")}),
		chatDelta(0, schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("7123 4567 or <EMAIL_ADD")}),
		chatDelta(1, schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("choice")}),
		chatDelta(0, schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("RESS_1>.")}),
		chatDelta(0, toolDelta(0, `{"to":"<EMAIL_`)),
		chatDelta(0, toolDelta(1, `{"n":1}`)),
		chatDelta(0, toolDelta(0, `ADDRESS_1>"}`)),
		chatDelta(0, schemas.ChatStreamResponseChoiceDelta{Reasoning: schemas.Ptr("+44 20 7123 4567"), ReasoningDetails: []schemas.ChatReasoningDetails{
			{Index: 0, Text: schemas.Ptr("+44 20 7123 4567")}, {Index: 1, Text: schemas.Ptr("+44 20 7123 4567")},
		}}),
		chatDelta(0, schemas.ChatStreamResponseChoiceDelta{ReasoningDetails: []schemas.ChatReasoningDetails{{Index: 0, Signature: schemas.Ptr("sig")}}}),
	}
	if err := reply.Stream(chunks); err != nil {
		t.Fatal(err)
	}
	delta := func(i int) *schemas.ChatStreamResponseChoiceDelta {
		return chunks[i].BifrostChatResponse.Choices[0].Delta
	}
	for i, want := range map[int]string{0: "Call <PHONE_NUMBER> or a@corp.io.", 1: "Second ", 2: "", 3: "choice", 4: ""} {
		if got := *delta(i).Content; got != want {
			t.Errorf("content %d = %q, want %q", i, got, want)
		}
	}
	for i, want := range map[int]string{5: `{"to":"a@corp.io"}`, 6: `{"n":1}`, 7: ""} {
		if got := delta(i).ToolCalls[0].Function.Arguments; got != want {
			t.Errorf("arguments %d = %q, want %q", i, got, want)
		}
	}
	// The signed detail and the reasoning text of its message stay, and the unsigned detail
	// is text like any other.
	details := delta(8).ReasoningDetails
	if *delta(8).Reasoning != "+44 20 7123 4567" || *details[0].Text != "+44 20 7123 4567" || *details[1].Text != "<PHONE_NUMBER>" {
		t.Errorf("reasoning=%q details=%q %q", *delta(8).Reasoning, *details[0].Text, *details[1].Text)
	}
	if metrics := reply.state.PluginMetrics.Redaction; metrics == nil || metrics.ResponseItemsRedacted != 2 || metrics.ItemsRestored != 2 {
		t.Errorf("metrics=%+v", metrics)
	}
}

func responsesDelta(eventType schemas.ResponsesStreamResponseType, output, content int, delta string) *schemas.BifrostStreamChunk {
	return &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
		Type: eventType, OutputIndex: &output, ContentIndex: &content, Delta: &delta,
	}}
}

func TestReplyRedactionChangesAStreamedResponsesReply(t *testing.T) {
	t.Parallel()
	reply := replyRedactionFor(t, redaction.ActionReplace, "I am a@corp.io")
	reasoning := schemas.ResponsesMessageTypeReasoning
	sealedIndex := 0
	chunks := []*schemas.BifrostStreamChunk{
		responsesDelta(schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta, 0, 0, "+44 20 7123 4567"),
		responsesDelta(schemas.ResponsesStreamResponseTypeOutputTextDelta, 1, 0, "Call +44 20 7123"),
		responsesDelta(schemas.ResponsesStreamResponseTypeOutputTextDelta, 1, 1, "other part 4567"),
		responsesDelta(schemas.ResponsesStreamResponseTypeOutputTextDelta, 1, 0, " 4567 <EMAIL_ADDRESS_1>"),
		responsesDelta(schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta, 2, 0, `{"to":"<EMAIL_ADDRESS`),
		responsesDelta(schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta, 2, 0, `_1>"}`),
		{BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeOutputItemDone, OutputIndex: &sealedIndex,
			Item: &schemas.ResponsesMessage{Type: &reasoning, ResponsesReasoning: &schemas.ResponsesReasoning{EncryptedContent: schemas.Ptr("abc")}},
		}},
	}
	err := reply.Stream(chunks)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"+44 20 7123 4567", "Call <PHONE_NUMBER> a@corp.io", "other part 4567", "", `{"to":"a@corp.io"}`, ""} {
		if got := *chunks[i].BifrostResponsesStreamResponse.Delta; got != want {
			t.Errorf("delta %d = %q, want %q", i, got, want)
		}
	}
	// The events of the encrypted reasoning item stay, and the text of a finished part
	// changes as its deltas did.
	done := func(output int, text string) (*schemas.BifrostResponsesStreamResponse, []byte) {
		event := &schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputTextDone, OutputIndex: &output, Text: &text}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		return event, encoded
	}
	event, encoded := done(0, "+44 20 7123 4567")
	if out, err := reply.Event(event, encoded); err != nil || string(out) != string(encoded) {
		t.Errorf("sealed event=%s err=%v", out, err)
	}
	event, encoded = done(1, "Call +44 20 7123 4567 <EMAIL_ADDRESS_1>")
	if out, err := reply.Event(event, encoded); err != nil || !strings.Contains(string(out), `"text":"Call <PHONE_NUMBER> a@corp.io"`) {
		t.Errorf("event=%s err=%v", out, err)
	}
	if out, err := reply.Event(chunks[1].BifrostResponsesStreamResponse, []byte(`{"delta":"+44 20 7123 4567"}`)); err != nil || string(out) != `{"delta":"+44 20 7123 4567"}` {
		t.Errorf("a delta was read twice: %s err=%v", out, err)
	}
	// The stream repeats the texts in the response that ends it, and the record counts them
	// once.
	completed := &schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeCompleted}
	whole := []byte(`{"type":"response.completed","response":{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Call +44 20 7123 4567 <EMAIL_ADDRESS_1>"}]},{"type":"function_call","arguments":"{\"to\":\"<EMAIL_ADDRESS_1>\"}"}]}}`)
	if out, err := reply.Event(completed, whole); err != nil || !strings.Contains(string(out), `Call <PHONE_NUMBER> a@corp.io`) {
		t.Errorf("completed=%s err=%v", out, err)
	}
	if metrics := reply.state.PluginMetrics.Redaction; metrics == nil || metrics.ResponseItemsRedacted != 1 || metrics.ItemsRestored != 2 {
		t.Errorf("metrics=%+v", metrics)
	}
}

func TestReplyRedactionRefusesAStreamedReply(t *testing.T) {
	t.Parallel()
	reply := replyRedactionFor(t, redaction.ActionRefuse, "hello")
	chunks := []*schemas.BifrostStreamChunk{
		chatDelta(0, schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("Call +44 20 ")}),
		chatDelta(0, schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("7123 4567")}),
	}
	err := reply.Stream(chunks)
	var refused *redaction.RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("err=%v", err)
	}
	failure := ReplyRedactionError(err)
	if *failure.StatusCode != 400 || *failure.Error.Code != "redaction_refused" || failure.Error.Message != "Policy refuses a response that matches <PHONE_NUMBER>" {
		t.Fatalf("failure=%+v %+v", failure, failure.Error)
	}
}

// A reply that only gets values back streams as it arrives. A chunk waits only while its text
// ends in what may become a placeholder, and reasoning keeps its placeholders, since its
// signature can arrive after its text.
func TestReplyRedactionStreamsAReplyThatOnlyRestores(t *testing.T) {
	t.Parallel()
	reply := replyRedactionOf(t, "I am a@corp.io")
	type step struct {
		chunk *schemas.BifrostStreamChunk
		holds bool
	}
	finish := "stop"
	ended := chatDelta(0, schemas.ChatStreamResponseChoiceDelta{})
	ended.BifrostChatResponse.Choices[0].FinishReason = &finish
	steps := []step{
		{chatDelta(0, schemas.ChatStreamResponseChoiceDelta{Reasoning: schemas.Ptr("think <EMAIL_ADDRESS_1> and <EMAIL")}), false},
		{chatDelta(0, schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("Mail ")}), false},
		{chatDelta(0, schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("a < b and <EMAIL")}), true},
		{chatDelta(1, schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("other choice")}), true},
		{chatDelta(0, schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("_ADDRESS_1> now")}), false},
		{chatDelta(0, toolDelta(0, `{"to":"<`)), true},
		{chatDelta(0, toolDelta(0, `EMAIL_ADDRESS_1>"}`)), false},
		{chatDelta(0, schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("ends in <")}), true},
		{ended, false},
	}
	var held []*schemas.BifrostStreamChunk
	var windows [][]*schemas.BifrostStreamChunk
	for index, step := range steps {
		held = append(held, step.chunk)
		holds := reply.Holds([]*schemas.BifrostStreamChunk{step.chunk})
		if holds != step.holds {
			t.Errorf("step %d holds=%t, want %t", index, holds, step.holds)
		}
		if !holds {
			if err := reply.Stream(held); err != nil {
				t.Fatal(err)
			}
			windows, held = append(windows, held), nil
		}
	}
	delta := func(index int) *schemas.ChatStreamResponseChoiceDelta {
		return steps[index].chunk.BifrostChatResponse.Choices[0].Delta
	}
	if got := *delta(0).Reasoning; got != "think <EMAIL_ADDRESS_1> and <EMAIL" {
		t.Errorf("reasoning = %q", got)
	}
	for index, want := range map[int]string{1: "Mail ", 2: "a < b and a@corp.io now", 3: "other choice", 4: "", 7: "ends in <"} {
		if got := *delta(index).Content; got != want {
			t.Errorf("content %d = %q, want %q", index, got, want)
		}
	}
	if first, rest := delta(5).ToolCalls[0].Function.Arguments, delta(6).ToolCalls[0].Function.Arguments; first != `{"to":"a@corp.io"}` || rest != "" {
		t.Errorf("arguments = %q %q", first, rest)
	}
	if len(windows) != 5 {
		t.Errorf("windows = %d, want 5", len(windows))
	}
	if metrics := reply.state.PluginMetrics.Redaction; metrics == nil || metrics.ItemsRestored != 2 {
		t.Errorf("metrics=%+v", metrics)
	}
	// A Responses reasoning event and a reasoning item keep their placeholders too.
	text := "see <EMAIL_ADDRESS_1>"
	event := &schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone, Text: &text}
	encoded, _ := json.Marshal(event)
	if out, err := reply.Event(event, encoded); err != nil || !strings.Contains(string(out), `"text":"see <EMAIL_ADDRESS_1>"`) {
		t.Errorf("reasoning event=%s err=%v", out, err)
	}
	item := []byte(`{"type":"response.output_item.done","item":{"summary":[{"type":"summary_text","text":"see <EMAIL_ADDRESS_1>"}],"type":"reasoning"}}`)
	if out, err := reply.Event(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemDone}, item); err != nil || string(out) != string(item) {
		t.Errorf("reasoning item=%s err=%v", out, err)
	}
}
