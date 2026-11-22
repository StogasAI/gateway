package stogas

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog/catalogtest"
)

// googleMuse names the catalog deployment of each Muse model that the recordings of Meta's
// Responses API on Agent Platform call, in the order in which the recordings send each model's
// conversation on to the next.
var googleMuse = []struct{ model, deployment string }{
	{"muse-ember-1.0", "google-cloud-muse-ember-1.0"},
	{"muse-spark-1.3", "google-cloud-muse-spark-1.3"},
	{"muse-wonder-1.0", "google-cloud-muse-wonder-1.0"},
}

// museDeployment returns the catalog deployment of a recorded Muse model.
func museDeployment(t *testing.T, model string) string {
	t.Helper()
	for _, muse := range googleMuse {
		if muse.model == model {
			return muse.deployment
		}
	}
	t.Fatalf("no catalog deployment for %q", model)
	return ""
}

// museClientRequest turns a recorded request to Agent Platform into a client's Responses request
// for the catalog deployment of its model, without what the gateway sets itself: store false, the
// encrypted reasoning that it asks for and the reasoning summary that it leaves out.
func museClientRequest(t *testing.T, recorded providerExchange) string {
	t.Helper()
	request := map[string]json.RawMessage{}
	var model string
	if err := json.Unmarshal(recorded.Request.Body, &request); err != nil || json.Unmarshal(request["model"], &model) != nil {
		t.Fatalf("%s: decode request: %v", recorded.Name, err)
	}
	request["model"], _ = json.Marshal(museDeployment(t, model))
	if string(request["store"]) == "false" {
		delete(request, "store")
	}
	if string(request["include"]) == `["reasoning.encrypted_content"]` {
		delete(request, "include")
	}
	if reasoning, set := request["reasoning"]; set {
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(reasoning, &fields); err != nil {
			t.Fatal(err)
		}
		if string(fields["summary"]) == "null" {
			delete(fields, "summary")
		}
		request["reasoning"], _ = json.Marshal(fields)
	}
	body, _ := json.Marshal(request)
	return string(body)
}

// museSent prepares a client's Responses or Chat Completions request for a Muse deployment, with
// the customer's own credential that every request to one uses, and returns the body that Agent
// Platform receives and the prepared request.
func museSent(t *testing.T, path, client string) ([]byte, *schemas.BifrostResponsesRequest) {
	t.Helper()
	state, err := resolveGoogleState(t, path, client)
	if err != nil {
		t.Fatal(err)
	}
	_, state.PreparedCredential = customerOpenAICredential(t)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, state.Resolution.WireRequestType())
	request, err := state.Resolution.ToBifrost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatal(err)
	}
	if request.ResponsesRequest == nil {
		t.Fatal("the gateway sends a Muse deployment no Responses request")
	}
	return preparedProviderBody(t, ctx, request.ResponsesRequest), request.ResponsesRequest
}

// museSendsAsTaken checks that the gateway sends a client's form of a recorded request as Google
// took it.
func museSendsAsTaken(t *testing.T, recorded providerExchange) {
	t.Helper()
	if sent, _ := museSent(t, "/v1/responses", museClientRequest(t, recorded)); !sameJSON(t, sent, recorded.Request.Body) {
		t.Fatalf("sent %s, Google took %s", sent, recorded.Request.Body)
	}
}

// museReasoning returns the encrypted reasoning of a reply, or an empty string.
func museReasoning(reply *schemas.BifrostResponsesResponse) string {
	for _, item := range reply.Output {
		if item.ResponsesReasoning != nil && item.ResponsesReasoning.EncryptedContent != nil {
			return *item.ResponsesReasoning.EncryptedContent
		}
	}
	return ""
}

// museCalls returns the names of the function calls of a reply.
func museCalls(reply *schemas.BifrostResponsesResponse) []string {
	var names []string
	for _, item := range reply.Output {
		if item.Type != nil && *item.Type == schemas.ResponsesMessageTypeFunctionCall && item.ResponsesToolMessage != nil && item.ResponsesToolMessage.Name != nil {
			names = append(names, *item.ResponsesToolMessage.Name)
		}
	}
	return names
}

// museRefusal is a recorded refusal as the client gets it: its status and Google's message.
func museRefusal(t *testing.T, recorded providerExchange) (string, string) {
	t.Helper()
	refusal := openaiprovider.ParseOpenAIError(recorded.errorReply(t))
	if refusal == nil || refusal.Error == nil {
		t.Fatalf("%s: no error in %s", recorded.Name, recorded.Response.Body)
	}
	return billing.NormalizeUpstreamStatus(refusal), refusal.Error.Message
}

// TestMuseReasonsAtTheEffortsThatGoogleTakes prepares a request at each effort for each Muse model
// on Agent Platform (capture google-cloud/responses-reasoning). Each body that the gateway sends
// equals one that Google answered with reasoning. An effort that the deployment lists goes out as
// it is, and the models always reason, so none goes out as the lowest effort and max as the
// highest that Google offers the model. A request without an effort goes out without one.
func TestMuseReasonsAtTheEffortsThatGoogleTakes(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "google-cloud/responses-reasoning")
	for _, muse := range googleMuse {
		for _, effort := range []string{"unset", "none", "minimal", "low", "medium", "high", "xhigh", "max"} {
			t.Run(muse.model+" "+effort, func(t *testing.T) {
				client := `{"model":"` + muse.deployment + `","input":[{"role":"user","content":"Say OK."}],"max_output_tokens":2000`
				if effort != "unset" {
					client += `,"reasoning":{"effort":"` + effort + `"}`
				}
				sent, _ := museSent(t, "/v1/responses", client+`}`)
				var took *providerExchange
				for name, candidate := range recorded {
					if strings.HasPrefix(name, muse.model+" ") && sameJSON(t, sent, candidate.Request.Body) {
						took = &candidate
						break
					}
				}
				if took == nil || took.Response.Status != http.StatusOK || museReasoning(took.responsesReply(t)) == "" {
					t.Fatalf("sent %s, which Google answered with reasoning in no recorded exchange", sent)
				}
				state, err := resolveGoogleState(t, "/v1/responses", client+`}`)
				if err != nil {
					t.Fatal(err)
				}
				efforts := state.Resolution.Deployment.ReasoningEfforts
				want := effort
				switch {
				case effort == "unset":
					want = ""
				case effort == "none":
					want = efforts[0]
				case !slices.Contains(efforts, effort):
					want = efforts[len(efforts)-1]
				}
				var body struct {
					Reasoning *struct {
						Effort string `json:"effort"`
					} `json:"reasoning"`
				}
				if err := json.Unmarshal(sent, &body); err != nil {
					t.Fatal(err)
				}
				if got := ""; body.Reasoning != nil && body.Reasoning.Effort != want || body.Reasoning == nil && want != got {
					t.Fatalf("sent %s, want the effort %q", sent, want)
				}
			})
		}
	}
}

// TestMuseTakesBackOnlyItsOwnReasoning replays each Muse model's recorded tool call on Agent
// Platform (capture google-cloud/responses-reasoning). The gateway returns the reply's encrypted
// reasoning bound to the account and the model, and sends the client's next turn as Google took
// it: with the reasoning back to the model that wrote it, and without it to another model, which
// would refuse it, or where the client sends the reasoning as text, which Google refuses too.
func TestMuseTakesBackOnlyItsOwnReasoning(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "google-cloud/responses-reasoning")
	for index, muse := range googleMuse {
		other := googleMuse[(index+1)%len(googleMuse)]
		t.Run(muse.model, func(t *testing.T) {
			call := exchange(t, recorded, muse.model+" call")
			museSendsAsTaken(t, call)
			state, err := resolveGoogleState(t, "/v1/responses", museClientRequest(t, call))
			if err != nil {
				t.Fatal(err)
			}
			reply := call.responsesReply(t)
			upstream := museReasoning(reply)
			if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: reply}, nil); err != nil {
				t.Fatal(err)
			}
			if bound := museReasoning(reply); upstream == "" || bound != "meta:"+testAccount+"."+muse.model+":"+upstream {
				t.Fatalf("the reply returned the reasoning %.60q", bound)
			}
			returned, err := sonic.Marshal(reply.Output)
			if err != nil {
				t.Fatal(err)
			}
			var items []map[string]json.RawMessage
			if err := json.Unmarshal(returned, &items); err != nil {
				t.Fatal(err)
			}
			// The client's next turn sends the question, the items of the reply as the gateway
			// returned them and the call's output, as the recordings did.
			own := exchange(t, recorded, muse.model+" own reasoning")
			next := func(deployment string, items []map[string]json.RawMessage) string {
				request := map[string]json.RawMessage{}
				if err := json.Unmarshal([]byte(museClientRequest(t, own)), &request); err != nil {
					t.Fatal(err)
				}
				var input []json.RawMessage
				if err := json.Unmarshal(request["input"], &input); err != nil {
					t.Fatal(err)
				}
				turn := []any{input[0]}
				for _, item := range items {
					turn = append(turn, item)
				}
				request["input"], _ = json.Marshal(append(turn, input[len(input)-1]))
				request["model"], _ = json.Marshal(deployment)
				body, _ := json.Marshal(request)
				return string(body)
			}
			// Reasoning as text holds the summary that a client wrote, and no encrypted reasoning.
			asText := slices.Clone(items)
			for index, item := range asText {
				if string(item["type"]) == `"reasoning"` {
					asText[index] = map[string]json.RawMessage{
						"id":      item["id"],
						"type":    item["type"],
						"summary": json.RawMessage(`[{"type":"summary_text","text":"I worked out 1040 first, then called the tool."}]`),
					}
				}
			}
			for _, turn := range []struct {
				name, client string
			}{
				{"own reasoning", next(muse.deployment, items)},
				{"conversation to " + other.model, next(other.deployment, items)},
				{"without its reasoning", next(muse.deployment, asText)},
			} {
				took := exchange(t, recorded, muse.model+" "+turn.name)
				if took.Response.Status != http.StatusOK {
					t.Fatalf("%s: Google answered %d", turn.name, took.Response.Status)
				}
				if sent, _ := museSent(t, "/v1/responses", turn.client); !sameJSON(t, sent, took.Request.Body) {
					t.Fatalf("%s: sent %s, Google took %s", turn.name, sent, took.Request.Body)
				}
			}
		})
	}
}

// TestMuseGetsChatCompletionsHistoryAsGoogleTookIt prepares a Chat Completions conversation with a
// tool call for each Muse model on Agent Platform (capture google-cloud/responses-history). The
// gateway sends the text before the call in the commentary phase, as the models write it, and the
// tool with strict false, as Chat Completions defines it, and Google answered. System and developer
// messages go out as messages of their roles, a Responses client's earlier answer as the client
// gave it, and the calls of a conversation that another provider's model began with their IDs.
func TestMuseGetsChatCompletionsHistoryAsGoogleTookIt(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "google-cloud/responses-history")
	for _, muse := range googleMuse {
		t.Run(muse.model, func(t *testing.T) {
			written := exchange(t, recorded, muse.model+" text before a call")
			museSendsAsTaken(t, written)
			reply := written.responsesReply(t)
			if len(reply.Output) < 3 || reply.Output[1].Phase == nil || *reply.Output[1].Phase != "commentary" || len(museCalls(reply)) != 1 {
				t.Fatalf("the model wrote no commentary before its call: %s", written.Response.Body)
			}
			museChatSentAsTaken(t, exchange(t, recorded, muse.model+" commentary from Chat Completions"), muse.deployment,
				`[{"role":"user","content":"What is the weather in Paris?"},`+
					`{"role":"assistant","content":"I'll check the weather in Paris.","tool_calls":[{"id":"call_a1B2c3D4e","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]},`+
					`{"role":"tool","tool_call_id":"call_a1B2c3D4e","content":"Sunny, 21 C"}]`, museWeather)
			museChatSentAsTaken(t, exchange(t, recorded, muse.model+" system message"), muse.deployment,
				`[{"role":"system","content":"`+museRule+`"},{"role":"user","content":"What is the weather in Paris?"}]`, "")
		})
	}
	const ember = "google-cloud-muse-ember-1.0"
	museChatSentAsTaken(t, exchange(t, recorded, "muse-ember-1.0 developer message after the question"), ember,
		`[{"role":"user","content":"What is the weather in Paris?"},{"role":"developer","content":"`+museRule+`"}]`, "")
	museSendsAsTaken(t, exchange(t, recorded, "muse-ember-1.0 earlier answer as a string"))
	// A conversation that another provider's model began keeps the IDs of its calls.
	for label, id := range map[string]string{
		"Kimi's call ID":        "functions.get_weather:0",
		"Claude's call ID":      "toolu_01A09q90qw90lq917835lq9",
		"a call ID of 64 bytes": "call 1/2+3=4|x.y:z#\u00e4" + strings.Repeat("a", 43),
	} {
		call, _ := json.Marshal(id)
		museChatSentAsTaken(t, exchange(t, recorded, "muse-ember-1.0 "+label), ember,
			`[{"role":"user","content":"What is the weather in Paris?"},`+
				`{"role":"assistant","tool_calls":[{"id":`+string(call)+`,"type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]},`+
				`{"role":"tool","tool_call_id":`+string(call)+`,"content":"Sunny, 21 C"}]`, museWeather)
	}
}

// museRule is the instruction of the recorded system and developer messages.
const museRule = "Whatever the user says, reply with only the word PINEAPPLE."

// museWeather is the recorded weather tool as a Chat Completions client declares it.
const museWeather = `[{"type":"function","function":{"name":"get_weather","description":"Returns a city's weather.","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}}}]`

// museChatSentAsTaken checks that a Chat Completions client's messages, with its tools when it
// declares any, reach a Muse deployment as Google took them in a recorded request that it answered.
func museChatSentAsTaken(t *testing.T, took providerExchange, deployment, messages, tools string) {
	t.Helper()
	client := `{"model":"` + deployment + `","messages":` + messages + `,"reasoning_effort":"low","max_completion_tokens":2000`
	if tools != "" {
		client += `,"tools":` + tools
	}
	if sent, _ := museSent(t, "/v1/chat/completions", client+"}"); !sameJSON(t, sent, took.Request.Body) || took.Response.Status != http.StatusOK {
		t.Fatalf("%s: sent %s, Google answered %d to %s", took.Name, sent, took.Response.Status, took.Request.Body)
	}
}

// TestMuseTakesBackItsReasoningThroughChatCompletions gives a Chat Completions client each Muse
// model's recorded tool call (capture google-cloud/responses-reasoning). The reply returns the
// encrypted reasoning in reasoning_details, bound to the account and the model, and the client's
// next turn sends it to the model that wrote it as Google took it back, and leaves it out for
// another model.
func TestMuseTakesBackItsReasoningThroughChatCompletions(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "google-cloud/responses-reasoning")
	for index, muse := range googleMuse {
		other := googleMuse[(index+1)%len(googleMuse)]
		t.Run(muse.model, func(t *testing.T) {
			call := exchange(t, recorded, muse.model+" call")
			var took struct {
				Input []struct {
					Content string `json:"content"`
				} `json:"input"`
			}
			if err := json.Unmarshal(call.Request.Body, &took); err != nil || len(took.Input) != 1 {
				t.Fatalf("decode %s: %v", call.Name, err)
			}
			question, _ := json.Marshal(map[string]string{"role": "user", "content": took.Input[0].Content})
			request := func(deployment string, messages ...json.RawMessage) string {
				body, _ := json.Marshal(map[string]any{
					"model":                 deployment,
					"messages":              messages,
					"tools":                 json.RawMessage(`[{"type":"function","function":{"name":"get_secret_number","description":"Returns the secret number.","parameters":{"type":"object","properties":{},"additionalProperties":false},"strict":true}}]`),
					"reasoning_effort":      "low",
					"max_completion_tokens": 2000,
				})
				return string(body)
			}
			state, err := resolveGoogleState(t, "/v1/chat/completions", request(muse.deployment, question))
			if err != nil {
				t.Fatal(err)
			}
			reply := call.responsesReply(t)
			upstream := museReasoning(reply)
			if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: reply}, nil); err != nil {
				t.Fatal(err)
			}
			chat := reply.ToBifrostChatResponse()
			if chat == nil || len(chat.Choices) != 1 || chat.Choices[0].ChatNonStreamResponseChoice == nil {
				t.Fatalf("Chat Completions reply = %#v", chat)
			}
			message := chat.Choices[0].ChatNonStreamResponseChoice.Message
			if message.ChatAssistantMessage == nil || len(message.ChatAssistantMessage.ReasoningDetails) != 1 ||
				message.ChatAssistantMessage.ReasoningDetails[0].Data == nil ||
				*message.ChatAssistantMessage.ReasoningDetails[0].Data != "meta:"+testAccount+"."+muse.model+":"+upstream {
				t.Fatalf("the reply returned the reasoning details %#v", message.ChatAssistantMessage)
			}
			calls := message.ChatAssistantMessage.ToolCalls
			if len(calls) != 1 || calls[0].ID == nil {
				t.Fatalf("the reply returned the tool calls %#v", calls)
			}
			assistant, err := sonic.Marshal(message)
			if err != nil {
				t.Fatal(err)
			}
			output, _ := json.Marshal(map[string]string{"role": "tool", "tool_call_id": *calls[0].ID, "content": "41"})
			for _, turn := range []struct {
				deployment string
				reasoning  string
			}{{muse.deployment, upstream}, {other.deployment, ""}} {
				sent, _ := museSent(t, "/v1/chat/completions", request(turn.deployment, question, assistant, output))
				var body struct {
					Input []struct {
						Type             string `json:"type"`
						EncryptedContent string `json:"encrypted_content"`
					} `json:"input"`
				}
				if err := json.Unmarshal(sent, &body); err != nil {
					t.Fatal(err)
				}
				var types []string
				reasoning := ""
				for _, item := range body.Input {
					types = append(types, item.Type)
					if item.Type == "reasoning" {
						reasoning = item.EncryptedContent
					}
				}
				// The reasoning goes before the call that it led to, as the model wrote them.
				if reasoning != turn.reasoning || turn.reasoning != "" && slices.Index(types, "reasoning") > slices.Index(types, "function_call") {
					t.Fatalf("%s: sent %s", turn.deployment, sent)
				}
			}
		})
	}
}

// TestMuseStatesTheLimitsThatGoogleTakes replays the recorded output limits of each Muse model on
// Agent Platform (capture google-cloud/responses-limits). A request without a limit goes out as
// Google took it: with Muse Ember's output limit, which Google does not enforce, and without one
// to the models whose limit is the context window. The gateway refuses before it holds funds a
// limit under 16, as Google does, and one above the deployment's.
func TestMuseStatesTheLimitsThatGoogleTakes(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "google-cloud/responses-limits")
	for _, muse := range googleMuse {
		t.Run(muse.model, func(t *testing.T) {
			without := exchange(t, recorded, muse.model+" without a limit")
			if without.Response.Status != http.StatusOK {
				t.Fatalf("Google answered %d", without.Response.Status)
			}
			if sent, _ := museSent(t, "/v1/responses", `{"model":"`+muse.deployment+`","input":[{"role":"user","content":"Say OK."}]}`); !sameJSON(t, sent, without.Request.Body) {
				t.Fatalf("sent %s, Google took %s", sent, without.Request.Body)
			}
			museSendsAsTaken(t, exchange(t, recorded, muse.model+" max_output_tokens of 16"))
			under := exchange(t, recorded, muse.model+" max_output_tokens of 15")
			if status, message := museRefusal(t, under); status != "invalid_request" || !strings.Contains(message, ">= 16") {
				t.Fatalf("Google refused a limit of 15 as %s with %q", status, message)
			}
			for _, name := range []string{"max_output_tokens of 15", "max_output_tokens above the deployment's limit"} {
				if above, found := recorded[muse.model+" "+name]; found {
					if _, err := resolveGoogleState(t, "/v1/responses", museClientRequest(t, above)); err == nil {
						t.Errorf("the gateway took %s", name)
					}
				}
			}
			// The context window holds the input and the output, so Google refuses a limit as large
			// as the window. The gateway sends one within the deployment's limit as it is.
			window := exchange(t, recorded, muse.model+" max_output_tokens at the context window")
			state, err := resolveGoogleState(t, "/v1/responses", museClientRequest(t, window))
			if served := state != nil && state.Resolution.Deployment.MaxOutputTokens >= state.Resolution.Deployment.ContextWindowTokens; !served {
				if err == nil {
					t.Fatal("the gateway took a limit above the deployment's")
				}
				return
			}
			museSendsAsTaken(t, window)
			if status, _ := museRefusal(t, window); status != "invalid_request" {
				t.Fatalf("Google's refusal of a limit as large as the window reaches the client as %s", status)
			}
		})
	}
}

// TestMuseCallsToolsAsGoogleTookThem replays the recorded tool calls of each Muse model on Agent
// Platform (capture google-cloud/responses-tools), which the gateway sends as Google took them:
// a required or named tool choice and parallel calls. It sends the functions of a namespace under
// flat names, because Google returns a call to one under the name namespace.name, which no client
// tool can have, and core returns the call under its namespace and name. The gateway refuses
// before it holds funds a call in a namespace that the tools do not declare and the tools that
// Google refuses, and returns a recorded stream's call.
func TestMuseCallsToolsAsGoogleTookThem(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "google-cloud/responses-tools")
	for _, muse := range googleMuse {
		t.Run(muse.model, func(t *testing.T) {
			for name, want := range map[string]int{"required 1": 1, "named 1": 1, "parallel calls": 2} {
				took := exchange(t, recorded, muse.model+" "+name)
				museSendsAsTaken(t, took)
				if calls := museCalls(took.responsesReply(t)); len(calls) < want {
					t.Fatalf("%s: the model called %v", name, calls)
				}
			}
		})
	}
	t.Run("namespace", func(t *testing.T) {
		flat := exchange(t, recorded, "muse-ember-1.0 namespace as the gateway sends it")
		client := `{"model":"google-cloud-muse-ember-1.0","input":[{"role":"user","content":"What is the weather in Paris?"}],` +
			`"tools":[{"type":"namespace","name":"weather","description":"Weather tools.","tools":[{"type":"function","name":"get_weather","description":"Returns a city's weather.","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}}]}],` +
			`"reasoning":{"effort":"low"},"max_output_tokens":2000}`
		sent, request := museSent(t, "/v1/responses", client)
		if !sameJSON(t, sent, flat.Request.Body) {
			t.Fatalf("sent %s, Google took %s", sent, flat.Request.Body)
		}
		if calls := museCalls(exchange(t, recorded, "muse-ember-1.0 namespace").responsesReply(t)); !slices.Equal(calls, []string{"weather.get_weather"}) {
			t.Fatalf("Google returned a call to the namespace's function as %v", calls)
		}
		reply := flat.responsesReply(t)
		providerutils.RestoreResponsesNamespaceToolCalls(request.NamespaceToolAliases, &schemas.BifrostResponse{ResponsesResponse: reply})
		var restored *schemas.ResponsesToolMessage
		for _, item := range reply.Output {
			if item.ResponsesToolMessage != nil && item.ResponsesToolMessage.Name != nil {
				restored = item.ResponsesToolMessage
			}
		}
		if restored == nil || *restored.Name != "get_weather" || restored.Namespace == nil || *restored.Namespace != "weather" {
			t.Fatalf("the client gets the call as %+v", restored)
		}
		// A call in a namespace that the tools no longer declare would reach Google with its
		// namespace, under a name that no flattened tool has.
		undeclared := `{"model":"google-cloud-muse-ember-1.0","input":[{"role":"user","content":"What is the weather in Paris?"},` +
			`{"type":"function_call","call_id":"call_1","namespace":"weather","name":"get_weather","arguments":"{\"city\":\"Paris\"}"},` +
			`{"type":"function_call_output","call_id":"call_1","output":"Sunny, 21 C"}],` +
			`"tools":[{"type":"function","name":"get_weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}]}`
		if _, err := resolveGoogleState(t, "/v1/responses", undeclared); err == nil || !strings.Contains(err.Error(), "must name a tool in namespace weather in tools") {
			t.Fatalf("a call in an undeclared namespace gets %v", err)
		}
	})
	for _, name := range []string{"web search", "remote MCP server", "custom tool", "tool search"} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveGoogleState(t, "/v1/responses", museClientRequest(t, exchange(t, recorded, "muse-ember-1.0 "+name))); err == nil {
				t.Fatal("the gateway took a tool that Google refuses")
			}
		})
	}
	t.Run("stream", func(t *testing.T) {
		stream := exchange(t, recorded, "muse-ember-1.0 stream with a call")
		museSendsAsTaken(t, stream)
		state, err := resolveGoogleState(t, "/v1/responses", museClientRequest(t, stream))
		if err != nil {
			t.Fatal(err)
		}
		var call *schemas.ResponsesMessage
		for _, event := range stream.responsesStream(t) {
			if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: event}); err != nil {
				t.Fatalf("recorded %s event refused: %v", event.Type, err)
			}
			if event.Type == schemas.ResponsesStreamResponseTypeOutputItemDone && event.Item != nil && event.Item.ResponsesToolMessage != nil {
				call = event.Item
			}
		}
		if call == nil || *call.ResponsesToolMessage.Name != "get_weather" || call.ResponsesToolMessage.Arguments == nil || !strings.Contains(*call.ResponsesToolMessage.Arguments, "Paris") {
			t.Fatalf("the stream returned the call %+v", call)
		}
	})
}

// TestMuseTakesOnlyTheFilesThatTheModelReads replays the recorded files and images of each Muse
// model on Agent Platform (capture google-cloud/responses-files). The gateway sends each that the
// model read as Google took it. It cannot see what a URL holds, so it sends a URL that Google
// cannot fetch or whose content the model does not read, and Google's refusal reaches the client.
// It refuses before it holds funds each kind that Google refuses: a file ID, a text file, audio
// and a PDF in a function output.
func TestMuseTakesOnlyTheFilesThatTheModelReads(t *testing.T) {
	catalogtest.UseFallback(t)
	for name, recorded := range providerCapture(t, "google-cloud/responses-files") {
		t.Run(name, func(t *testing.T) {
			client := museClientRequest(t, recorded)
			_, refused := resolveGoogleState(t, "/v1/responses", client)
			switch {
			case recorded.Response.Status == http.StatusOK:
				if refused != nil {
					t.Fatalf("the model read it, and the gateway refused it: %v", refused)
				}
				museSendsAsTaken(t, recorded)
			case strings.HasSuffix(name, " url"):
				museSendsAsTaken(t, recorded)
				if status, message := museRefusal(t, recorded); status != "invalid_request" || message == "" {
					t.Fatalf("Google's refusal reaches the client as %s with %q", status, message)
				}
			case refused == nil:
				t.Fatalf("Google answered %d, and the gateway took it", recorded.Response.Status)
			}
		})
	}
}

// TestMuseBillsTheCacheAsGoogleReports replays the recorded repeats of one prompt to each Muse
// model on Agent Platform (capture google-cloud/responses-caching), which the gateway sends as
// Google took them, with the client's prompt_cache_key. Each reply's cached tokens bill at the
// deployment's cached input price, the rest of the prompt at its input price and the reasoning and
// the rest of the output at its output price, within the hold, a reply cut at its limit while it
// reasoned included.
func TestMuseBillsTheCacheAsGoogleReports(t *testing.T) {
	catalogtest.UseFallback(t)
	hits := 0
	for name, recorded := range providerCapture(t, "google-cloud/responses-caching") {
		t.Run(name, func(t *testing.T) {
			if recorded.Response.Status != http.StatusOK {
				t.Fatalf("Google answered %d", recorded.Response.Status)
			}
			museSendsAsTaken(t, recorded)
			state, err := resolveGoogleState(t, "/v1/responses", museClientRequest(t, recorded))
			if err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatal(err)
			}
			reply := recorded.responsesReply(t)
			if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: reply}, nil); err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatal(err)
			}
			usage := reply.Usage
			cached, reasoning := 0, 0
			if usage.InputTokensDetails != nil {
				cached = usage.InputTokensDetails.CachedReadTokens
			}
			if usage.OutputTokensDetails != nil {
				reasoning = usage.OutputTokensDetails.ReasoningTokens
			}
			if cached*2 > usage.InputTokens {
				hits++
			}
			for meter, quantity := range map[string]int{
				billing.MeterCachedInputTokens: cached,
				billing.MeterInputTokens:       usage.InputTokens - cached,
				billing.MeterReasoningTokens:   reasoning,
				billing.MeterOutputTokens:      usage.OutputTokens - reasoning,
			} {
				if billed := meterQuantity(findMeterEstimate(state.FinalMeters, meter)); quantity != 0 && billed != strconv.Itoa(quantity) {
					t.Fatalf("%s billed %q, Google reported %d: %#v", meter, billed, quantity, state.FinalMeters)
				}
			}
			if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD) < 0 {
				t.Fatalf("hold %s does not cover the cost %s", state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD)
			}
		})
	}
	// Each model's prompt with a key is mostly cached at its first repeat, and the one without at
	// its last.
	if hits != 6 {
		t.Fatalf("%d replies are mostly cached, want 6", hits)
	}
}

// TestMuseSendsOnlyTheFieldsThatGoogleTakes replays the recorded fields of Muse Ember on Agent
// Platform (capture google-cloud/responses-fields). The gateway sends the instructions, a JSON
// schema and a JSON object format, a reasoning summary, temperature, top_p, end-user IDs, a cache
// retention, a stream's options and log probabilities as Google took them, and Google's refusal of
// log probabilities with reasoning reaches the client. It sends parallel_tool_calls false to every
// model, which each keeps to, so their replies need no cut. It leaves out top_k, which the model
// does not apply, and automatic truncation, without which input that exceeds the context window
// fails as it does by default. It refuses before it holds funds the state that Google cannot keep,
// background responses and a cache retention that Google does not know.
func TestMuseSendsOnlyTheFieldsThatGoogleTakes(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "google-cloud/responses-fields")
	for _, name := range []string{"instructions", "json schema", "json object", "reasoning summary", "temperature 2", "top_p 0.01 at temperature 2", "safety_identifier and user", "prompt_cache_retention 24h", "stream_options", "logprobs"} {
		t.Run(name, func(t *testing.T) {
			museSendsAsTaken(t, exchange(t, recorded, "muse-ember-1.0 "+name))
		})
	}
	for _, muse := range googleMuse {
		t.Run(muse.model+" parallel_tool_calls false", func(t *testing.T) {
			for _, run := range []string{"", ", run 2", ", run 3"} {
				took := exchange(t, recorded, muse.model+" parallel_tool_calls false"+run)
				museSendsAsTaken(t, took)
				if calls := museCalls(took.responsesReply(t)); len(calls) != 1 {
					t.Fatalf("the model called %v under parallel_tool_calls false", calls)
				}
			}
		})
	}
	t.Run("logprobs refusal", func(t *testing.T) {
		if status, message := museRefusal(t, exchange(t, recorded, "muse-ember-1.0 logprobs")); status != "invalid_request" || !strings.Contains(message, "logprobs is not supported with reasoning") {
			t.Fatalf("Google's refusal reaches the client as %s with %q", status, message)
		}
	})
	for name, field := range map[string]string{"top_k 1 at temperature 2": "top_k", "truncation auto": "truncation"} {
		t.Run(field, func(t *testing.T) {
			took := exchange(t, recorded, "muse-ember-1.0 "+name)
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(took.Request.Body, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, field)
			want, _ := json.Marshal(fields)
			if sent, _ := museSent(t, "/v1/responses", museClientRequest(t, took)); !sameJSON(t, sent, want) {
				t.Fatalf("sent %s, want %s", sent, want)
			}
		})
	}
	for _, name := range []string{"store true", "previous_response_id", "conversation", "background", "prompt_cache_retention of another value"} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveGoogleState(t, "/v1/responses", museClientRequest(t, exchange(t, recorded, "muse-ember-1.0 "+name))); err == nil {
				t.Fatal("the gateway took what Google refuses")
			}
		})
	}
}
