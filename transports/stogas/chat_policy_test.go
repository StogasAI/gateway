package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestChatPolicyRejectsUnsupportedFields(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"audio", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"audio":{}}`, "audio is not supported"},
		{"empty messages", `{"model":"gpt-5.5","messages":[]}`, "messages must contain at least one message"},
		{"null message", `{"model":"gpt-5.5","messages":[null]}`, "messages must contain only objects"},
		{"missing role", `{"model":"gpt-5.5","messages":[{"content":"hi"}]}`, "messages[0].role must be a string"},
		{"unknown role", `{"model":"gpt-5.5","messages":[{"role":"owner","content":"hi"}]}`, "messages[0].role is not supported"},
		{"unknown message field", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi","future":true}]}`, "messages[0].future is not supported"},
		{"unknown text block field", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","future":true}]}]}`, "messages[0].content[0].future is not supported"},
		{"orphan tool result", `{"model":"gpt-5.5","messages":[{"role":"tool","tool_call_id":"call_1","content":"done"}]}`, "must match an unresolved preceding assistant tool call"},
		{"tool call without result", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]}]}`, "require one matching tool result each"},
		{"intervening message before tool result", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"user","content":"skip it"},{"role":"tool","tool_call_id":"call_1","content":"done"}]}`, "must be a tool result"},
		{"duplicate tool call id", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"one","arguments":"{}"}},{"id":"call_1","type":"function","function":{"name":"two","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","content":"done"}]}`, "duplicates another assistant tool call"},
		{"duplicate tool result", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","content":"done"},{"role":"tool","tool_call_id":"call_1","content":"again"}]}`, "must match an unresolved preceding assistant tool call"},
		{"tool call unknown field", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","future":true,"function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","content":"done"}]}`, "tool_calls[0].future is not supported"},
		{"tool call non-string arguments", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":{}}}]},{"role":"tool","tool_call_id":"call_1","content":"done"}]}`, "Invalid JSON body"},
		{"tool call malformed arguments", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"not-json"}}]},{"role":"tool","tool_call_id":"call_1","content":"done"}]}`, "arguments must encode a JSON object"},
		{"tool call array arguments", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"[]"}}]},{"role":"tool","tool_call_id":"call_1","content":"done"}]}`, "arguments must encode a JSON object"},
		{"tool call duplicate argument key", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"key\":1,\"key\":2}"}}]},{"role":"tool","tool_call_id":"call_1","content":"done"}]}`, "arguments must encode a JSON object"},
		{"oversized tool call id", fmt.Sprintf(`{"model":"gpt-5.5","messages":[{"role":"assistant","tool_calls":[{"id":%q,"type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":%q,"content":"done"}]}`, strings.Repeat("a", 65), strings.Repeat("a", 65)), "at most 64 bytes"},
		{"Anthropic unsafe tool call id", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"assistant","tool_calls":[{"id":"call:1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call:1","content":"done"}]}`, "only letters, digits, underscores, or hyphens"},
		{"stream-only tool call index", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","content":"done"}]}`, "tool_calls[0].index is not supported"},
		{"empty assistant", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":null}]}`, "must contain content, refusal, reasoning history, annotations, or tool calls"},
		{"empty annotations", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"},{"role":"assistant","annotations":[]}]}`, "annotations must be a non-empty array"},
		{"citation reversed range", `{"model":"gpt-5.5","messages":[{"role":"assistant","content":"answer","annotations":[{"type":"url_citation","url_citation":{"start_index":5,"end_index":2,"title":"source","url":"https://example.com"}}]},{"role":"user","content":"continue"}]}`, "end_index must be an integer at or after start_index"},
		{"reasoning details on OpenAI", `{"model":"gpt-5.5","messages":[{"role":"assistant","content":"answer","reasoning_details":[{"index":0,"type":"reasoning.text","text":"thought","signature":"sig"}]},{"role":"user","content":"continue"}]}`, "supported only for Anthropic-format deployments"},
		{"unsigned Anthropic reasoning", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"assistant","content":"answer","reasoning":"thought"},{"role":"user","content":"continue"}]}`, "requires signed reasoning_details"},
		{"Anthropic reasoning detail index gap", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"assistant","content":"answer","reasoning_details":[{"index":1,"type":"reasoning.text","text":"thought","signature":"sig"}]},{"role":"user","content":"continue"}]}`, "must match its array position"},
		{"Anthropic reasoning detail missing signature", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"assistant","content":"answer","reasoning_details":[{"index":0,"type":"reasoning.text","text":"thought"}]},{"role":"user","content":"continue"}]}`, "signature is required"},
		{"Anthropic reasoning detail unknown field", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"assistant","content":"answer","reasoning_details":[{"index":0,"type":"reasoning.encrypted","data":"opaque","future":true}]},{"role":"user","content":"continue"}]}`, "reasoning_details[0].future is not supported"},
		{"Anthropic reasoning text mismatch", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"assistant","content":"answer","reasoning":"different","reasoning_details":[{"index":0,"type":"reasoning.text","text":"thought","signature":"sig"}]},{"role":"user","content":"continue"}]}`, "reasoning must match the visible text"},
		{"message audio", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi","audio":{"data":"abc"}}]}`, "Only text message content"},
		{"empty prompt", `{"model":"gpt-5.5","messages":[{"role":"user","content":"  "}]}`, "messages[0].content must contain non-empty text"},
		{"message file id", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi","file_id":"file_123"}]}`, "file_id inputs are not supported"},
		{"message file url", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi","file_url":"https://example.com/a.pdf"}]}`, "file_url inputs are not supported"},
		{"message file data", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi","file_data":"data:text/plain;base64,aGk="}]}`, "file inputs are not supported"},
		{"message image url", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi","image_url":"https://example.com/x.png"}]}`, "Only text message content"},
		{"image content block", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/x.png"}}]}]}`, "Only text message content"},
		{"input file content block", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,aGk="}]}]}`, "file inputs are not supported"},
		{"text block file id", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","file_id":"file_123"}]}]}`, "file_id inputs are not supported"},
		{"text block file url", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","file_url":"https://example.com/a.pdf"}]}]}`, "file_url inputs are not supported"},
		{"text block file data", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","file_data":"data:text/plain;base64,aGk="}]}]}`, "file inputs are not supported"},
		{"text block file object", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","file":{"file_data":"data:text/plain;base64,aGk="}}]}]}`, "file inputs are not supported"},
		{"text block image url", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","image_url":{"url":"https://example.com/x.png"}}]}]}`, "Only text message content"},
		{"text block input image", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","input_image":{"image_url":"https://example.com/x.png"}}]}]}`, "Only text message content"},
		{"text block input audio", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","input_audio":{"data":"abc","format":"mp3"}}]}]}`, "Only text message content"},
		{"modalities", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"modalities":["text","audio"]}`, "modalities"},
		{"n", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"n":2}`, "n must be 1"},
		{"hosted tool", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"web_search"}]}`, "Only function tools"},
		{"local shell tool", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"local_shell"}]}`, "Only function tools"},
		{"apply patch tool", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"apply_patch"}]}`, "Only function tools"},
		{"fallbacks", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"fallbacks":["openai-gpt-5.5-2026-04-23-flex"]}`, "Fallbacks are not supported"},
		{"tool choice any string", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tool_choice":"any"}`, "tool_choice must be auto, none, required"},
		{"tool choice required without tools", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tool_choice":"required"}`, "tool_choice requires supported tools"},
		{"tool choice without tools", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`, "tool_choice requires supported tools"},
		{"tool choice unknown function", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":{"type":"function","function":{"name":"other"}}}`, "tool_choice selects an unknown function tool"},
		{"custom tool", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"custom","name":"custom_tool"}]}`, "custom tools are not supported"},
		{"function tool missing name", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{}}]}`, "tools[0].function.name is required"},
		{"function tool shorthand", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","name":"lookup"}]}`, "tools[0].name is not supported"},
		{"function tool unknown field", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","defer_loading":true}}]}`, "tools[0].function.defer_loading is not supported"},
		{"function tool invalid name", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup tool"}}]}`, "must contain 1 to 64"},
		{"duplicate function tool", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}},{"type":"function","function":{"name":"lookup"}}]}`, "duplicates another tool"},
		{"function parameters array", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":[]}}]}`, "Invalid JSON body"},
		{"function strict string", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","strict":"true"}}]}`, "Invalid JSON body"},
		{"tool choice shorthand", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":{"type":"function","name":"lookup"}}`, "tool_choice.name is not supported"},
		{"tool choice unknown field", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":{"type":"function","function":{"name":"lookup","future":true}}}`, "tool_choice.function.future is not supported"},
		{"anthropic hosted tool", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"web_search"}]}`, "Only function tools"},
		{"anthropic custom tool", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"custom","name":"custom_tool"}]}`, "custom tools are not supported for the selected Chat deployment"},
		{"anthropic custom tool choice", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":{"type":"custom","name":"custom_tool"}}`, "custom tool_choice is not supported for the selected Chat deployment"},
		{"anthropic message name", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","name":"alice","content":"hi"}]}`, "name is not supported for Anthropic-format history"},
		{"azure claude tool result name", `{"model":"azure-claude-sonnet-4-6","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","name":"lookup","tool_call_id":"call_1","content":"done"}]}`, "name is not supported for Anthropic-format history"},
		{"anthropic refusal history", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"assistant","refusal":"no"},{"role":"user","content":"continue"}]}`, "refusal is not supported for Anthropic-format history"},
		{"anthropic trailing assistant prefill whitespace", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"complete this"},{"role":"assistant","content":"answer: "}]}`, "must not end in whitespace"},
		{"Anthropic reordered system message", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"first"},{"role":"system","content":"new policy"},{"role":"user","content":"continue"}]}`, "cannot be preserved after the conversation starts"},
		{"Azure Claude reordered developer message", `{"model":"azure-claude-sonnet-4-6","messages":[{"role":"user","content":"first"},{"role":"developer","content":"new policy"},{"role":"assistant","content":"answer"},{"role":"user","content":"continue"}]}`, "cannot be preserved after the conversation starts"},
		{"Anthropic mid-conversation system placement", `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"first"},{"role":"system","content":"new policy"},{"role":"user","content":"continue"}]}`, "must be last or immediately precede an assistant message"},
		{"metadata non-string", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"metadata":{"a":1}}`, "metadata values"},
		{"anthropic-only cache control on openai", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"ephemeral"}}`, "only supported for Anthropic"},
		{"nested cache control on openai", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`, "cache_control is only supported for Anthropic"},
		{"prompt cache options anthropic", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"prompt_cache_options":{"mode":"explicit"}}`, "prompt_cache_options is only supported for OpenAI"},
		{"anthropic cache control bad ttl", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"ephemeral","ttl":"24h"}}`, "cache_control.ttl must be 5m or 1h"},
		{"anthropic cache control bad type", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"persisted","ttl":"1h"}}`, "cache_control.type must be ephemeral"},
		{"openai task budget", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"task_budget":{"type":"tokens","total":20000}}`, "task_budget is only supported for Anthropic"},
		{"openai context management", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"context_management":{"edits":[{"type":"compact_20260112"}]}}`, "context_management is only supported for Anthropic"},
		{"anthropic frequency penalty", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"frequency_penalty":0.1}`, "frequency_penalty is only supported for OpenAI"},
		{"anthropic logit bias", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"logit_bias":{"123":1}}`, "logit_bias is only supported for OpenAI"},
		{"anthropic logprobs", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"logprobs":true}`, "logprobs is only supported for OpenAI"},
		{"anthropic prediction", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"prediction":{"type":"content","content":"hi"}}`, "prediction is only supported for OpenAI"},
		{"anthropic presence penalty", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"presence_penalty":0.1}`, "presence_penalty is only supported for OpenAI"},
		{"anthropic prompt cache key", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"prompt_cache_key":"tenant-a"}`, "prompt_cache_key is not supported for Anthropic-format"},
		{"prompt cache isolation key", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"prompt_cache_isolation_key":"tenant-a"}`, "prompt_cache_isolation_key is not supported"},
		{"anthropic seed", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"seed":1}`, "seed is only supported for OpenAI"},
		{"anthropic top logprobs", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"top_logprobs":1}`, "top_logprobs is only supported for OpenAI"},
		{"anthropic verbosity", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"verbosity":"medium"}`, "verbosity is only supported for OpenAI"},
		{"anthropic web search options", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"web_search_options":{"search_context_size":"low"}}`, "web_search_options is only supported for OpenAI"},
		{"openai repetition penalty", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"repetition_penalty":1.1}`, "only supported for Chutes"},
		{"empty stop sequence", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stop":[""]}`, "stop sequences must be non-empty"},
		{"duplicate stop sequence", `{"model":"chutes/qwen3-32b","messages":[{"role":"user","content":"hi"}],"stop":["END","END"]}`, "stop must not contain duplicate values"},
		{"too many portable stop sequences", `{"model":"chutes/qwen3-32b","messages":[{"role":"user","content":"hi"}],"stop":["01","02","03","04","05","06","07","08","09","10","11","12","13","14","15","16","17"]}`, "stop contains too many items"},
		{"oversized stop sequence", fmt.Sprintf(`{"model":"chutes/qwen3-32b","messages":[{"role":"user","content":"hi"}],"stop":["%s"]}`, strings.Repeat("x", maxStopSequenceBytes+1)), "stop values must not exceed"},
		{"NUL stop sequence", `{"model":"chutes/qwen3-32b","messages":[{"role":"user","content":"hi"}],"stop":["END\u0000"]}`, "stop values must not contain NUL"},
		{"prediction unknown field", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"prediction":{"type":"content","content":"answer","future":true}}`, "prediction must contain only type and content"},
		{"prediction non-text part", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"prediction":{"type":"content","content":[{"type":"image_url","text":"answer"}]}}`, "must contain only type=text and text"},
		{"response format unknown field", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_object","future":true}}`, "supports only type"},
		{"response format invalid schema name", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"bad name","schema":{"type":"object"}}}}`, "name must contain 1 to 64"},
		{"openai reasoning display", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning_display":"summarized"}`, "only supported for Anthropic-format"},
		{"anthropic empty stop sequence", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"stop_sequences":[""]}`, "stop_sequences must contain non-empty strings"},
		{"anthropic duplicate stop sequence", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"stop_sequences":["END","END"]}`, "stop_sequences must not contain duplicate values"},
		{"anthropic too many stop sequences", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"stop_sequences":["01","02","03","04","05","06","07","08","09","10","11","12","13","14","15","16","17"]}`, "stop_sequences contains too many items"},
		{"anthropic json object response format", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_object"}}`, "must be json_schema for Anthropic-format"},
		{"top k openai", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"top_k":40}`, "top_k is only supported for Anthropic"},
		{"stop sequences openai", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stop_sequences":["END"]}`, "stop_sequences is only supported for Anthropic"},
		{"anthropic stop conflicts with stop sequences", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"stop":["DONE"],"stop_sequences":["END"]}`, "stop conflicts with stop_sequences"},
		{"conflicting reasoning alias", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning":{"effort":"minimal"},"reasoning_effort":"minimal"}`, "conflicts"},
		{"bad reasoning object", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning":"low"}`, "reasoning must be an object"},
		{"bad reasoning max tokens", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning_max_tokens":0}`, "reasoning_max_tokens is outside the supported range"},
		{"bad nested reasoning max tokens", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning":{"max_tokens":"many"}}`, "reasoning.max_tokens must be an integer"},
		{"unsupported manual reasoning limit", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning":{"max_tokens":1024}}`, "manual reasoning token limits are not supported"},
		{"manual reasoning budget below deployment minimum", `{"model":"anthropic-claude-opus-4-6","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":4096,"reasoning":{"max_tokens":1023}}`, "at least the deployment minimum"},
		{"manual reasoning budget equals output limit", `{"model":"anthropic-claude-opus-4-6","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":1024,"reasoning":{"max_tokens":1024}}`, "less than the output token limit"},
		{"manual reasoning budget above deployment maximum", `{"model":"anthropic-claude-opus-4-6","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":128000,"reasoning":{"max_tokens":128000}}`, "exceeds the deployment maximum"},
		{"manual reasoning limit on adaptive-only Anthropic model", `{"model":"anthropic-claude-opus-4-7","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":4096,"reasoning":{"max_tokens":1024}}`, "manual reasoning token limits are not supported"},
		{"manual reasoning limit on Azure", `{"model":"azure-gpt-5.6-sol","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":4096,"reasoning":{"max_tokens":1024}}`, "manual reasoning token limits are not supported"},
		{"manual reasoning limit on Chutes", `{"model":"chutes-glm-5.2","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":4096,"reasoning":{"max_tokens":1024}}`, "manual reasoning token limits are not supported"},
		{"conflicting reasoning controls", `{"model":"anthropic/claude-opus-4-6","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":4096,"reasoning":{"effort":"high","max_tokens":1024}}`, "reasoning effort conflicts"},
		{"bad reasoning enabled type", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning":{"enabled":"yes"}}`, "reasoning.enabled must be a boolean"},
		{"unknown reasoning effort", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"ultra"}`, "must be one of"},
		{"chat reasoning summary", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning":{"summary":"auto"}}`, "reasoning.summary is not supported"},
		{"unknown reasoning field", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning":{"effort":"low","unknown":true}}`, "reasoning.unknown is not supported"},
		{"store true", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"store":true}`, "store=true is not supported"},
		{"store string", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"store":"false"}`, "Invalid JSON body"},
		{"anthropic parallel tool calls", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"parallel_tool_calls":false}`, "parallel_tool_calls is not supported for Anthropic"},
		{"stream options without stream", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream_options":{"include_usage":false}}`, "stream_options requires stream=true"},
		{"stream options unknown key", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"unknown":true}}`, "stream_options.unknown is not supported"},
		{"chat stream obfuscation", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"include_obfuscation":true}}`, "stream_options.include_obfuscation is not supported for Chat Completions"},
		{"anthropic mcp toolset", `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"mcp_toolset","mcp_server_name":"remote"}]}`, "provider execution cannot be bounded"},
		{"openai mcp toolset", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"mcp_toolset","mcp_server_name":"remote"}]}`, "Only function tools"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResolvedChat(t, tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestStoreFalseIsAcceptedAcrossProvidersAndInterfaces(t *testing.T) {
	for _, tc := range []struct {
		name      string
		responses bool
		body      string
	}{
		{"OpenAI Chat", false, `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"store":false}`},
		{"Azure Chat", false, `{"model":"azure-gpt-5.6-sol","messages":[{"role":"user","content":"hi"}],"store":false}`},
		{"Anthropic Chat", false, `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"store":false}`},
		{"Chutes Chat", false, `{"model":"chutes-glm-5.2","messages":[{"role":"user","content":"hi"}],"store":false}`},
		{"OpenAI Responses", true, `{"model":"gpt-5-nano","input":"hi","store":false}`},
		{"Azure Responses", true, `{"model":"azure-gpt-5.6-sol","input":"hi","store":false}`},
		{"Anthropic Responses", true, `{"model":"anthropic/claude-sonnet-4-6","input":"hi","store":false}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.responses {
				err = validateResolvedResponses(t, tc.body)
			} else {
				err = validateResolvedChat(t, tc.body)
			}
			if err != nil {
				t.Fatalf("store=false was rejected: %v", err)
			}
		})
	}
}

func TestOpenAIProviderOwnedScalarsReachTheWireUnchanged(t *testing.T) {
	if err := validateNumber(rawJSON(t, `{"temperature":"hot"}`), "temperature"); err == nil || !strings.Contains(err.Error(), "temperature must be a number") {
		t.Fatalf("expected temperature shape error, got %v", err)
	}
	if err := validateInteger(rawJSON(t, `{"top_logprobs":"many"}`), "top_logprobs"); err == nil || !strings.Contains(err.Error(), "top_logprobs must be an integer") {
		t.Fatalf("expected top_logprobs shape error, got %v", err)
	}
	body := `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"temperature":2.01,"top_p":1.01,"frequency_penalty":-2.01,"presence_penalty":2.01,"logprobs":false,"top_logprobs":21,"logit_bias":{"future-token":100.1},"verbosity":"future-verbosity","stop":["a","b","c","d","e"]}`
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("provider-owned OpenAI values were rejected: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	wireBytes, bifrostErr := prepareOpenAIChatBody(
		schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
		bifrostReq.ChatRequest,
		false,
	)
	if bifrostErr != nil {
		t.Fatalf("prepareOpenAIChatBody returned error: %v", bifrostErr)
	}
	var wire map[string]any
	if err := json.Unmarshal(wireBytes, &wire); err != nil {
		t.Fatalf("unmarshal provider request: %v", err)
	}
	if wire["temperature"] != 2.01 || wire["top_p"] != 1.01 ||
		wire["frequency_penalty"] != -2.01 || wire["presence_penalty"] != 2.01 ||
		wire["top_logprobs"] != float64(21) || wire["verbosity"] != "future-verbosity" {
		t.Fatalf("provider-owned values changed on the wire: %s", wireBytes)
	}
	if stops, ok := wire["stop"].([]any); !ok || len(stops) != 5 {
		t.Fatalf("provider-owned stop list changed on the wire: %s", wireBytes)
	}
}

func TestChatPolicyAllowsAnthropicSpecificFieldsForAnthropicDeployments(t *testing.T) {
	err := validateResolvedChat(t, `{
		"model":"anthropic/claude-sonnet-4-6",
		"messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral","ttl":"5m"}}]}],
		"cache_control":{"type":"ephemeral","ttl":"1h"},
		"top_p":0.9,
		"top_k":40,
		"stop_sequences":["END"],
		"context_management":{"edits":[
			{"type":"clear_thinking_20251015","keep":{"type":"thinking_turns","value":2}},
			{"type":"clear_tool_uses_20250919","clear_at_least":{"type":"input_tokens","value":5000},"clear_tool_inputs":["lookup"],"exclude_tools":[],"keep":{"type":"tool_uses","value":3},"trigger":{"type":"input_tokens","value":30000}}
		]},
		"tools":[{"type":"function","function":{"name":"lookup"},"cache_control":{"type":"ephemeral"}}],
		"tool_choice":"required"
	}`)
	if err != nil {
		t.Fatalf("expected Anthropic-specific chat request to pass, got %v", err)
	}
}

func TestAnthropicTaskBudgetValidation(t *testing.T) {
	tests := []struct {
		name                string
		model               string
		taskBudget          string
		want                string
		chatSchemaRejection bool
	}{
		{name: "minimum", model: "anthropic/claude-opus-4-7", taskBudget: `{"type":"tokens","total":20000}`},
		{name: "remaining zero", model: "anthropic/claude-opus-4-8", taskBudget: `{"type":"tokens","total":20000,"remaining":0}`},
		{name: "fable", model: "anthropic/claude-fable-5", taskBudget: `{"type":"tokens","total":20000,"remaining":19000}`},
		{name: "unsupported model", model: "anthropic/claude-sonnet-4-6", taskBudget: `{"type":"tokens","total":20000}`, want: "not supported for this Anthropic model"},
		{name: "not object", model: "anthropic/claude-opus-4-7", taskBudget: `[]`, want: "must be an object", chatSchemaRejection: true},
		{name: "unknown field", model: "anthropic/claude-opus-4-7", taskBudget: `{"type":"tokens","total":20000,"future":true}`, want: "supports only type, total, and remaining"},
		{name: "missing type", model: "anthropic/claude-opus-4-7", taskBudget: `{"total":20000}`, want: "type must be tokens"},
		{name: "wrong type", model: "anthropic/claude-opus-4-7", taskBudget: `{"type":"future","total":20000}`, want: "type must be tokens"},
		{name: "missing total", model: "anthropic/claude-opus-4-7", taskBudget: `{"type":"tokens"}`, want: "total is required"},
		{name: "fractional total", model: "anthropic/claude-opus-4-7", taskBudget: `{"type":"tokens","total":20000.5}`, want: "total must be an integer", chatSchemaRejection: true},
		{name: "small total", model: "anthropic/claude-opus-4-7", taskBudget: `{"type":"tokens","total":19999}`, want: "below the provider minimum"},
		{name: "fractional remaining", model: "anthropic/claude-opus-4-7", taskBudget: `{"type":"tokens","total":20000,"remaining":1.5}`, want: "remaining must be an integer", chatSchemaRejection: true},
		{name: "negative remaining", model: "anthropic/claude-opus-4-7", taskBudget: `{"type":"tokens","total":20000,"remaining":-1}`, want: "remaining must be between zero"},
		{name: "remaining above total", model: "anthropic/claude-opus-4-7", taskBudget: `{"type":"tokens","total":20000,"remaining":20001}`, want: "remaining must be between zero"},
	}
	for _, route := range []struct {
		name       string
		validate   func(*testing.T, string) error
		bodyPrefix string
	}{
		{name: "chat", validate: validateResolvedChat, bodyPrefix: `{"model":%q,"messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16,"task_budget":%s}`},
		{name: "responses", validate: validateResolvedResponses, bodyPrefix: `{"model":%q,"input":"hi","max_output_tokens":16,"task_budget":%s}`},
	} {
		for _, tc := range tests {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				body := fmt.Sprintf(route.bodyPrefix, tc.model, tc.taskBudget)
				err := route.validate(t, body)
				if route.name == "chat" && tc.chatSchemaRejection {
					if err == nil || !strings.Contains(err.Error(), catalog.ErrInvalidJSON.Message) {
						t.Fatalf("expected the Chat schema to reject the task budget, got %v", err)
					}
					return
				}
				if tc.want == "" {
					if err != nil {
						t.Fatalf("expected task budget to pass, got %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("expected %q, got %v", tc.want, err)
				}
			})
		}
	}
}

func TestAnthropicContextManagementValidation(t *testing.T) {
	valid := []struct {
		name    string
		model   string
		payload string
	}{
		{name: "clear tool defaults", model: "anthropic/claude-haiku-4-5", payload: `{"edits":[{"type":"clear_tool_uses_20250919"}]}`},
		{name: "clear tool full", model: "anthropic/claude-opus-5", payload: `{"edits":[{"type":"clear_tool_uses_20250919","clear_at_least":{"type":"input_tokens","value":0},"clear_tool_inputs":["lookup"],"exclude_tools":["preserve"],"keep":{"type":"tool_uses","value":0},"trigger":{"type":"tool_uses","value":1}}]}`},
		{name: "clear thinking string all", model: "anthropic/claude-sonnet-4-6", payload: `{"edits":[{"type":"clear_thinking_20251015","keep":"all"}]}`},
		{name: "clear thinking object all", model: "anthropic/claude-sonnet-4-6", payload: `{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"all"}}]}`},
		{name: "ordered editing strategies", model: "anthropic/claude-opus-5", payload: `{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"thinking_turns","value":1}},{"type":"clear_tool_uses_20250919","clear_tool_inputs":false,"exclude_tools":null}]}`},
		{name: "compaction defaults", model: "anthropic/claude-opus-5", payload: `{"edits":[{"type":"compact_20260112"}]}`},
		{name: "compaction full", model: "anthropic/claude-sonnet-4-6", payload: `{"edits":[{"type":"compact_20260112","trigger":{"type":"input_tokens","value":50000},"pause_after_compaction":true,"instructions":"Preserve decisions"}]}`},
		{name: "compaction null option", model: "anthropic/claude-sonnet-4-6", payload: `{"edits":[{"type":"compact_20260112","pause_after_compaction":null}]}`},
		{name: "Azure compaction", model: "azure/claude-opus-4-8", payload: `{"edits":[{"type":"compact_20260112","trigger":null,"instructions":null}]}`},
	}
	invalid := []struct {
		name    string
		model   string
		payload string
		want    string
	}{
		{name: "top-level array", payload: `[]`},
		{name: "top-level unknown field", payload: `{"edits":[{"type":"clear_tool_uses_20250919"}],"future":true}`, want: "supports only edits"},
		{name: "missing edits", payload: `{}`, want: "non-empty array"},
		{name: "null edits", payload: `{"edits":null}`, want: "non-empty array"},
		{name: "empty edits", payload: `{"edits":[]}`, want: "non-empty array"},
		{name: "non-object edit", payload: `{"edits":["compact_20260112"]}`},
		{name: "missing edit type", payload: `{"edits":[{}]}`, want: "type is required"},
		{name: "unknown edit type", payload: `{"edits":[{"type":"future_edit"}]}`, want: "type is not supported"},
		{name: "duplicate edit", payload: `{"edits":[{"type":"clear_tool_uses_20250919"},{"type":"clear_tool_uses_20250919"}]}`, want: "must be unique"},
		{name: "clear thinking not first", payload: `{"edits":[{"type":"clear_tool_uses_20250919"},{"type":"clear_thinking_20251015"}]}`, want: "must be the first"},
		{name: "clear thinking unknown field", payload: `{"edits":[{"type":"clear_thinking_20251015","future":true}]}`, want: "supports only type and keep"},
		{name: "clear thinking null keep", payload: `{"edits":[{"type":"clear_thinking_20251015","keep":null}]}`, want: "must be all or an object"},
		{name: "clear thinking wrong string", payload: `{"edits":[{"type":"clear_thinking_20251015","keep":"recent"}]}`, want: "must be all or an object"},
		{name: "clear thinking wrong object type", payload: `{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"turns","value":1}}]}`, want: "must be all or thinking_turns"},
		{name: "clear thinking all extra field", payload: `{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"all","value":1}}]}`, want: "supports no other fields"},
		{name: "clear thinking zero turns", payload: `{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"thinking_turns","value":0}}]}`, want: "positive integer"},
		{name: "clear thinking fractional turns", payload: `{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"thinking_turns","value":1.5}}]}`},
		{name: "clear tool unknown field", payload: `{"edits":[{"type":"clear_tool_uses_20250919","future":true}]}`, want: "contains unsupported fields"},
		{name: "clear at least wrong type", payload: `{"edits":[{"type":"clear_tool_uses_20250919","clear_at_least":{"type":"tool_uses","value":1}}]}`, want: "type is not supported"},
		{name: "clear at least missing value", payload: `{"edits":[{"type":"clear_tool_uses_20250919","clear_at_least":{"type":"input_tokens"}}]}`, want: "below the provider minimum"},
		{name: "clear inputs wrong type", payload: `{"edits":[{"type":"clear_tool_uses_20250919","clear_tool_inputs":{"lookup":true}}]}`, want: "boolean or an array"},
		{name: "clear inputs empty name", payload: `{"edits":[{"type":"clear_tool_uses_20250919","clear_tool_inputs":[""]}]}`, want: "boolean or an array"},
		{name: "exclude tools duplicate", payload: `{"edits":[{"type":"clear_tool_uses_20250919","exclude_tools":["lookup","lookup"]}]}`, want: "must not contain duplicate"},
		{name: "clear tool keep null", payload: `{"edits":[{"type":"clear_tool_uses_20250919","keep":null}]}`, want: "must be an object"},
		{name: "clear tool trigger fractional", payload: `{"edits":[{"type":"clear_tool_uses_20250919","trigger":{"type":"tool_uses","value":1.5}}]}`},
		{name: "compaction unknown field", payload: `{"edits":[{"type":"compact_20260112","future":true}]}`, want: "contains unsupported fields"},
		{name: "compaction unsupported model", model: "anthropic/claude-haiku-4-5", payload: `{"edits":[{"type":"compact_20260112"}]}`, want: "not supported for this Anthropic model"},
		{name: "compaction trigger wrong type", payload: `{"edits":[{"type":"compact_20260112","trigger":{"type":"tool_uses","value":50000}}]}`, want: "type is not supported"},
		{name: "compaction trigger below minimum", payload: `{"edits":[{"type":"compact_20260112","trigger":{"type":"input_tokens","value":49999}}]}`, want: "below the provider minimum"},
		{name: "compaction instructions wrong type", payload: `{"edits":[{"type":"compact_20260112","instructions":true}]}`, want: "must be a string or null"},
	}

	for _, route := range []struct {
		name     string
		validate func(*testing.T, string) error
		format   string
	}{
		{name: "chat", validate: validateResolvedChat, format: `{"model":%q,"messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16,"context_management":%s}`},
		{name: "responses", validate: validateResolvedResponses, format: `{"model":%q,"input":"hi","max_output_tokens":16,"context_management":%s}`},
	} {
		for _, tc := range valid {
			t.Run(route.name+"/valid/"+tc.name, func(t *testing.T) {
				if err := route.validate(t, fmt.Sprintf(route.format, tc.model, tc.payload)); err != nil {
					t.Fatalf("valid context management was rejected: %v", err)
				}
			})
		}
		for _, tc := range invalid {
			t.Run(route.name+"/invalid/"+tc.name, func(t *testing.T) {
				model := tc.model
				if model == "" {
					model = "anthropic/claude-opus-5"
				}
				err := route.validate(t, fmt.Sprintf(route.format, model, tc.payload))
				if err == nil {
					t.Fatal("invalid context management was accepted")
				}
				if tc.want != "" && !strings.Contains(err.Error(), tc.want) && !strings.Contains(err.Error(), catalog.ErrInvalidJSON.Message) {
					t.Fatalf("expected %q, got %v", tc.want, err)
				}
			})
		}
	}
}

func TestEveryAnthropicDeploymentEnforcesTaskBudgetModelSupport(t *testing.T) {
	type matrixDeployment struct {
		RouteIDs []string `json:"routeIds"`
	}
	type matrixRoute struct {
		Interfaces []string `json:"interfaces"`
		ProviderID string   `json:"providerId"`
	}
	public, ok := catalog.PublicCatalogPayload()
	if !ok {
		t.Fatal("compiled public catalog is unavailable")
	}
	deployments := map[string]matrixDeployment{}
	routes := map[string]matrixRoute{}
	if err := json.Unmarshal(public.Graph["deployments"], &deployments); err != nil {
		t.Fatalf("decode catalog deployments: %v", err)
	}
	if err := json.Unmarshal(public.Graph["routes"], &routes); err != nil {
		t.Fatalf("decode catalog routes: %v", err)
	}

	allowed := 0
	rejected := 0
	for deploymentID, deploymentSpec := range deployments {
		for _, routeID := range deploymentSpec.RouteIDs {
			routeSpec := routes[routeID]
			if routeSpec.ProviderID != string(schemas.Anthropic) {
				continue
			}
			for _, interfaceName := range routeSpec.Interfaces {
				var (
					body  string
					path  string
					route catalog.Route
				)
				switch interfaceName {
				case "chat_completions":
					path = "/v1/chat/completions"
					route = catalog.RouteChat
					body = fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16,"task_budget":{"type":"tokens","total":20000}}`, deploymentID)
				case "responses":
					path = "/v1/responses"
					route = catalog.RouteResponses
					body = fmt.Sprintf(`{"model":%q,"input":"hi","max_output_tokens":16,"task_budget":{"type":"tokens","total":20000}}`, deploymentID)
				default:
					t.Fatalf("%s: unsupported Anthropic interface %q", routeID, interfaceName)
				}
				resolvedDeployment, active := testDeploymentForRoute(schemas.Anthropic, deploymentID, route)
				if !active {
					continue
				}
				model := strings.ToLower(resolvedDeployment.Upstream.Model)
				wantAllowed := strings.Contains(model, "opus-4-7") ||
					strings.Contains(model, "opus-4-8") ||
					strings.Contains(model, "opus-5") ||
					strings.Contains(model, "fable") ||
					strings.Contains(model, "mythos")
				t.Run(deploymentID+"/"+interfaceName, func(t *testing.T) {
					resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: path, Body: []byte(body)})
					if err != nil {
						t.Fatalf("ResolveRequest returned error: %v", err)
					}
					state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
					err = state.Adapter.ValidateRequest(state)
					if wantAllowed {
						allowed++
						if err != nil {
							t.Fatalf("supported task budget model %q was rejected: %v", model, err)
						}
						return
					}
					rejected++
					if err == nil || !strings.Contains(err.Error(), "task_budget is not supported for this Anthropic model") {
						t.Fatalf("unsupported task budget model %q was not rejected correctly: %v", model, err)
					}
				})
			}
		}
	}
	if allowed == 0 || rejected == 0 {
		t.Fatalf("incomplete task budget model matrix: allowed=%d rejected=%d", allowed, rejected)
	}
}

func TestEveryAnthropicWireDeploymentEnforcesCompactionModelSupport(t *testing.T) {
	type matrixDeployment struct {
		RouteIDs []string `json:"routeIds"`
	}
	type matrixRoute struct {
		Interfaces []string `json:"interfaces"`
		ProviderID string   `json:"providerId"`
	}
	public, ok := catalog.PublicCatalogPayload()
	if !ok {
		t.Fatal("compiled public catalog is unavailable")
	}
	deployments := map[string]matrixDeployment{}
	routes := map[string]matrixRoute{}
	if err := json.Unmarshal(public.Graph["deployments"], &deployments); err != nil {
		t.Fatalf("decode catalog deployments: %v", err)
	}
	if err := json.Unmarshal(public.Graph["routes"], &routes); err != nil {
		t.Fatalf("decode catalog routes: %v", err)
	}

	allowed := 0
	rejected := 0
	for deploymentID, deploymentSpec := range deployments {
		for _, routeID := range deploymentSpec.RouteIDs {
			routeSpec := routes[routeID]
			provider := schemas.ModelProvider(routeSpec.ProviderID)
			if provider != schemas.Anthropic && routeID != "azure-anthropic-messages" {
				continue
			}
			for _, interfaceName := range routeSpec.Interfaces {
				var (
					body  string
					path  string
					route catalog.Route
				)
				switch interfaceName {
				case "chat_completions":
					path = "/v1/chat/completions"
					route = catalog.RouteChat
					body = fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16,"context_management":{"edits":[{"type":"compact_20260112"}]}}`, deploymentID)
				case "responses":
					path = "/v1/responses"
					route = catalog.RouteResponses
					body = fmt.Sprintf(`{"model":%q,"input":"hi","max_output_tokens":16,"context_management":{"edits":[{"type":"compact_20260112"}]}}`, deploymentID)
				default:
					t.Fatalf("%s: unsupported Anthropic-family interface %q", routeID, interfaceName)
				}
				resolvedDeployment, active := testDeploymentForRoute(provider, deploymentID, route)
				if !active {
					continue
				}
				if provider == schemas.Azure && !strings.EqualFold(resolvedDeployment.Upstream.ModelFormat, "Anthropic") {
					t.Fatalf("%s unexpectedly uses %q wire format on %s", deploymentID, resolvedDeployment.Upstream.ModelFormat, routeID)
				}
				wantAllowed := anthropicModelSupportsCompaction(resolvedDeployment.Upstream.Model)
				t.Run(deploymentID+"/"+interfaceName, func(t *testing.T) {
					resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: path, Body: []byte(body)})
					if err != nil {
						t.Fatalf("ResolveRequest returned error: %v", err)
					}
					state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
					err = state.Adapter.ValidateRequest(state)
					if wantAllowed {
						allowed++
						if err != nil {
							t.Fatalf("supported compaction model %q was rejected: %v", resolvedDeployment.Upstream.Model, err)
						}
						return
					}
					rejected++
					if err == nil || !strings.Contains(err.Error(), "compact_20260112 is not supported for this Anthropic model") {
						t.Fatalf("unsupported compaction model %q was not rejected correctly: %v", resolvedDeployment.Upstream.Model, err)
					}
				})
			}
		}
	}
	if allowed == 0 || rejected == 0 {
		t.Fatalf("incomplete compaction model matrix: allowed=%d rejected=%d", allowed, rejected)
	}
}

func TestAnthropicContextManagementReachesBothProviderWireFormatsExactly(t *testing.T) {
	contextManagement := `{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"thinking_turns","value":2}},{"type":"clear_tool_uses_20250919","clear_at_least":{"type":"input_tokens","value":5000},"clear_tool_inputs":["lookup"],"exclude_tools":["preserve"],"keep":{"type":"tool_uses","value":3},"trigger":{"type":"input_tokens","value":30000}}]}`
	for _, tc := range []struct {
		name string
		path string
		body string
	}{
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16,"context_management":` + contextManagement + `}`},
		{name: "responses", path: "/v1/responses", body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_output_tokens":16,"context_management":` + contextManagement + `}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: tc.path, Body: []byte(tc.body)})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			request, err := resolution.ToBifrost(ctx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			var wire []byte
			var bifrostErr *schemas.BifrostError
			if request.ChatRequest != nil {
				wire, bifrostErr = anthropicprovider.BuildAnthropicChatRequestBody(ctx, request.ChatRequest, anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic})
			} else {
				wire, bifrostErr = anthropicprovider.BuildAnthropicResponsesRequestBody(ctx, request.ResponsesRequest, anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic})
			}
			if bifrostErr != nil {
				t.Fatalf("build Anthropic provider request: %v", bifrostErr)
			}
			if strings.Contains(string(wire), "clear_at_last") {
				t.Fatalf("provider wire used obsolete clear_at_last field: %s", wire)
			}
			var decoded struct {
				ContextManagement struct {
					Edits []map[string]any `json:"edits"`
				} `json:"context_management"`
			}
			if err := json.Unmarshal(wire, &decoded); err != nil {
				t.Fatalf("decode Anthropic provider request: %v\n%s", err, wire)
			}
			if len(decoded.ContextManagement.Edits) != 2 {
				t.Fatalf("context management edits were lost: %s", wire)
			}
			clearThinking := decoded.ContextManagement.Edits[0]
			keepThinking, _ := clearThinking["keep"].(map[string]any)
			if clearThinking["type"] != "clear_thinking_20251015" || keepThinking["type"] != "thinking_turns" || keepThinking["value"] != float64(2) {
				t.Fatalf("clear-thinking edit changed on provider wire: %s", wire)
			}
			clearTools := decoded.ContextManagement.Edits[1]
			clearAtLeast, _ := clearTools["clear_at_least"].(map[string]any)
			keepTools, _ := clearTools["keep"].(map[string]any)
			trigger, _ := clearTools["trigger"].(map[string]any)
			clearInputs, _ := clearTools["clear_tool_inputs"].([]any)
			excluded, _ := clearTools["exclude_tools"].([]any)
			if clearTools["type"] != "clear_tool_uses_20250919" ||
				clearAtLeast["type"] != "input_tokens" || clearAtLeast["value"] != float64(5000) ||
				keepTools["type"] != "tool_uses" || keepTools["value"] != float64(3) ||
				trigger["type"] != "input_tokens" || trigger["value"] != float64(30000) ||
				len(clearInputs) != 1 || clearInputs[0] != "lookup" || len(excluded) != 1 || excluded[0] != "preserve" {
				t.Fatalf("clear-tool edit changed on provider wire: %s", wire)
			}
		})
	}
}

func TestChatPolicyAllowsDeclaredFunctionToolChoice(t *testing.T) {
	for _, body := range []string{
		`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tool_choice":"auto"}`,
		`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tool_choice":"none"}`,
		`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":"required"}`,
		`{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":"required"}`,
		`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`,
		`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"parallel_tool_calls":false,"tool_choice":{"type":"function","function":{"name":"lookup"}}}`,
		`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`,
		`{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`,
	} {
		if err := validateResolvedChat(t, body); err != nil {
			t.Fatalf("expected declared tool choice to pass, got %v\nbody=%s", err, body)
		}
	}
}

func TestClientToolDefinitionLimits(t *testing.T) {
	chatTools := make([]map[string]any, maxClientTools)
	responsesTools := make([]map[string]any, maxClientTools)
	for index := 0; index < maxClientTools; index++ {
		name := fmt.Sprintf("tool_%d", index)
		chatTools[index] = map[string]any{"type": "function", "function": map[string]any{"name": name}}
		responsesTools[index] = map[string]any{"type": "function", "name": name}
	}
	chatRaw, err := json.Marshal(chatTools)
	if err != nil {
		t.Fatalf("marshal Chat tools: %v", err)
	}
	if _, err := validateChatTools(chatRaw); err != nil {
		t.Fatalf("128 Chat tools should pass: %v", err)
	}

	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi"}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	responsesRaw, err := json.Marshal(responsesTools)
	if err != nil {
		t.Fatalf("marshal Responses tools: %v", err)
	}
	if _, err := parseResponsesTools(state, responsesRaw); err != nil {
		t.Fatalf("128 Responses tools should pass: %v", err)
	}

	chatTools = append(chatTools, map[string]any{"type": "function", "function": map[string]any{"name": "overflow"}})
	chatRaw, _ = json.Marshal(chatTools)
	if _, err := validateChatTools(chatRaw); err == nil || !strings.Contains(err.Error(), "at most 128") {
		t.Fatalf("129 Chat tools should fail closed, got %v", err)
	}
	responsesTools = append(responsesTools, map[string]any{"type": "function", "name": "overflow"})
	responsesRaw, _ = json.Marshal(responsesTools)
	if _, err := parseResponsesTools(state, responsesRaw); err == nil || !strings.Contains(err.Error(), "at most 128") {
		t.Fatalf("129 Responses tools should fail closed, got %v", err)
	}
}

func TestChatClientToolContinuationReachesEveryProviderWireLosslessly(t *testing.T) {
	tests := []struct {
		anthropicWire bool
		model         string
		name          string
	}{
		{name: "OpenAI", model: "gpt-5.5"},
		{name: "Azure OpenAI", model: "azure-gpt-5.6-sol"},
		{name: "Anthropic", model: "anthropic/claude-sonnet-4-6", anthropicWire: true},
		{name: "Azure Claude", model: "azure-claude-sonnet-4-6", anthropicWire: true},
		{name: "Chutes", model: "chutes-glm-5.2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"find the record"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"key\":\"value\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"record-result"},{"role":"user","content":"continue"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`, tc.model)
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
			request, err := resolution.ToBifrost(ctx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			wireBody := preparedProviderBody(t, ctx, request.ChatRequest)
			var wire map[string]any
			if err := json.Unmarshal(wireBody, &wire); err != nil {
				t.Fatalf("decode prepared provider body: %v\n%s", err, wireBody)
			}
			messages, ok := wire["messages"].([]any)
			if !ok || len(messages) < 3 {
				t.Fatalf("provider messages were not built: %#v\n%s", wire["messages"], wireBody)
			}
			if !tc.anthropicWire {
				assistant, assistantOK := messages[1].(map[string]any)
				results, resultsOK := messages[2].(map[string]any)
				calls, callsOK := assistant["tool_calls"].([]any)
				if !assistantOK || !callsOK || len(calls) != 1 {
					t.Fatalf("assistant tool call was lost: %#v\n%s", assistant, wireBody)
				}
				call, callOK := calls[0].(map[string]any)
				function, functionOK := call["function"].(map[string]any)
				if !callOK || !functionOK || call["id"] != "call_1" || call["type"] != "function" || function["name"] != "lookup" || function["arguments"] != `{"key":"value"}` {
					t.Fatalf("tool call changed on OpenAI-format wire: %#v\n%s", call, wireBody)
				}
				if _, exists := call["index"]; exists {
					t.Fatalf("stream-only tool-call index leaked to OpenAI-format wire: %#v\n%s", call, wireBody)
				}
				if !resultsOK || results["role"] != "tool" || results["tool_call_id"] != "call_1" || results["content"] != "record-result" {
					t.Fatalf("tool result changed on OpenAI-format wire: %#v\n%s", results, wireBody)
				}
				return
			}

			var toolUse, toolResult map[string]any
			for _, rawMessage := range messages {
				message, ok := rawMessage.(map[string]any)
				if !ok {
					continue
				}
				blocks, ok := message["content"].([]any)
				if !ok {
					continue
				}
				for _, rawBlock := range blocks {
					block, ok := rawBlock.(map[string]any)
					if !ok {
						continue
					}
					switch block["type"] {
					case "tool_use":
						toolUse = block
					case "tool_result":
						toolResult = block
					}
				}
			}
			if toolUse == nil || toolUse["id"] != "call_1" || toolUse["name"] != "lookup" || !reflect.DeepEqual(toolUse["input"], map[string]any{"key": "value"}) {
				t.Fatalf("tool call changed on Anthropic-format wire: %#v\n%s", toolUse, wireBody)
			}
			if toolResult == nil || toolResult["tool_use_id"] != "call_1" || toolResult["content"] != "record-result" {
				t.Fatalf("tool result changed on Anthropic-format wire: %#v\n%s", toolResult, wireBody)
			}
		})
	}
}

func TestChatSignedReasoningHistoryReachesAnthropicFamilyWireLosslessly(t *testing.T) {
	for _, tc := range []struct {
		model string
		name  string
	}{
		{name: "Anthropic", model: "anthropic/claude-sonnet-4-6"},
		{name: "Azure Claude", model: "azure-claude-sonnet-4-6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"first"},{"role":"assistant","content":"answer","reasoning":"visible thought\n","reasoning_details":[{"index":0,"type":"reasoning.text","text":"visible thought","signature":"signed-thought"},{"index":1,"type":"reasoning.encrypted","data":"opaque-redacted"}]},{"role":"user","content":"continue"}],"reasoning":{"effort":"high"}}`, tc.model)
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
			request, err := resolution.ToBifrost(ctx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			wireBody := preparedProviderBody(t, ctx, request.ChatRequest)
			if !strings.Contains(string(wireBody), `"type":"thinking"`) || !strings.Contains(string(wireBody), `"thinking":"visible thought"`) || !strings.Contains(string(wireBody), `"signature":"signed-thought"`) || !strings.Contains(string(wireBody), `"type":"redacted_thinking"`) || !strings.Contains(string(wireBody), `"data":"opaque-redacted"`) {
				t.Fatalf("signed reasoning history changed on Anthropic-family wire: %s", wireBody)
			}
		})
	}
}

func TestAnthropicMidConversationSystemMessagesReachProviderWireInPlace(t *testing.T) {
	tests := []struct {
		body string
		name string
		path string
	}{
		{
			name: "Opus Chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"first"},{"role":"system","content":"new policy"},{"role":"assistant","content":"answer"},{"role":"user","content":"continue"}]}`,
		},
		{
			name: "Opus Responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-opus-4-8","input":[{"role":"user","content":"first"},{"role":"system","content":"new policy"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer","annotations":[],"logprobs":[]}]},{"role":"user","content":"continue"}]}`,
		},
		{
			name: "Sonnet 5 Chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-5","messages":[{"role":"user","content":"first"},{"role":"system","content":"new policy"},{"role":"assistant","content":"answer"},{"role":"user","content":"continue"}]}`,
		},
		{
			name: "Sonnet 5 Responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-5","input":[{"role":"user","content":"first"},{"role":"system","content":"new policy"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer","annotations":[],"logprobs":[]}]},{"role":"user","content":"continue"}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: tc.path, Body: []byte(tc.body)})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
			request, err := resolution.ToBifrost(ctx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			var wire map[string]any
			var wireBody []byte
			if request.ChatRequest != nil {
				wireBody = preparedProviderBody(t, ctx, request.ChatRequest)
			} else {
				wireBody = preparedProviderBody(t, ctx, request.ResponsesRequest)
			}
			if err := json.Unmarshal(wireBody, &wire); err != nil {
				t.Fatalf("decode provider request: %v\n%s", err, wireBody)
			}
			messages, ok := wire["messages"].([]any)
			if !ok || len(messages) != 4 {
				t.Fatalf("provider message sequence changed: %#v\n%s", wire["messages"], wireBody)
			}
			wantRoles := []string{"user", "system", "assistant", "user"}
			for index, want := range wantRoles {
				message, ok := messages[index].(map[string]any)
				if !ok || message["role"] != want {
					t.Fatalf("provider message %d role = %#v, want %q\n%s", index, message["role"], want, wireBody)
				}
			}
		})
	}
}

func TestChatStopStringShorthandNormalizesToBifrostStopArray(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stop":"END"}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	bifrostReq, err := resolution.ToBifrost(bifrostCtx)
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if got := bifrostReq.ChatRequest.Params.Stop; len(got) != 1 || got[0] != "END" {
		t.Fatalf("expected stop string shorthand to normalize to [END], got %#v", got)
	}
}

func TestChatResponseFormatReachesProviderWireRequest(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "openai json schema",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"type":"object","properties":{"ok":{"type":"boolean"}}},"strict":true}}}`,
		},
		{
			name: "anthropic json schema",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			bifrostReq, err := resolution.ToBifrost(bifrostCtx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			switch resolution.Provider {
			case schemas.OpenAI:
				wire := openaiprovider.ToOpenAIChatRequest(bifrostCtx, bifrostReq.ChatRequest)
				wireBytes, err := json.Marshal(wire)
				if err != nil {
					t.Fatalf("marshal OpenAI chat request: %v", err)
				}
				if !strings.Contains(string(wireBytes), `"response_format"`) || !strings.Contains(string(wireBytes), `"strict":true`) {
					t.Fatalf("expected OpenAI chat response_format to reach wire request, got %s", wireBytes)
				}
			case schemas.Anthropic:
				wire, err := anthropicprovider.ToAnthropicChatRequest(bifrostCtx, bifrostReq.ChatRequest)
				if err != nil {
					t.Fatalf("ToAnthropicChatRequest returned error: %v", err)
				}
				if len(wire.Tools) != 0 {
					t.Fatalf("expected direct Anthropic structured output to avoid tool emulation, got %#v", wire.Tools)
				}
				if wire.OutputConfig == nil || len(wire.OutputConfig.Format) == 0 {
					t.Fatalf("expected Anthropic output_config.format, got %#v", wire.OutputConfig)
				}
				var outputFormat map[string]any
				if err := json.Unmarshal(wire.OutputConfig.Format, &outputFormat); err != nil {
					t.Fatalf("decode Anthropic output_config.format: %v", err)
				}
				if outputFormat["type"] != "json_schema" || outputFormat["schema"] == nil {
					t.Fatalf("unexpected Anthropic output_config.format %#v", outputFormat)
				}
				if _, hasStrict := outputFormat["strict"]; hasStrict {
					t.Fatalf("Anthropic output_config.format must not contain unsupported strict flag: %#v", outputFormat)
				}
			}
		})
	}
}

func TestChatPolicyRejectsUnsupportedCacheControlPositions(t *testing.T) {
	err := validateResolvedChat(t, `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","cache_control":{"type":"ephemeral"},"content":"hi"}]}`)
	if err == nil || !strings.Contains(err.Error(), "messages[0].cache_control is not supported") {
		t.Fatalf("expected message-level cache_control rejection, got %v", err)
	}
}

func TestAnthropicCacheControlRejectsUnknownKeys(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"ephemeral","ttl":"1h","scope":"future-provider-owned"},"max_completion_tokens":16}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","cache_control":{"type":"ephemeral","ttl":"1h","scope":"future-provider-owned"},"max_output_tokens":16}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tc.path,
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err == nil ||
				!strings.Contains(err.Error(), "supports only type and ttl") {
				t.Fatalf("unknown cache control was accepted: %v", err)
			}
		})
	}
}

func TestAnthropicCachePrewarmAllowsZeroOutputTokens(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat top-level cache_control",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"ephemeral","ttl":"5m"},"max_completion_tokens":0}`,
		},
		{
			name: "chat content cache_control max_tokens alias",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral","ttl":"1h"}}]}],"max_tokens":0}`,
		},
		{
			name: "responses top-level cache_control",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","cache_control":{"type":"ephemeral","ttl":"5m"},"max_output_tokens":0}`,
		},
		{
			name: "responses input cache_control",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral","ttl":"1h"}}]}],"max_output_tokens":0}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tc.path,
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			if resolution.OutputTokenLimit() != 0 {
				t.Fatalf("expected cache-prewarm output limit 0, got %d", resolution.OutputTokenLimit())
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			switch tc.path {
			case "/v1/chat/completions":
				if bifrostReq.ChatRequest == nil || bifrostReq.ChatRequest.Params == nil || bifrostReq.ChatRequest.Params.MaxCompletionTokens == nil || *bifrostReq.ChatRequest.Params.MaxCompletionTokens != 0 {
					t.Fatalf("expected Bifrost chat max_completion_tokens=0, got %#v", bifrostReq.ChatRequest)
				}
			case "/v1/responses":
				if bifrostReq.ResponsesRequest == nil || bifrostReq.ResponsesRequest.Params == nil || bifrostReq.ResponsesRequest.Params.MaxOutputTokens == nil || *bifrostReq.ResponsesRequest.Params.MaxOutputTokens != 0 {
					t.Fatalf("expected Bifrost responses max_output_tokens=0, got %#v", bifrostReq.ResponsesRequest)
				}
			}
		})
	}
}

func TestZeroOutputTokensRequireAllowedAnthropicCacheControl(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat no cache_control",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":0}`,
		},
		{
			name: "chat schema property named cache_control",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}}],"max_completion_tokens":0}`,
		},
		{
			name: "responses no cache_control",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_output_tokens":0}`,
		},
		{
			name: "responses schema property named cache_control",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}],"max_output_tokens":0}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tc.path,
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error before adapter validation: %v", err)
			}
			if resolution.OutputTokenLimit() != 0 {
				t.Fatalf("expected catalog to preserve zero output cap, got %d", resolution.OutputTokenLimit())
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			err = state.Adapter.ValidateRequest(state)
			if err == nil || !strings.Contains(err.Error(), "Parameter exceeds catalog limit") {
				t.Fatalf("expected zero output cap rejection, got %v", err)
			}
		})
	}
}

func TestAnthropicFastDeploymentUsesModelSlugAndStandardTier(t *testing.T) {
	for _, body := range []string{
		`{"model":"anthropic/anthropic-claude-opus-4-8-fast","messages":[{"role":"user","content":"hi"}]}`,
		`{"model":"anthropic/anthropic-claude-opus-4-8-fast","messages":[{"role":"user","content":"hi"}],"service_tier":"standard_only"}`,
	} {
		resolution, err := catalog.ResolveRequest(catalog.RequestInput{
			Method: "POST",
			Path:   "/v1/chat/completions",
			Body:   []byte(body),
		})
		if err != nil {
			t.Fatalf("ResolveRequest returned error: %v", err)
		}
		if resolution.Deployment.ID != "anthropic-claude-opus-4-8-fast" || resolution.Model != "claude-opus-4-8" {
			t.Fatalf("unexpected fast deployment resolution: %#v", resolution)
		}
		state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
		if err := state.Adapter.ValidateRequest(state); err != nil {
			t.Fatalf("ValidateRequest returned error: %v", err)
		}
		if err := state.Adapter.SanitizeRequest(state); err != nil {
			t.Fatalf("SanitizeRequest returned error: %v", err)
		}
		bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
		if err != nil {
			t.Fatalf("ToBifrost returned error: %v", err)
		}
		if got := bifrostReq.ChatRequest.Params.Speed; got == nil || *got != "fast" {
			t.Fatalf("expected fast deployment to set typed speed, got %#v", got)
		}
		if bifrostReq.ChatRequest.Params.ServiceTier == nil || *bifrostReq.ChatRequest.Params.ServiceTier != schemas.BifrostServiceTierDefault {
			t.Fatalf("expected fast deployment to imply the standard service tier, got %#v", bifrostReq.ChatRequest.Params.ServiceTier)
		}
	}
}

func TestAnthropicUSDeploymentSetsInferenceGeoInternally(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/anthropic-claude-opus-4-8-fast-us","messages":[{"role":"user","content":"hi"}]}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.ID != "anthropic-claude-opus-4-8-fast-us" || resolution.Deployment.Upstream.InferenceGeo != "us" {
		t.Fatalf("unexpected US deployment resolution: %#v", resolution.Deployment)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if got := bifrostReq.ChatRequest.Params.Speed; got == nil || *got != "fast" {
		t.Fatalf("expected fast US deployment to set typed speed, got %#v", got)
	}
	if got := bifrostReq.ChatRequest.Params.ExtraParams["inference_geo"]; got != "us" {
		t.Fatalf("expected US deployment to set inference_geo internally, got %#v", bifrostReq.ChatRequest.Params.ExtraParams)
	}
	if bifrostReq.ChatRequest.Params.ServiceTier == nil || *bifrostReq.ChatRequest.Params.ServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("expected US standard deployment to imply Bifrost default tier, got %#v", bifrostReq.ChatRequest.Params.ServiceTier)
	}
}

func TestUnknownCompatibilityFieldsCannotChangeExecutionOrReachProvider(t *testing.T) {
	for _, item := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi","audio":null,"image_url":null,"sdk_extension":null}],"speed":"fast","inference_geo":"us","mcp_servers":[{"url":"https://example.com"}],"include_server_side_tool_invocations":true,"sdk_trace":{"id":"trace_1"},"user":"caller","safety_identifier":"caller","audio":null,"function_call":null,"functions":[],"fallbacks":[],"container":null,"modalities":[],"prompt_cache_isolation_key":"","store":null,"stream_options":null}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-opus-4-8","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi","image_url":null,"sdk_extension":null}],"sdk_extension":null}],"max_output_tokens":16,"speed":"fast","inference_geo":"us","mcp_servers":[{"url":"https://example.com"}],"include_server_side_tool_invocations":true,"sdk_trace":{"id":"trace_1"},"user":"caller","safety_identifier":"caller","background":false,"conversation":null,"previous_response_id":"","fallbacks":[],"container":null,"store":null,"stream_options":null}`,
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: item.path, Body: []byte(item.body)})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			if resolution.Deployment.ID != "anthropic-claude-opus-4-8" {
				t.Fatalf("ignored fields changed deployment: %s", resolution.Deployment.ID)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			request, err := resolution.ToBifrost(ctx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, request.RequestType)
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			var wire []byte
			if request.ChatRequest != nil {
				wire = preparedProviderBody(t, ctx, request.ChatRequest)
			} else {
				wire = preparedProviderBody(t, ctx, request.ResponsesRequest)
			}
			var payload map[string]any
			if err := json.Unmarshal(wire, &payload); err != nil {
				t.Fatalf("decode provider body: %v", err)
			}
			if payload["inference_geo"] == "us" {
				t.Fatalf("client inference_geo changed provider execution: %s", wire)
			}
			if payload["speed"] == "fast" {
				t.Fatalf("client speed changed provider execution: %s", wire)
			}
			for _, field := range []string{
				"mcp_servers", "include_server_side_tool_invocations", "sdk_trace",
				"user", "safety_identifier", "audio", "function_call", "functions", "fallbacks", "container",
				"background", "conversation", "previous_response_id",
			} {
				if _, exists := payload[field]; exists {
					t.Fatalf("ignored field %s reached provider: %s", field, wire)
				}
			}
		})
	}
}

func TestAnthropicOutboundServiceTierMapping(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want string
	}{
		{
			name: "chat auto",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}]}`,
			want: "standard_only",
		},
		{
			name: "chat default",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"default"}`,
			want: "standard_only",
		},
		{
			name: "chat standard",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"standard"}`,
			want: "standard_only",
		},
		{
			name: "chat standard only",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"standard_only"}`,
			want: "standard_only",
		},
		{
			name: "responses auto",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_output_tokens":16}`,
			want: "standard_only",
		},
		{
			name: "responses default",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","service_tier":"default","max_output_tokens":16}`,
			want: "standard_only",
		},
		{
			name: "responses standard only",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","service_tier":"standard_only","max_output_tokens":16}`,
			want: "standard_only",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   item.path,
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			bifrostReq, err := resolution.ToBifrost(bifrostCtx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}

			switch item.path {
			case "/v1/chat/completions":
				anthropicReq, err := anthropicprovider.ToAnthropicChatRequest(bifrostCtx, bifrostReq.ChatRequest)
				if err != nil {
					t.Fatalf("ToAnthropicChatRequest returned error: %v", err)
				}
				if anthropicReq.ServiceTier == nil || *anthropicReq.ServiceTier != item.want {
					t.Fatalf("expected Anthropic chat service_tier %q, got %#v", item.want, anthropicReq.ServiceTier)
				}
			case "/v1/responses":
				body, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(bifrostCtx, bifrostReq.ResponsesRequest, anthropicprovider.AnthropicRequestBuildConfig{
					Provider:    schemas.Anthropic,
					IsStreaming: bifrostReq.RequestType == schemas.ResponsesStreamRequest,
				})
				if bifrostErr != nil {
					t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
				}
				var payload struct {
					ServiceTier string `json:"service_tier"`
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("failed to decode Anthropic Responses request body: %v\n%s", err, body)
				}
				if payload.ServiceTier != item.want {
					t.Fatalf("expected Anthropic Responses service_tier %q, got %q in %s", item.want, payload.ServiceTier, body)
				}
			}
		})
	}
}

func TestAnthropicRejectsUncatalogedServiceTiers(t *testing.T) {
	for _, tier := range []string{"auto", "priority", "flex"} {
		t.Run(tier, func(t *testing.T) {
			_, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(`{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"` + tier + `"}`),
			})
			if err == nil {
				t.Fatalf("expected Anthropic service_tier %q to fail closed", tier)
			}
		})
	}
}

func TestChatPolicySanitizesMetadataBeforeUpstream(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"metadata":{"tenant":"test"}}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if bifrostReq.ChatRequest.Params.Metadata != nil {
		t.Fatalf("expected metadata to be sanitized before upstream, got %#v", bifrostReq.ChatRequest.Params.Metadata)
	}
}

func TestSanitizeRequestForcesChatStreamUsage(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"include_usage":false}}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if bifrostReq.ChatRequest.Params.StreamOptions == nil ||
		bifrostReq.ChatRequest.Params.StreamOptions.IncludeUsage == nil ||
		!*bifrostReq.ChatRequest.Params.StreamOptions.IncludeUsage {
		t.Fatalf("expected chat stream include_usage to be forced before upstream, got %#v", bifrostReq.ChatRequest.Params.StreamOptions)
	}
}

func TestApplyUpstreamCredentialsRejectsManagedCredentialsForBYOKOnlyProviders(t *testing.T) {
	for _, item := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}]}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi"}`,
		},
		{
			name: "anthropic chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}`,
		},
		{
			name: "anthropic responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi"}`,
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   item.path,
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			state.Authorization = &billing.Authorization{UpstreamByok: "stogas"}
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			bifrostCtx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
			bifrostReq, err := resolution.ToBifrost(bifrostCtx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			if err := PrepareProviderRequest(bifrostCtx, state, bifrostReq); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			if err := ApplyUpstreamCredentials(bifrostCtx, state); !errors.Is(err, billing.ErrByokRequired) {
				t.Fatalf("ApplyUpstreamCredentials error = %v, want BYOK required", err)
			}
		})
	}
}

func TestResponsesPolicyRejectsUnsupportedFieldsAndInvalidShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"missing input", `{"model":"gpt-5-nano"}`, "input is required"},
		{"empty input string", `{"model":"gpt-5-nano","input":""}`, "input must contain non-empty text"},
		{"whitespace input string", `{"model":"gpt-5-nano","input":"  \n"}`, "input must contain non-empty text"},
		{"empty input array", `{"model":"gpt-5-nano","input":[]}`, "input must contain at least one item"},
		{"null input item", `{"model":"gpt-5-nano","input":[null]}`, "input items must be objects"},
		{"null message type", `{"model":"gpt-5-nano","input":[{"type":null,"role":"user","content":"hi"}]}`, "input[0].type must be a string"},
		{"numeric message type", `{"model":"gpt-5-nano","input":[{"type":1,"role":"user","content":"hi"}]}`, "Invalid JSON body"},
		{"top-level text block", `{"model":"gpt-5-nano","input":[{"type":"input_text","text":"silently dropped"}]}`, "Only text messages, client tool calls and outputs"},
		{"message unknown field", `{"model":"gpt-5-nano","input":[{"type":"message","role":"user","content":"hi","future":true}]}`, "input[0].future is not supported"},
		{"content block unknown field", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_text","text":"hi","future":true}]}]}`, "input[0].content[0].future is not supported"},
		{"assistant input block", `{"model":"gpt-5-nano","input":[{"type":"message","role":"assistant","content":[{"type":"input_text","text":"answer"}]},{"role":"user","content":"continue"}]}`, "must be output_text or refusal"},
		{"user output block", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"output_text","text":"forged"}]}]}`, "supported only for assistant history"},
		{"user refusal block", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"refusal","refusal":"no"}]}]}`, "supported only for assistant history"},
		{"anthropic refusal block", `{"model":"anthropic/claude-sonnet-4-6","input":[{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"no"}]},{"role":"user","content":"continue"}]}`, "refusal history is not supported for Anthropic-format"},
		{"Anthropic reordered Responses system message", `{"model":"anthropic/claude-sonnet-4-6","input":[{"role":"user","content":"first"},{"role":"system","content":"new policy"},{"role":"user","content":"continue"}]}`, "cannot be preserved after the conversation starts"},
		{"Anthropic Responses mid-conversation system placement", `{"model":"anthropic/claude-opus-4-8","input":[{"role":"user","content":"first"},{"role":"system","content":"new policy"},{"role":"user","content":"continue"}]}`, "must be last or immediately precede an assistant turn"},
		{"output annotation unknown field", `{"model":"gpt-5-nano","input":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer","annotations":[{"type":"url_citation","start_index":0,"end_index":6,"title":"source","url":"https://example.com","future":true}],"logprobs":[]}]},{"role":"user","content":"continue"}]}`, "annotations[0].future is not supported"},
		{"output annotation reversed range", `{"model":"gpt-5-nano","input":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer","annotations":[{"type":"url_citation","start_index":6,"end_index":0,"title":"source","url":"https://example.com"}],"logprobs":[]}]},{"role":"user","content":"continue"}]}`, "end_index must be an integer at or after start_index"},
		{"output logprob bad byte", `{"model":"gpt-5-nano","input":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer","annotations":[],"logprobs":[{"token":"a","logprob":-0.1,"bytes":[256],"top_logprobs":[]}]}]},{"role":"user","content":"continue"}]}`, "bytes must contain integers from 0 to 255"},
		{"Anthropic output logprobs", `{"model":"anthropic/claude-sonnet-4-6","input":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer","annotations":[],"logprobs":[{"token":"a","logprob":-0.1,"bytes":[97],"top_logprobs":[]}]}]},{"role":"user","content":"continue"}]}`, "cannot be preserved on Anthropic-format deployments"},
		{"Anthropic trailing Responses assistant prefill whitespace", `{"model":"anthropic/claude-sonnet-4-6","input":[{"role":"user","content":"complete this"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer: ","annotations":[],"logprobs":[]}]}]}`, "must not end in whitespace"},
		{"orphan function output", `{"model":"gpt-5-nano","input":[{"type":"function_call_output","call_id":"call_1","output":"done"}]}`, "must match an earlier client tool call"},
		{"function call without output", `{"model":"gpt-5-nano","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"}]}`, "require one matching output"},
		{"function call malformed arguments", `{"model":"gpt-5-nano","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"not-json"},{"type":"function_call_output","call_id":"call_1","output":"done"}]}`, "arguments must encode a JSON object"},
		{"function call array arguments", `{"model":"gpt-5-nano","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"[]"},{"type":"function_call_output","call_id":"call_1","output":"done"}]}`, "arguments must encode a JSON object"},
		{"function call duplicate argument key", `{"model":"gpt-5-nano","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{\"key\":1,\"key\":2}"},{"type":"function_call_output","call_id":"call_1","output":"done"}]}`, "arguments must encode a JSON object"},
		{"oversized Responses call id", fmt.Sprintf(`{"model":"gpt-5-nano","input":[{"type":"function_call","call_id":%q,"name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":%q,"output":"done"}]}`, strings.Repeat("a", 65), strings.Repeat("a", 65)), "at most 64 bytes"},
		{"Anthropic unsafe Responses call id", `{"model":"anthropic/claude-sonnet-4-6","input":[{"type":"function_call","call_id":"call:1","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"call:1","output":"done"}]}`, "only letters, digits, underscores, or hyphens"},
		{"function call invalid name", `{"model":"gpt-5-nano","input":[{"type":"function_call","call_id":"call_1","name":"lookup tool","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"done"}]}`, "name must contain 1 to 64"},
		{"message before function output", `{"model":"gpt-5-nano","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"message","role":"user","content":"skip it"},{"type":"function_call_output","call_id":"call_1","output":"done"}]}`, "must resolve the preceding client tool calls"},
		{"duplicate function call id", `{"model":"gpt-5-nano","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"function_call","call_id":"call_1","name":"other","arguments":"{}"}]}`, "duplicates another client tool call"},
		{"duplicate function output", `{"model":"gpt-5-nano","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"one"},{"type":"function_call_output","call_id":"call_1","output":"two"}]}`, "duplicates a client tool output"},
		{"non-text function output", `{"model":"gpt-5-nano","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":[{"type":"input_text","text":"done"}]}]}`, "input[1].output must be a string"},
		{"custom call on Anthropic", `{"model":"anthropic/claude-sonnet-4-6","input":[{"type":"custom_tool_call","call_id":"call_1","name":"lookup","input":"query"},{"type":"custom_tool_call_output","call_id":"call_1","output":"done"}]}`, "supported only for OpenAI-format deployments"},
		{"reasoning item unknown field", `{"model":"gpt-5-nano","input":[{"type":"message","role":"user","content":"continue"},{"type":"reasoning","encrypted_content":"opaque","future":true}]}`, "input[1].future is not supported"},
		{"background", `{"model":"gpt-5-nano","input":"hi","background":true}`, "background is not supported"},
		{"conversation", `{"model":"gpt-5-nano","input":"hi","conversation":"conv_123"}`, "conversation is not supported"},
		{"fallbacks", `{"model":"gpt-5-nano","input":"hi","fallbacks":["openai-gpt-5-nano-2025-08-07-flex"]}`, "Fallbacks are not supported"},
		{"previous response", `{"model":"gpt-5-nano","input":"hi","previous_response_id":"resp_123"}`, "previous_response_id is not supported"},
		{"reasoning input item without encrypted content", `{"model":"gpt-5-nano","input":[{"type":"reasoning","summary":[]}]}`, "reasoning input items require encrypted_content"},
		{"reasoning input item on Anthropic", `{"model":"anthropic/claude-sonnet-4-6","input":[{"type":"reasoning","encrypted_content":"opaque"}]}`, "reasoning input items are only supported for OpenAI reasoning deployments"},
		{"prompt cache options anthropic", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","prompt_cache_options":{"mode":"explicit"}}`, "prompt_cache_options is only supported for OpenAI"},
		{"openai cache control", `{"model":"gpt-5-nano","input":"hi","cache_control":{"type":"ephemeral"}}`, "cache_control is only supported for Anthropic"},
		{"openai input cache control", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`, "cache_control is only supported for Anthropic"},
		{"openai tool cache control", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup","cache_control":{"type":"ephemeral"}}]}`, "cache_control is only supported for Anthropic"},
		{"anthropic cache control bad ttl", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","cache_control":{"type":"ephemeral","ttl":"24h"}}`, "cache_control.ttl must be 5m or 1h"},
		{"anthropic message cache control unsupported", `{"model":"anthropic/claude-sonnet-4-6","input":[{"role":"user","cache_control":{"type":"ephemeral"},"content":"hi"}]}`, "input[0].cache_control is not supported"},
		{"anthropic responses frequency penalty", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","frequency_penalty":0.1}`, "frequency_penalty is only supported for OpenAI"},
		{"anthropic responses include", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","include":["message.output_text.logprobs"]}`, "include is only supported for OpenAI"},
		{"anthropic responses presence penalty", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","presence_penalty":0.1}`, "presence_penalty is only supported for OpenAI"},
		{"responses include unknown value", `{"model":"gpt-5-nano","input":"hi","include":["file_search_call.results"]}`, "not supported by the text-only Stogas API"},
		{"responses duplicate include", `{"model":"gpt-5-nano","input":"hi","include":["reasoning.encrypted_content","reasoning.encrypted_content"]}`, "must not contain duplicate values"},
		{"responses text unknown field", `{"model":"gpt-5-nano","input":"hi","text":{"future":true}}`, "text must contain only format and verbosity"},
		{"responses text format unknown field", `{"model":"gpt-5-nano","input":"hi","text":{"format":{"type":"text","future":true}}}`, "supports only type"},
		{"responses text format missing schema", `{"model":"gpt-5-nano","input":"hi","text":{"format":{"type":"json_schema","name":"answer"}}}`, "schema must be an object"},
		{"anthropic responses verbosity", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","text":{"verbosity":"medium"}}`, "cannot be preserved on Anthropic-format"},
		{"anthropic responses json object format", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","text":{"format":{"type":"json_object"}}}`, "must be json_schema for Anthropic-format"},
		{"anthropic responses stream obfuscation", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","stream":true,"stream_options":{"include_obfuscation":false}}`, "cannot be preserved on Anthropic-format"},
		{"anthropic detailed reasoning summary", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","reasoning":{"summary":"detailed"}}`, "must be auto for Anthropic-format"},
		{"anthropic truncation", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","truncation":"auto"}`, "truncation is not supported for Anthropic-format"},
		{"anthropic prompt cache key", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","prompt_cache_key":"tenant-a"}`, "prompt_cache_key is not supported for Anthropic-format"},
		{"top k openai", `{"model":"gpt-5-nano","input":"hi","top_k":40}`, "top_k is only supported for Anthropic"},
		{"stop sequences openai", `{"model":"gpt-5-nano","input":"hi","stop_sequences":["END"]}`, "stop_sequences is only supported for Anthropic"},
		{"responses stop unsupported before stop sequences conflict", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","stop":["DONE"],"stop_sequences":["END"]}`, "stop is not supported"},
		{"openai task budget", `{"model":"gpt-5-nano","input":"hi","task_budget":{"type":"tokens","total":20000}}`, "task_budget is only supported for Anthropic"},
		{"openai context management", `{"model":"gpt-5-nano","input":"hi","context_management":{"edits":[{"type":"compact_20260112"}]}}`, "context_management is only supported for Anthropic"},
		{"reasoning effort bad type", `{"model":"gpt-5-nano","input":"hi","reasoning.effort":3}`, "reasoning.effort must be a string"},
		{"responses bad reasoning object", `{"model":"gpt-5-nano","input":"hi","reasoning":"low"}`, "reasoning must be an object"},
		{"responses bad reasoning max tokens", `{"model":"gpt-5-nano","input":"hi","reasoning":{"max_tokens":0}}`, "reasoning.max_tokens is outside the supported range"},
		{"client reasoning mode", `{"model":"gpt-5.6-sol","input":"hi","reasoning":{"mode":"pro"}}`, "reasoning.mode is not supported"},
		{"responses unsupported manual reasoning limit", `{"model":"gpt-5.6-sol","input":"hi","reasoning":{"max_tokens":1024}}`, "manual reasoning token limits are not supported"},
		{"responses manual reasoning budget below deployment minimum", `{"model":"anthropic-claude-opus-4-6","input":"hi","max_output_tokens":4096,"reasoning":{"max_tokens":1023}}`, "at least the deployment minimum"},
		{"responses manual reasoning budget equals output limit", `{"model":"anthropic-claude-opus-4-6","input":"hi","max_output_tokens":1024,"reasoning":{"max_tokens":1024}}`, "less than the output token limit"},
		{"responses manual reasoning limit on adaptive-only Anthropic model", `{"model":"anthropic-claude-opus-4-7","input":"hi","max_output_tokens":4096,"reasoning":{"max_tokens":1024}}`, "manual reasoning token limits are not supported"},
		{"responses manual reasoning limit on Azure", `{"model":"azure-gpt-5.6-sol","input":"hi","max_output_tokens":4096,"reasoning":{"max_tokens":1024}}`, "manual reasoning token limits are not supported"},
		{"responses reasoning display", `{"model":"gpt-5-nano","input":"hi","reasoning":{"display":"summarized"}}`, "reasoning.display is not supported"},
		{"responses unknown reasoning field", `{"model":"gpt-5-nano","input":"hi","reasoning":{"unknown":true}}`, "reasoning.unknown is not supported"},
		{"reasoning effort conflict", `{"model":"gpt-5-nano","input":"hi","reasoning":{"effort":"low"},"reasoning.effort":"medium"}`, "reasoning.effort conflicts"},
		{"stream options without stream", `{"model":"gpt-5-nano","input":"hi","stream_options":{"include_obfuscation":true}}`, "stream_options requires stream=true"},
		{"responses include usage stream option", `{"model":"gpt-5-nano","input":"hi","stream":true,"stream_options":{"include_usage":true}}`, "stream_options.include_usage is not supported for Responses"},
		{"store true", `{"model":"gpt-5-nano","input":"hi","store":true}`, "store=true is not supported"},
		{"store string", `{"model":"gpt-5-nano","input":"hi","store":"false"}`, "Invalid JSON body"},
		{"metadata non-string", `{"model":"gpt-5-nano","input":"hi","metadata":{"tenant":1}}`, "metadata values"},
		{"anthropic parallel tool calls", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"function","name":"lookup"}],"parallel_tool_calls":false}`, "parallel_tool_calls is not supported for Anthropic"},
		{"anthropic max tool calls function only", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"function","name":"lookup"}],"max_tool_calls":2}`, "max_tool_calls is only supported for Anthropic hosted tools"},
		{"max tool calls without tools", `{"model":"gpt-5-nano","input":"hi","max_tool_calls":2}`, "max_tool_calls requires supported tools"},
		{"max tool calls too large", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"max_tool_calls":129}`, "max_tool_calls is outside the supported range"},
		{"max tool calls with function only", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"max_tool_calls":1}`, "supported only for priced hosted Responses tools"},
		{"parallel tools without tools", `{"model":"gpt-5-nano","input":"hi","parallel_tool_calls":true}`, "parallel_tool_calls requires supported tools"},
		{"tool choice without tools", `{"model":"gpt-5-nano","input":"hi","tool_choice":"auto"}`, "tool_choice requires supported tools"},
		{"openai file search", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"file_search"}]}`, "hosted retrieval and file storage have separate pricing"},
		{"openai code interpreter", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"code_interpreter"}]}`, "hosted containers have separate pricing and lifecycle"},
		{"openai hosted shell", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`, "hosted execution needs a container lifecycle"},
		{"openai local shell", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"local_shell"}]}`, "local execution requires provider-state continuation"},
		{"openai apply patch", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"apply_patch"}]}`, "local execution requires provider-state continuation"},
		{"openai computer", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"computer_use_preview"}]}`, "text-only Stogas API"},
		{"openai image generation", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"image_generation"}]}`, "text-only Stogas API"},
		{"openai tool search", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"tool_search"}]}`, "tool-loading or provider-state lifecycle"},
		{"openai namespace", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"namespace","name":"crm","tools":[{"type":"function","name":"lookup"}]}]}`, "tool-loading or provider-state lifecycle"},
		{"openai memory", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"memory"}]}`, "tool-loading or provider-state lifecycle"},
		{"openai remote mcp URL", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"],"require_approval":"never"}]}`, "provider execution cannot be bounded or approved"},
		{"openai remote mcp connector", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"calendar","connector_id":"connector_googlecalendar","require_approval":"never"}]}`, "provider execution cannot be bounded or approved"},
		{"anthropic remote mcp", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"]}]}`, "provider execution cannot be bounded or approved"},
		{"anthropic custom", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"custom","name":"shell"}]}`, "free-form input formats are not preserved"},
		{"anthropic local shell", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"local_shell"}]}`, "Only function, web_fetch"},
		{"anthropic max uses too large", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search","max_uses":129}]}`, "max_uses is outside the supported range"},
		{"anthropic web fetch max uses too large", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_fetch_20260309","name":"web_fetch","max_uses":129}]}`, "max_uses is outside the supported range"},
		{"anthropic web fetch negative content cap", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_fetch_20260309","name":"web_fetch","max_content_tokens":-1}]}`, "max_content_tokens is outside the supported range"},
		{"anthropic hosted tool wrong name", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"lookup"}]}`, "name must be web_search"},
		{"anthropic advanced function flag", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"function","name":"lookup","defer_loading":true}]}`, "defer_loading is not supported"},
		{"anthropic unsupported fetch flag", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_fetch_20260309","name":"web_fetch","allowed_callers":["direct"]}]}`, "allowed_callers is not supported"},
		{"anthropic overlapping domain filters", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search","filters":{"allowed_domains":["example.com"],"blocked_domains":["EXAMPLE.COM"]}}]}`, "duplicates a domain"},
		{"anthropic max tool calls conflicts with max uses", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_tool_calls":2,"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":3}]}`, "max_tool_calls conflicts with tools[].max_uses"},
		{"anthropic web fetch max tool calls conflicts with max uses", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_tool_calls":2,"tools":[{"type":"web_fetch_20260309","name":"web_fetch","max_uses":3}]}`, "max_tool_calls conflicts with tools[].max_uses"},
		{"anthropic multiple hosted tools", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20260318","name":"web_search","max_uses":2},{"type":"web_fetch_20260318","name":"web_fetch","max_uses":2}]}`, "one hosted tool per request"},
		{"anthropic code execution", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"code_execution_20250825","name":"code_execution"}],"max_tool_calls":1}`, "Explicit Anthropic code_execution tools are not supported"},
		{"anthropic computer use", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"computer_20251124","name":"computer"}],"max_tool_calls":1}`, "Only function, web_fetch"},
		{"openai web fetch", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_fetch_20260309"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai code execution version", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"code_execution_20250825"}],"max_tool_calls":1}`, "hosted containers have separate pricing and lifecycle"},
		{"openai empty web search suffix", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai separator-only web search suffix", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search__"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai empty preview web search suffix", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai separator-only preview web search suffix", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview__"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai malformed preview web search prefix", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_previewfoo"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai unknown dated web search", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_2026_01_01"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai unknown web search alias", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_latest"}],"max_tool_calls":1}`, "Only function, custom"},
		{"responses function unknown field", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup","eager_input_streaming":true}]}`, "eager_input_streaming is not supported"},
		{"responses function parameters array", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup","parameters":[]}]}`, "Invalid JSON body"},
		{"responses duplicate tool names", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"},{"type":"custom","name":"lookup"}]}`, "duplicates another client tool"},
		{"responses duplicate hosted type", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search"},{"type":"web_search_2025_08_26"}]}`, "duplicates another hosted tool"},
		{"responses custom grammar missing syntax", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"custom","name":"parse","format":{"type":"grammar","definition":"start: WORD"}}]}`, "format.syntax is required"},
		{"responses custom bad grammar syntax", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"custom","name":"parse","format":{"type":"grammar","definition":"start: WORD","syntax":"peg"}}]}`, "format.syntax must be lark or regex"},
		{"openai web search unknown field", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search","external_web_access":true}]}`, "external_web_access is not supported"},
		{"openai preview filters", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview","filters":{"allowed_domains":["example.com"]}}]}`, "filters is not supported"},
		{"openai web search invalid domain", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search","filters":{"allowed_domains":["https://example.com/path"]}}]}`, "contains an invalid domain"},
		{"openai web search bad location country", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search","user_location":{"type":"approximate","country":"USA"}}]}`, "country must be a two-letter country code"},
		{"unsupported tool choice", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"code_interpreter"}}`, "tool_choice must select a supported tool"},
		{"hosted tool choice not declared", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"web_search_preview"},"max_tool_calls":1}`, "max_tool_calls is supported only for priced hosted Responses tools"},
		{"hosted selector version mismatch", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_2025_03_11"}],"tool_choice":{"type":"web_search_preview"},"max_tool_calls":1}`, "tool_choice selects an undeclared hosted tool version"},
		{"allowed tools missing mode", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"function","name":"lookup"}]}}`, "tool_choice.mode is required"},
		{"allowed hosted tool choice not declared", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"web_search_preview"}]},"max_tool_calls":1}`, "max_tool_calls is supported only for priced hosted Responses tools"},
		{"allowed hosted selector version mismatch", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_2025_08_26"}],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"web_search"}]},"max_tool_calls":1}`, "tool_choice selects an undeclared hosted tool version"},
		{"allowed tools web fetch", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"web_fetch_20260309"}]},"max_tool_calls":1}`, "max_tool_calls is supported only for priced hosted Responses tools"},
		{"anthropic hosted selector", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":{"type":"web_search_20250305"}}`, "only string tool_choice modes or named function selectors"},
		{"anthropic allowed tools selector", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"web_search_20250305"}]}}`, "allowed_tools is supported only for OpenAI-format"},
		{"image input", `{"model":"gpt-5-nano","input":[{"type":"input_image","image_url":"https://example.com/a.png"}]}`, "Only text input"},
		{"file id input", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}]}`, "file inputs are not supported"},
		{"hosted file input", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_file","file_url":"https://example.com/a.txt"}]}]}`, "file inputs are not supported"},
		{"inline file input", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,aGk="}]}]}`, "file inputs are not supported"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResolvedResponses(t, tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestResponsesReasoningEffortAliasIsAdmittedBeforeProviderConversion(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","reasoning.effort":"high"}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	reasoning := bifrostReq.ResponsesRequest.Params.Reasoning
	if reasoning == nil || reasoning.Effort == nil || *reasoning.Effort != "high" {
		t.Fatalf("expected canonical reasoning.effort=high before provider conversion, got %#v", reasoning)
	}
	if _, ok := bifrostReq.ResponsesRequest.Params.ExtraParams["reasoning.effort"]; ok {
		t.Fatalf("reasoning.effort must not be forwarded as ExtraParams: %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
	}
	wireReq := openaiprovider.ToOpenAIResponsesRequest(
		schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
		bifrostReq.ResponsesRequest,
	)
	wireBytes, err := json.Marshal(wireReq)
	if err != nil {
		t.Fatalf("marshal OpenAI wire request: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(wireBytes, &wire); err != nil {
		t.Fatalf("unmarshal wire request: %v", err)
	}
	var wireReasoning map[string]string
	if err := json.Unmarshal(wire["reasoning"], &wireReasoning); err != nil {
		t.Fatalf("wire reasoning not present: body=%s err=%v", wireBytes, err)
	}
	if wireReasoning["effort"] != "high" {
		t.Fatalf("expected wire reasoning.effort=high, got %#v body=%s", wireReasoning, wireBytes)
	}
}

func TestReasoningEffortAdmissionAcrossCatalogModels(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		body      string
		want      string
		wantError bool
	}{
		{
			name: "OpenAI maps minimal to nearest low effort",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"minimal"}`,
			want: "low",
		},
		{
			name: "OpenAI enabled maps to nearest medium effort",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning":{"enabled":true}}`,
			want: "medium",
		},
		{
			name: "OpenAI disabled maps to none",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"reasoning":{"enabled":false}}`,
			want: "none",
		},
		{
			name: "Anthropic accepted max effort",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"reasoning":{"effort":"max"}}`,
			want: "max",
		},
		{
			name: "Anthropic Opus preserves xhigh",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-opus-4-8","input":"hi","reasoning":{"effort":"xhigh"}}`,
			want: "xhigh",
		},
		{
			name: "Azure maps minimal to nearest low effort",
			path: "/v1/responses",
			body: `{"model":"azure-gpt-5.6-sol","input":"hi","reasoning":{"effort":"minimal"}}`,
			want: "low",
		},
		{
			name: "Anthropic maps xhigh upward to max on a tie",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","reasoning":{"effort":"xhigh"}}`,
			want: "max",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tc.path,
				Body:   []byte(tc.body),
			})
			if tc.wantError {
				if err == nil {
					t.Fatal("unadvertised reasoning effort was accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			request, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			var effort *string
			if request.ChatRequest != nil && request.ChatRequest.Params.Reasoning != nil {
				effort = request.ChatRequest.Params.Reasoning.Effort
			}
			if request.ResponsesRequest != nil && request.ResponsesRequest.Params.Reasoning != nil {
				effort = request.ResponsesRequest.Params.Reasoning.Effort
			}
			if effort == nil || *effort != tc.want {
				t.Fatalf("expected normalized effort %q, got %#v", tc.want, effort)
			}
		})
	}
}

func TestEveryAdvertisedReasoningEffortReachesProviderWireFormat(t *testing.T) {
	type matrixDeployment struct {
		ModelID  string   `json:"modelId"`
		RouteIDs []string `json:"routeIds"`
		Upstream struct {
			InferenceGeo  string `json:"inferenceGeo"`
			Model         string `json:"model"`
			ReasoningMode string `json:"reasoningMode"`
			ServiceTier   string `json:"serviceTier"`
			Speed         string `json:"speed"`
		} `json:"upstream"`
	}
	type matrixModel struct {
		DeprecationDate *string `json:"deprecationDate"`
	}
	type matrixRoute struct {
		Interfaces []string `json:"interfaces"`
		ProviderID string   `json:"providerId"`
	}
	type wirePayload struct {
		InferenceGeo    string `json:"inference_geo"`
		MaxTokens       int    `json:"max_tokens"`
		Model           string `json:"model"`
		ReasoningEffort string `json:"reasoning_effort"`
		ServiceTier     string `json:"service_tier"`
		Speed           string `json:"speed"`
		Reasoning       struct {
			Effort string `json:"effort"`
			Mode   string `json:"mode"`
		} `json:"reasoning"`
		OutputConfig struct {
			Effort string `json:"effort"`
		} `json:"output_config"`
		Thinking struct {
			Type string `json:"type"`
		} `json:"thinking"`
		ChatTemplateKwargs struct {
			EnableThinking bool `json:"enable_thinking"`
			Thinking       bool `json:"thinking"`
		} `json:"chat_template_kwargs"`
	}

	public, ok := catalog.PublicCatalogPayload()
	if !ok {
		t.Fatal("compiled public catalog is unavailable")
	}
	deployments := map[string]matrixDeployment{}
	models := map[string]matrixModel{}
	routes := map[string]matrixRoute{}
	if err := json.Unmarshal(public.Graph["deployments"], &deployments); err != nil {
		t.Fatalf("decode catalog deployments: %v", err)
	}
	if err := json.Unmarshal(public.Graph["routes"], &routes); err != nil {
		t.Fatalf("decode catalog routes: %v", err)
	}
	if err := json.Unmarshal(public.Graph["models"], &models); err != nil {
		t.Fatalf("decode catalog models: %v", err)
	}

	deploymentIDs := make([]string, 0, len(deployments))
	for id := range deployments {
		deploymentIDs = append(deploymentIDs, id)
	}
	slices.Sort(deploymentIDs)

	for _, deploymentID := range deploymentIDs {
		source := deployments[deploymentID]
		for _, routeID := range source.RouteIDs {
			route := routes[routeID]
			provider := schemas.ModelProvider(route.ProviderID)
			usesAnthropicWire := provider == schemas.Anthropic || routeID == "azure-anthropic-messages"
			for _, interfaceName := range route.Interfaces {
				var (
					path  string
					route catalog.Route
				)
				switch interfaceName {
				case "chat_completions":
					path = "/v1/chat/completions"
					route = catalog.RouteChat
				case "responses":
					path = "/v1/responses"
					route = catalog.RouteResponses
				default:
					t.Fatalf("%s: unsupported catalog interface %q", routeID, interfaceName)
				}

				resolved, active := testDeploymentForRoute(provider, deploymentID, route)
				if !active {
					deprecationDate := models[source.ModelID].DeprecationDate
					if deprecationDate == nil {
						t.Fatalf("%s is unavailable without a deprecation date", deploymentID)
					}
					deprecatedAt, err := time.Parse(time.DateOnly, *deprecationDate)
					if err != nil || deprecatedAt.After(time.Now().UTC()) {
						t.Fatalf("%s has an invalid active deprecation cutoff %q", deploymentID, *deprecationDate)
					}
					continue
				}

				efforts := resolved.ReasoningEfforts
				if len(efforts) == 0 {
					efforts = []string{""}
				}
				for _, effort := range efforts {
					name := deploymentID + "/" + interfaceName
					if effort != "" {
						name += "/" + effort
					}
					t.Run(name, func(t *testing.T) {
						requestBody := map[string]any{"model": deploymentID}
						if interfaceName == "chat_completions" {
							requestBody["messages"] = []map[string]any{{"content": "hi", "role": "user"}}
							requestBody["max_completion_tokens"] = 2048
						} else {
							requestBody["input"] = "hi"
							requestBody["max_output_tokens"] = 2048
						}
						if effort != "" {
							requestBody["reasoning"] = map[string]any{"effort": effort}
						}
						body, err := json.Marshal(requestBody)
						if err != nil {
							t.Fatal(err)
						}
						resolution, err := catalog.ResolveRequest(catalog.RequestInput{
							Method: "POST",
							Path:   path,
							Body:   body,
						})
						if err != nil {
							t.Fatalf("resolve catalog deployment: %v", err)
						}
						if resolution.Deployment.ID != deploymentID {
							t.Fatalf("resolved %q, want %q", resolution.Deployment.ID, deploymentID)
						}
						state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
						validationErr := state.Adapter.ValidateRequest(state)
						if validationErr != nil {
							t.Fatalf("validate catalog deployment: %v", validationErr)
						}
						if err := state.Adapter.SanitizeRequest(state); err != nil {
							t.Fatalf("sanitize catalog deployment: %v", err)
						}
						ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
						request, err := resolution.ToBifrost(ctx)
						if err != nil {
							t.Fatalf("build Bifrost request: %v", err)
						}
						if interfaceName == "chat_completions" && request.ChatRequest.Provider != provider {
							t.Fatalf("Bifrost chat provider = %q, want %q", request.ChatRequest.Provider, provider)
						}
						if interfaceName == "responses" && request.ResponsesRequest.Provider != provider {
							t.Fatalf("Bifrost Responses provider = %q, want %q", request.ResponsesRequest.Provider, provider)
						}

						var wireBytes []byte
						switch {
						case usesAnthropicWire && interfaceName == "chat_completions":
							var bifrostErr *schemas.BifrostError
							wireBytes, bifrostErr = anthropicprovider.BuildAnthropicChatRequestBody(
								ctx,
								request.ChatRequest,
								anthropicprovider.AnthropicRequestBuildConfig{Provider: provider, Model: source.Upstream.Model},
							)
							if bifrostErr != nil {
								t.Fatalf("build Anthropic-family chat wire request: %v", bifrostErr)
							}
						case usesAnthropicWire && interfaceName == "responses":
							var bifrostErr *schemas.BifrostError
							wireBytes, bifrostErr = anthropicprovider.BuildAnthropicResponsesRequestBody(
								ctx,
								request.ResponsesRequest,
								anthropicprovider.AnthropicRequestBuildConfig{Provider: provider, Model: source.Upstream.Model},
							)
							if bifrostErr != nil {
								t.Fatalf("build Anthropic-family Responses wire request: %v", bifrostErr)
							}
						case (provider == schemas.OpenAI || provider == schemas.Azure) && interfaceName == "chat_completions":
							wireBytes, err = json.Marshal(openaiprovider.ToOpenAIChatRequest(ctx, request.ChatRequest))
						case (provider == schemas.OpenAI || provider == schemas.Azure) && interfaceName == "responses":
							wireBytes, err = json.Marshal(openaiprovider.ToOpenAIResponsesRequest(ctx, request.ResponsesRequest))
						case provider == catalog.ProviderChutes && interfaceName == "chat_completions":
							var bifrostErr *schemas.BifrostError
							wireBytes, bifrostErr = prepareChutesChatBody(ctx, request.ChatRequest, false)
							if bifrostErr != nil {
								t.Fatalf("prepare Chutes provider body: %v", bifrostErr)
							}
						default:
							t.Fatalf("unsupported provider/interface %s/%s", provider, interfaceName)
						}
						if err != nil {
							t.Fatalf("build provider wire request: %v", err)
						}
						wire := wirePayload{}
						if err := json.Unmarshal(wireBytes, &wire); err != nil {
							t.Fatalf("decode provider wire request: %v\n%s", err, wireBytes)
						}
						if wire.Model != source.Upstream.Model {
							t.Fatalf("wire model = %q, want %q", wire.Model, source.Upstream.Model)
						}
						if wire.Reasoning.Mode != source.Upstream.ReasoningMode {
							t.Fatalf("wire reasoning mode = %q, want %q\n%s", wire.Reasoning.Mode, source.Upstream.ReasoningMode, wireBytes)
						}
						switch provider {
						case schemas.OpenAI:
							if wire.ServiceTier != source.Upstream.ServiceTier {
								t.Fatalf("wire service_tier = %q, want %q", wire.ServiceTier, source.Upstream.ServiceTier)
							}
						case schemas.Azure:
							wantTier := source.Upstream.ServiceTier
							if wire.ServiceTier != wantTier || wire.InferenceGeo != "" || wire.Speed != "" {
								t.Fatalf("wire Azure axes = tier:%q geo:%q speed:%q, want tier:%q", wire.ServiceTier, wire.InferenceGeo, wire.Speed, wantTier)
							}
						case schemas.Anthropic:
							wantInferenceGeo := source.Upstream.InferenceGeo
							if wire.ServiceTier != "standard_only" ||
								wire.InferenceGeo != wantInferenceGeo {
								t.Fatalf(
									"wire Anthropic axes = tier:%q geo:%q, want tier:standard_only geo:%q",
									wire.ServiceTier,
									wire.InferenceGeo,
									wantInferenceGeo,
								)
							}
							wantSpeed := ""
							if source.Upstream.Speed == "fast" {
								wantSpeed = "fast"
							}
							if wire.Speed != wantSpeed {
								t.Fatalf("wire speed = %q, want %q", wire.Speed, wantSpeed)
							}
						case catalog.ProviderChutes:
							if wire.MaxTokens != 2048 || wire.ServiceTier != "" || wire.InferenceGeo != "" || wire.Speed != "" {
								t.Fatalf("wire Chutes controls are invalid: %#v", wire)
							}
						}
						if effort == "" {
							return
						}
						if usesAnthropicWire && effort == "none" {
							if wire.Thinking.Type != "disabled" || wire.OutputConfig.Effort != "" {
								t.Fatalf("wire reasoning was not disabled\n%s", wireBytes)
							}
							return
						}
						var wireEffort string
						wantEffort := effort
						switch {
						case usesAnthropicWire:
							wireEffort = wire.OutputConfig.Effort
						case (provider == schemas.OpenAI || provider == schemas.Azure) && interfaceName == "chat_completions":
							wireEffort = wire.ReasoningEffort
						case provider == schemas.OpenAI || provider == schemas.Azure:
							wireEffort = wire.Reasoning.Effort
						case provider == catalog.ProviderChutes:
							wireEffort = wire.ReasoningEffort
							control, supported := chutesReasoningWireControl(deploymentID, effort)
							if !supported {
								t.Fatalf("catalog advertises an unreviewed Chutes reasoning effort")
							}
							wantEffort = control.Effort
							if control.Thinking == nil ||
								wire.ChatTemplateKwargs.Thinking != *control.Thinking ||
								wire.ChatTemplateKwargs.EnableThinking != *control.Thinking {
								t.Fatalf("wire Chutes thinking controls are invalid\n%s", wireBytes)
							}
						default:
							wireEffort = wire.OutputConfig.Effort
						}
						if wireEffort != wantEffort {
							t.Fatalf("wire reasoning effort = %q, want %q\n%s", wireEffort, wantEffort, wireBytes)
						}
					})
				}
			}
		}
	}
}

func TestEveryAdvertisedManualReasoningBudgetReachesAnthropicWireFormat(t *testing.T) {
	type matrixDeployment struct {
		RouteIDs []string `json:"routeIds"`
	}
	type matrixRoute struct {
		Interfaces []string `json:"interfaces"`
		ProviderID string   `json:"providerId"`
	}

	public, ok := catalog.PublicCatalogPayload()
	if !ok {
		t.Fatal("compiled public catalog is unavailable")
	}
	deployments := map[string]matrixDeployment{}
	routes := map[string]matrixRoute{}
	if err := json.Unmarshal(public.Graph["deployments"], &deployments); err != nil {
		t.Fatalf("decode catalog deployments: %v", err)
	}
	if err := json.Unmarshal(public.Graph["routes"], &routes); err != nil {
		t.Fatalf("decode catalog routes: %v", err)
	}

	covered := 0
	for deploymentID, deployment := range deployments {
		for _, routeID := range deployment.RouteIDs {
			route := routes[routeID]
			provider := schemas.ModelProvider(route.ProviderID)
			if provider != schemas.Anthropic && routeID != "azure-anthropic-messages" {
				continue
			}
			for _, interfaceName := range route.Interfaces {
				interfaceName := interfaceName
				catalogRoute := catalog.RouteResponses
				if interfaceName == "chat_completions" {
					catalogRoute = catalog.RouteChat
				}
				resolved, active := testDeploymentForRoute(provider, deploymentID, catalogRoute)
				if !active || resolved.ReasoningMaxTokens == nil {
					continue
				}
				t.Run(deploymentID+"/"+interfaceName, func(t *testing.T) {
					minimum := resolved.ReasoningMaxTokens.Minimum
					requestBody := map[string]any{
						"model":     deploymentID,
						"reasoning": map[string]any{"max_tokens": minimum},
					}
					path := "/v1/responses"
					if interfaceName == "chat_completions" {
						path = "/v1/chat/completions"
						requestBody["messages"] = []map[string]any{{"content": "hi", "role": "user"}}
						requestBody["max_completion_tokens"] = minimum + 1
					} else if interfaceName == "responses" {
						requestBody["input"] = "hi"
						requestBody["max_output_tokens"] = minimum + 1
					} else {
						t.Fatalf("unsupported catalog interface %q", interfaceName)
					}
					body, err := json.Marshal(requestBody)
					if err != nil {
						t.Fatal(err)
					}
					resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: path, Body: body})
					if err != nil {
						t.Fatalf("resolve manual reasoning budget: %v", err)
					}
					state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
					if err := state.Adapter.ValidateRequest(state); err != nil {
						t.Fatalf("validate manual reasoning budget: %v", err)
					}
					ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
					request, err := resolution.ToBifrost(ctx)
					if err != nil {
						t.Fatalf("build Bifrost request: %v", err)
					}
					var wireBytes []byte
					if interfaceName == "chat_completions" {
						var bifrostErr *schemas.BifrostError
						wireBytes, bifrostErr = anthropicprovider.BuildAnthropicChatRequestBody(
							ctx,
							request.ChatRequest,
							anthropicprovider.AnthropicRequestBuildConfig{Provider: provider, Model: resolved.Upstream.Model},
						)
						if bifrostErr != nil {
							t.Fatalf("build Anthropic-family chat wire request: %v", bifrostErr)
						}
					} else {
						var bifrostErr *schemas.BifrostError
						wireBytes, bifrostErr = anthropicprovider.BuildAnthropicResponsesRequestBody(
							ctx,
							request.ResponsesRequest,
							anthropicprovider.AnthropicRequestBuildConfig{Provider: provider, Model: resolved.Upstream.Model},
						)
						if bifrostErr != nil {
							t.Fatalf("build Anthropic-family Responses wire request: %v", bifrostErr)
						}
					}
					var wire struct {
						Thinking struct {
							BudgetTokens *int   `json:"budget_tokens"`
							Type         string `json:"type"`
						} `json:"thinking"`
					}
					if err := json.Unmarshal(wireBytes, &wire); err != nil {
						t.Fatalf("decode Anthropic wire request: %v\n%s", err, wireBytes)
					}
					if wire.Thinking.Type != "enabled" || wire.Thinking.BudgetTokens == nil || *wire.Thinking.BudgetTokens != minimum {
						t.Fatalf("manual reasoning budget did not reach Anthropic wire: %#v\n%s", wire.Thinking, wireBytes)
					}
				})
				covered++
			}
		}
	}
	if covered == 0 {
		t.Fatal("catalog advertises no manual reasoning budget deployments")
	}
}

func TestChatReasoningMaxTokensAliasUsesTheSameManualBudgetContract(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic-claude-opus-4-6","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":2048,"reasoning_max_tokens":1024}`),
	})
	if err != nil {
		t.Fatalf("resolve reasoning_max_tokens alias: %v", err)
	}
	request, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("build Bifrost request: %v", err)
	}
	if request.ChatRequest.Params.Reasoning == nil || request.ChatRequest.Params.Reasoning.MaxTokens == nil ||
		*request.ChatRequest.Params.Reasoning.MaxTokens != 1024 {
		t.Fatalf("reasoning_max_tokens alias was not normalized: %#v", request.ChatRequest.Params.Reasoning)
	}
}

func TestResponsesInputTextOnlyRejectsMultimodalAliases(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "nested image_url alias",
			body: `[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]`,
			want: "Only text input",
		},
		{
			name: "top-level inline file",
			body: `[{"type":"input_file","file_data":"data:text/plain;base64,aGk="}]`,
			want: "file inputs are not supported",
		},
		{
			name: "typeless file id",
			body: `[{"role":"user","content":[{"file_id":"file_123"}]}]`,
			want: "file_id inputs are not supported",
		},
		{
			name: "typeless file url",
			body: `[{"role":"user","content":[{"file_url":"https://example.com/a.pdf"}]}]`,
			want: "file_url inputs are not supported",
		},
		{
			name: "typeless inline file",
			body: `[{"role":"user","content":[{"file_data":"data:text/plain;base64,aGk="}]}]`,
			want: "file inputs are not supported",
		},
		{
			name: "text-typed file object",
			body: `[{"role":"user","content":[{"type":"input_text","text":"hi","file":{"file_data":"data:text/plain;base64,aGk="}}]}]`,
			want: "input[0].content[0].file is not supported",
		},
		{
			name: "typeless image url",
			body: `[{"role":"user","content":[{"image_url":"https://example.com/a.png"}]}]`,
			want: "Only text input",
		},
		{
			name: "text-typed input image",
			body: `[{"role":"user","content":[{"type":"input_text","text":"hi","input_image":{"image_url":"https://example.com/a.png"}}]}]`,
			want: "input[0].content[0].input_image is not supported",
		},
		{
			name: "typeless input audio",
			body: `[{"role":"user","content":[{"input_audio":{"data":"abc","format":"mp3"}}]}]`,
			want: "Only text input",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResponsesInputTextOnly(nil, json.RawMessage(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestResponsesPolicyAllowsTextFunctionAndPricedWebSearch(t *testing.T) {
	for _, body := range []string{
		`{"model":"gpt-5-nano","input":"hi","stream":false,"instructions":"be brief","temperature":2.01,"top_p":1.01,"text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"object"},"strict":true},"verbosity":"future-verbosity"},"truncation":"future","prompt_cache_key":"tenant-cache"}`,
		`{"model":"gpt-5-nano","input":[{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"answer https://example.com","annotations":[{"type":"url_citation","start_index":7,"end_index":26,"title":"source","url":"https://example.com"}],"logprobs":[]}]},{"role":"user","content":"continue"}]}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":[{"type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"answer https://example.com","annotations":[{"type":"url_citation","start_index":7,"end_index":26,"title":"source","url":"https://example.com","text":"source","encrypted_index":"opaque"}],"logprobs":[]}]},{"role":"user","content":"continue"}]}`,
		`{"model":"gpt-5-nano","input":"hi","reasoning":{"summary":"future-summary","generate_summary":"future-generate-summary"}}`,
		`{"model":"gpt-5-nano","input":"hi","include":["web_search_call.action.sources","web_search_call.results","message.output_text.logprobs","reasoning.encrypted_content"],"top_logprobs":3}`,
		`{"model":"gpt-5-nano","input":"hi","stream":true,"stream_options":{"include_obfuscation":false}}`,
		`{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}],"tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"},"parallel_tool_calls":false}`,
		`{"model":"gpt-5-nano","input":[{"type":"function_call","id":"fc_1","status":"completed","call_id":"call_1","name":"lookup","arguments":"{\"key\":\"value\"}"},{"type":"function_call_output","id":"fco_1","status":"completed","call_id":"call_1","output":"done"}],"tools":[{"type":"function","name":"lookup"}]}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{\"key\":\"value\"}"},{"type":"function_call_output","call_id":"call_1","output":"done"}],"tools":[{"type":"function","name":"lookup"}]}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"custom","name":"lookup"}],"tool_choice":{"type":"custom","name":"lookup"}}`,
		`{"model":"gpt-5-nano","input":[{"type":"custom_tool_call","call_id":"call_1","name":"lookup","input":"query"},{"type":"custom_tool_call_output","call_id":"call_1","output":"done"}],"tools":[{"type":"custom","name":"lookup"}]}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto"}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_2025_08_26","filters":{"allowed_domains":["example.com"]},"search_context_size":"high","user_location":{"type":"approximate","city":"Paris","country":"FR","region":"Ile-de-France","timezone":"Europe/Paris"}}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_2025_03_11","search_context_size":"low","user_location":{"type":"approximate","country":"US"}}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_2025_03_11"}],"tool_choice":{"type":"web_search_preview_2025_03_11"},"max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":{"type":"web_search_preview"},"max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_2025_03_11"}],"tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"web_search_preview_2025_03_11"}]},"max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"web_search_preview"}]},"max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto","max_tool_calls":128}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"auto"}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20260209","name":"web_search","filters":{"allowed_domains":["example.com"],"blocked_domains":["blocked.example.com"]},"user_location":{"type":"approximate","country":"US","timezone":"America/New_York"}}],"tool_choice":"required","max_tool_calls":2}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search","name":"web_search"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_fetch_20260309","name":"web_fetch","max_content_tokens":1000}],"tool_choice":"required"}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral","ttl":"5m"}}]}],"cache_control":{"type":"ephemeral","ttl":"1h"},"tools":[{"type":"function","name":"lookup","cache_control":{"type":"ephemeral"}}]}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}]}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","top_p":0.9,"top_k":40,"stop_sequences":["END"]}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","context_management":{"edits":[{"type":"compact_20260112","trigger":{"type":"input_tokens","value":50000},"pause_after_compaction":false,"instructions":null}]}}`,
		`{"model":"anthropic/claude-opus-4-7","input":"hi","max_output_tokens":16,"task_budget":{"type":"tokens","total":20000,"remaining":19000}}`,
	} {
		if err := validateResolvedResponses(t, body); err != nil {
			t.Fatalf("expected Responses request to pass: %v\nbody=%s", err, body)
		}
	}
}

func TestResponsesClientToolContinuationReachesProviderWireLosslessly(t *testing.T) {
	tests := []struct {
		model         string
		name          string
		anthropicWire bool
	}{
		{name: "OpenAI", model: "gpt-5-nano"},
		{name: "Azure OpenAI", model: "azure-gpt-5.6-sol"},
		{name: "Anthropic", model: "anthropic/claude-sonnet-4-6", anthropicWire: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"model":%q,"input":[{"type":"message","role":"user","content":"find the record"},{"type":"function_call","id":"fc_1","status":"completed","call_id":"call_1","name":"lookup","arguments":"{\"key\":\"value\"}"},{"type":"function_call_output","id":"fco_1","status":"completed","call_id":"call_1","output":"record-result"},{"type":"message","role":"user","content":"continue"}],"tools":[{"type":"function","name":"lookup"}]}`, tc.model)
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
			request, err := resolution.ToBifrost(ctx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			wireBody := preparedProviderBody(t, ctx, request.ResponsesRequest)
			var wire map[string]any
			if err := json.Unmarshal(wireBody, &wire); err != nil {
				t.Fatalf("decode prepared provider body: %v\n%s", err, wireBody)
			}

			if !tc.anthropicWire {
				items, ok := wire["input"].([]any)
				if !ok || len(items) != 4 {
					t.Fatalf("OpenAI-format input was not preserved: %#v\n%s", wire["input"], wireBody)
				}
				call, callOK := items[1].(map[string]any)
				output, outputOK := items[2].(map[string]any)
				if !callOK || call["type"] != "function_call" || call["id"] != "fc_1" || call["status"] != "completed" || call["call_id"] != "call_1" || call["name"] != "lookup" || call["arguments"] != `{"key":"value"}` {
					t.Fatalf("function call changed on OpenAI-format wire: %#v\n%s", call, wireBody)
				}
				if !outputOK || output["type"] != "function_call_output" || output["id"] != "fco_1" || output["status"] != "completed" || output["call_id"] != "call_1" || output["output"] != "record-result" {
					t.Fatalf("function output changed on OpenAI-format wire: %#v\n%s", output, wireBody)
				}
				return
			}

			messages, ok := wire["messages"].([]any)
			if !ok || len(messages) < 3 {
				t.Fatalf("Anthropic messages were not built: %#v\n%s", wire["messages"], wireBody)
			}
			var toolUse, toolResult map[string]any
			for _, rawMessage := range messages {
				message, ok := rawMessage.(map[string]any)
				if !ok {
					continue
				}
				blocks, ok := message["content"].([]any)
				if !ok {
					continue
				}
				for _, rawBlock := range blocks {
					block, ok := rawBlock.(map[string]any)
					if !ok {
						continue
					}
					switch block["type"] {
					case "tool_use":
						toolUse = block
					case "tool_result":
						toolResult = block
					}
				}
			}
			if toolUse == nil || toolUse["id"] != "call_1" || toolUse["name"] != "lookup" || !reflect.DeepEqual(toolUse["input"], map[string]any{"key": "value"}) {
				t.Fatalf("function call changed on Anthropic wire: %#v\n%s", toolUse, wireBody)
			}
			if toolResult == nil || toolResult["tool_use_id"] != "call_1" || toolResult["content"] != "record-result" {
				t.Fatalf("function output changed on Anthropic wire: %#v\n%s", toolResult, wireBody)
			}
		})
	}
}

func TestResponsesAssistantOutputHistoryReachesProviderWireLosslessly(t *testing.T) {
	tests := []struct {
		body            string
		name            string
		wantAnnotations bool
	}{
		{
			name:            "OpenAI output item",
			wantAnnotations: true,
			body:            `{"model":"gpt-5-nano","input":[{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"answer https://example.com","annotations":[{"type":"url_citation","start_index":7,"end_index":26,"title":"source","url":"https://example.com"}],"logprobs":[]}]},{"role":"user","content":"continue"}]}`,
		},
		{
			name: "Anthropic citation",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":[{"type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"answer https://example.com","annotations":[{"type":"url_citation","start_index":7,"end_index":26,"title":"source","url":"https://example.com","text":"source","encrypted_index":"opaque"}],"logprobs":[]}]},{"role":"user","content":"continue"}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(tc.body)})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
			request, err := resolution.ToBifrost(ctx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			wireBody := string(preparedProviderBody(t, ctx, request.ResponsesRequest))
			if !strings.Contains(wireBody, "answer https://example.com") {
				t.Fatalf("assistant output text changed on provider wire: %s", wireBody)
			}
			if tc.wantAnnotations {
				var wire struct {
					Input []json.RawMessage `json:"input"`
				}
				if err := json.Unmarshal([]byte(wireBody), &wire); err != nil || len(wire.Input) == 0 {
					t.Fatalf("decode OpenAI provider wire: %v\n%s", err, wireBody)
				}
				var output struct {
					Content []struct {
						Annotations []struct {
							Type string `json:"type"`
							URL  string `json:"url"`
						} `json:"annotations"`
					} `json:"content"`
				}
				if err := json.Unmarshal(wire.Input[0], &output); err != nil || len(output.Content) != 1 ||
					len(output.Content[0].Annotations) != 1 ||
					output.Content[0].Annotations[0].Type != "url_citation" ||
					output.Content[0].Annotations[0].URL != "https://example.com" {
					t.Fatalf("OpenAI output annotation changed on provider wire: %s", wireBody)
				}
			} else if !strings.Contains(wireBody, `"encrypted_index":"opaque"`) {
				t.Fatalf("Anthropic encrypted citation index changed on provider wire: %s", wireBody)
			}
		})
	}
}

func TestResponsesCustomToolContinuationReachesOpenAIWireLosslessly(t *testing.T) {
	body := `{"model":"gpt-5-nano","input":[{"type":"custom_tool_call","id":"ctc_1","status":"completed","call_id":"call_1","name":"shell","input":"printf safe"},{"type":"custom_tool_call_output","id":"ctco_1","status":"completed","call_id":"call_1","output":"safe"}],"tools":[{"type":"custom","name":"shell"}]}`
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
	request, err := resolution.ToBifrost(ctx)
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatalf("PrepareProviderRequest returned error: %v", err)
	}
	var wire struct {
		Input []map[string]any `json:"input"`
	}
	wireBody := preparedProviderBody(t, ctx, request.ResponsesRequest)
	if err := json.Unmarshal(wireBody, &wire); err != nil {
		t.Fatalf("decode prepared provider body: %v\n%s", err, wireBody)
	}
	if len(wire.Input) != 2 || wire.Input[0]["type"] != "custom_tool_call" || wire.Input[0]["call_id"] != "call_1" || wire.Input[0]["name"] != "shell" || wire.Input[0]["input"] != "printf safe" || wire.Input[1]["type"] != "custom_tool_call_output" || wire.Input[1]["call_id"] != "call_1" || wire.Input[1]["output"] != "safe" {
		t.Fatalf("custom tool continuation changed on OpenAI wire: %#v\n%s", wire.Input, wireBody)
	}
}

func TestOpenAIAllowedToolsChoiceReachesProviderWireExactly(t *testing.T) {
	body := `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"},{"type":"web_search_preview_2025_03_11"}],"tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"function","name":"lookup"},{"type":"web_search_preview_2025_03_11"}]},"max_tool_calls":2}`
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
	request, err := resolution.ToBifrost(ctx)
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatalf("PrepareProviderRequest returned error: %v", err)
	}
	wireBody := preparedProviderBody(t, ctx, request.ResponsesRequest)
	var wire struct {
		ToolChoice struct {
			Mode  string           `json:"mode"`
			Tools []map[string]any `json:"tools"`
			Type  string           `json:"type"`
		} `json:"tool_choice"`
	}
	if err := json.Unmarshal(wireBody, &wire); err != nil {
		t.Fatalf("decode prepared provider body: %v\n%s", err, wireBody)
	}
	if wire.ToolChoice.Type != "allowed_tools" || wire.ToolChoice.Mode != "required" || len(wire.ToolChoice.Tools) != 2 ||
		wire.ToolChoice.Tools[0]["type"] != "function" || wire.ToolChoice.Tools[0]["name"] != "lookup" ||
		wire.ToolChoice.Tools[1]["type"] != "web_search_preview_2025_03_11" {
		t.Fatalf("allowed tool choice changed on OpenAI wire: %#v\n%s", wire.ToolChoice, wireBody)
	}
}

func TestResponsesPolicyPreservesStreamObfuscationOption(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","stream":true,"stream_options":{"include_obfuscation":false}}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if bifrostReq.ResponsesRequest.Params.StreamOptions == nil ||
		bifrostReq.ResponsesRequest.Params.StreamOptions.IncludeObfuscation == nil ||
		*bifrostReq.ResponsesRequest.Params.StreamOptions.IncludeObfuscation {
		t.Fatalf("expected Responses include_obfuscation=false to survive conversion, got %#v", bifrostReq.ResponsesRequest.Params.StreamOptions)
	}
}

func TestOpenAIChatWebSearchOptionsReachProviderWireRequest(t *testing.T) {
	body := `{
		"model":"gpt-5-search-api",
		"messages":[{"role":"user","content":"hi"}],
		"web_search_options":{
			"search_context_size":"low",
			"user_location":{
				"type":"approximate",
				"approximate":{
					"city":"San Francisco",
					"country":"US",
					"region":"California",
					"timezone":"America/Los_Angeles"
				}
			}
		},
		"max_completion_tokens":100
	}`
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(body),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if bifrostReq.ChatRequest == nil || bifrostReq.ChatRequest.Params == nil || bifrostReq.ChatRequest.Params.WebSearchOptions == nil {
		t.Fatalf("expected Bifrost chat web_search_options, got %#v", bifrostReq.ChatRequest)
	}
	wireRequest := openaiprovider.ToOpenAIChatRequest(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), bifrostReq.ChatRequest)
	wireBytes, err := json.Marshal(wireRequest)
	if err != nil {
		t.Fatalf("marshal OpenAI Chat request: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(wireBytes, &wire); err != nil {
		t.Fatalf("unmarshal OpenAI Chat wire request: %v\nbody=%s", err, string(wireBytes))
	}
	options, _ := wire["web_search_options"].(map[string]any)
	location, _ := options["user_location"].(map[string]any)
	approximate, _ := location["approximate"].(map[string]any)
	if options["search_context_size"] != "low" ||
		location["type"] != "approximate" ||
		approximate["city"] != "San Francisco" ||
		approximate["country"] != "US" ||
		approximate["region"] != "California" ||
		approximate["timezone"] != "America/Los_Angeles" {
		t.Fatalf("unexpected OpenAI Chat web_search_options wire body: %s", string(wireBytes))
	}
}

func TestResponsesPolicyPreservesAllowedOpenAIInclude(t *testing.T) {
	includes := []string{
		"web_search_call.action.sources",
		"web_search_call.results",
		"message.output_text.logprobs",
		"reasoning.encrypted_content",
	}
	body := `{"model":"gpt-5-nano","input":"hi","include":["web_search_call.action.sources","web_search_call.results","message.output_text.logprobs","reasoning.encrypted_content"],"top_logprobs":21}`
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(body),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if got := bifrostReq.ResponsesRequest.Params.Include; !slices.Equal(got, includes) {
		t.Fatalf("expected Bifrost include %#v, got %#v", includes, got)
	}
	if bifrostReq.ResponsesRequest.Params.TopLogProbs == nil || *bifrostReq.ResponsesRequest.Params.TopLogProbs != 21 {
		t.Fatalf("expected Bifrost top_logprobs=21, got %#v", bifrostReq.ResponsesRequest.Params.TopLogProbs)
	}
	wireRequest := openaiprovider.ToOpenAIResponsesRequest(
		schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
		bifrostReq.ResponsesRequest,
	)
	wireBytes, err := json.Marshal(wireRequest)
	if err != nil {
		t.Fatalf("marshal OpenAI Responses request: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(wireBytes, &wire); err != nil {
		t.Fatalf("unmarshal OpenAI wire request: %v", err)
	}
	var wireIncludes []string
	if err := json.Unmarshal(wire["include"], &wireIncludes); err != nil {
		t.Fatalf("wire include not preserved: body=%s err=%v", wireBytes, err)
	}
	if !slices.Equal(wireIncludes, includes) {
		t.Fatalf("expected OpenAI wire include %#v, got %#v body=%s", includes, wireIncludes, wireBytes)
	}
	var wireTopLogProbs int
	if err := json.Unmarshal(wire["top_logprobs"], &wireTopLogProbs); err != nil {
		t.Fatalf("wire top_logprobs not preserved: body=%s err=%v", wireBytes, err)
	}
	if wireTopLogProbs != 21 {
		t.Fatalf("expected OpenAI wire top_logprobs=21, got %d body=%s", wireTopLogProbs, wireBytes)
	}
}

func TestOpenAIResponsesEncryptedReasoningInputReservesEffectiveMaxInput(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		wantContext   int
		wantSearchCap bool
	}{
		{
			name:        "standard reasoning model",
			body:        `{"model":"gpt-5-nano","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]},{"type":"reasoning","id":"rs_123","summary":[],"encrypted_content":"opaque-ciphertext"}],"max_output_tokens":16}`,
			wantContext: 400000,
		},
		{
			name:        "Fast deployment context cap",
			body:        `{"model":"openai-gpt-5.5-2026-04-23-fast","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]},{"type":"reasoning","encrypted_content":"opaque-ciphertext"}],"max_output_tokens":16}`,
			wantContext: 272000,
		},
		{
			name:          "hosted tool content headroom is already reserved",
			body:          `{"model":"gpt-5-nano","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"search and continue"}]},{"type":"reasoning","encrypted_content":"opaque-ciphertext"}],"tools":[{"type":"web_search"}],"max_tool_calls":3,"max_output_tokens":16}`,
			wantContext:   400000,
			wantSearchCap: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			if resolution.Deployment.ContextWindowTokens != tc.wantContext {
				t.Fatalf("expected deployment context cap %d, got %d for %#v", tc.wantContext, resolution.Deployment.ContextWindowTokens, resolution.Deployment)
			}
			wantInput := tc.wantContext - resolution.OutputTokenLimit()
			if resolution.InputTokenLimit() != wantInput {
				t.Fatalf("encrypted reasoning must reserve effective max input %d, got %d", wantInput, resolution.InputTokenLimit())
			}

			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			if findMeterEstimateQuantity(state.Hold.Meters, billing.MeterInputTokens, strconv.Itoa(wantInput)) == nil {
				t.Fatalf("expected max-input hold quantity %d, got %#v", wantInput, state.Hold.Meters)
			}
			if got := countMeterEstimates(state.Hold.Meters, billing.MeterInputTokens); got != 1 {
				t.Fatalf("encrypted reasoning hold must not add a second input-token meter, got %d in %#v", got, state.Hold.Meters)
			}
			if tc.wantSearchCap {
				searchMeter := findMeterEstimate(state.Hold.Meters, MeterOpenAIResponsesWebSearchCalls)
				if searchMeter == nil || searchMeter.Quantity != "3" {
					t.Fatalf("expected web_search call hold quantity 3, got %#v in %#v", searchMeter, state.Hold.Meters)
				}
			}

			bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			wireRequest := openaiprovider.ToOpenAIResponsesRequest(
				schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
				bifrostReq.ResponsesRequest,
			)
			wireBytes, err := json.Marshal(wireRequest)
			if err != nil {
				t.Fatalf("marshal OpenAI Responses request: %v", err)
			}
			if !strings.Contains(string(wireBytes), `"encrypted_content":"opaque-ciphertext"`) {
				t.Fatalf("encrypted reasoning input must reach OpenAI wire request, got %s", string(wireBytes))
			}

			state.Signals = &StandardSignals{Prompt: 100, Completion: 16}
			if tc.wantSearchCap {
				state.Signals = &StandardSignals{Prompt: 100, Completion: 16, WebSearch: 2}
			}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatalf("CalculateUpstreamCost returned error: %v", err)
			}
			if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
				t.Fatalf("hold must cover actual provider usage after encrypted reasoning replay: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
			}
		})
	}
}

func TestResponsesTextFormatReachesProviderWireRequest(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "openai json schema",
			body: `{"model":"gpt-5-nano","input":"hi","text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"object","properties":{"ok":{"type":"boolean"}}},"strict":true}}}`,
		},
		{
			name: "anthropic json schema",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			bifrostReq, err := resolution.ToBifrost(bifrostCtx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			switch resolution.Provider {
			case schemas.OpenAI:
				wire := openaiprovider.ToOpenAIResponsesRequest(
					schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
					bifrostReq.ResponsesRequest,
				)
				wireBytes, err := json.Marshal(wire)
				if err != nil {
					t.Fatalf("marshal OpenAI responses request: %v", err)
				}
				if !strings.Contains(string(wireBytes), `"text"`) || !strings.Contains(string(wireBytes), `"strict":true`) {
					t.Fatalf("expected OpenAI Responses text.format to reach wire request, got %s", wireBytes)
				}
			case schemas.Anthropic:
				body, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
					bifrostCtx,
					bifrostReq.ResponsesRequest,
					anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
				)
				if bifrostErr != nil {
					t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
				}
				if strings.Contains(string(body), `"tools"`) {
					t.Fatalf("expected direct Anthropic structured output to avoid tool emulation, got %s", body)
				}
				if !strings.Contains(string(body), `"output_config"`) || !strings.Contains(string(body), `"format"`) || !strings.Contains(string(body), `"json_schema"`) {
					t.Fatalf("expected Anthropic Responses output_config.format, got %s", body)
				}
				if strings.Contains(string(body), `"strict"`) {
					t.Fatalf("Anthropic output_config.format must not contain unsupported strict flag: %s", body)
				}
			}
		})
	}
}

func TestOpenAIPromptCacheOptionsAndBreakpointsReachWireRequest(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.6-luna","messages":[{"role":"user","content":[{"type":"text","text":"hi","prompt_cache_breakpoint":{"mode":"explicit"}}]}],"prompt_cache_options":{"mode":"explicit","ttl":"30m"},"prompt_cache_retention":"24h"}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-luna","input":[{"role":"user","content":[{"type":"input_text","text":"hi","prompt_cache_breakpoint":{"mode":"explicit"}}]}],"prompt_cache_options":{"mode":"explicit","ttl":"30m"},"prompt_cache_retention":"24h"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tc.path,
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			var wire any
			switch tc.path {
			case "/v1/chat/completions":
				options := bifrostReq.ChatRequest.Params.PromptCacheOptions
				if options == nil || options.Mode == nil || *options.Mode != "explicit" ||
					options.TTL == nil || *options.TTL != "30m" {
					t.Fatalf("expected typed chat prompt_cache_options, got %#v", options)
				}
				if retention := bifrostReq.ChatRequest.Params.PromptCacheRetention; retention == nil || *retention != "24h" {
					t.Fatalf("expected typed chat prompt_cache_retention, got %#v", retention)
				}
				wire = openaiprovider.ToOpenAIChatRequest(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), bifrostReq.ChatRequest)
			case "/v1/responses":
				options := bifrostReq.ResponsesRequest.Params.PromptCacheOptions
				if options == nil || options.Mode == nil || *options.Mode != "explicit" ||
					options.TTL == nil || *options.TTL != "30m" {
					t.Fatalf("expected typed Responses prompt_cache_options, got %#v", options)
				}
				if retention := bifrostReq.ResponsesRequest.Params.PromptCacheRetention; retention == nil || *retention != "24h" {
					t.Fatalf("expected typed Responses prompt_cache_retention, got %#v", retention)
				}
				wire = openaiprovider.ToOpenAIResponsesRequest(
					schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
					bifrostReq.ResponsesRequest,
				)
			}
			wireBytes, err := json.Marshal(wire)
			if err != nil {
				t.Fatalf("marshal OpenAI wire request: %v", err)
			}
			if !strings.Contains(string(wireBytes), `"prompt_cache_options":{"mode":"explicit","ttl":"30m"}`) ||
				!strings.Contains(string(wireBytes), `"prompt_cache_breakpoint":{"mode":"explicit"}`) ||
				!strings.Contains(string(wireBytes), `"prompt_cache_retention":"24h"`) {
				t.Fatalf("wire prompt cache fields were not preserved: %s", wireBytes)
			}
		})
	}
}

func TestOpenAIPromptCacheImplicitModeReachesTheWire(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.6-luna","input":"hi","prompt_cache_options":{"mode":"implicit","ttl":"30m"}}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("documented implicit cache mode was rejected: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	wireBytes, err := json.Marshal(openaiprovider.ToOpenAIResponsesRequest(
		schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
		bifrostReq.ResponsesRequest,
	))
	if err != nil {
		t.Fatalf("marshal OpenAI Responses request: %v", err)
	}
	for _, field := range []string{`"mode":"implicit"`, `"ttl":"30m"`} {
		if !strings.Contains(string(wireBytes), field) {
			t.Fatalf("documented cache field %s was not preserved: %s", field, wireBytes)
		}
	}
}

func TestOpenAIPromptCachingRejectsUnrepresentableShapes(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		body          string
		want          string
		resolveReject bool
	}{
		{
			name:          "non-string mode",
			path:          "/v1/responses",
			body:          `{"model":"gpt-5.6-luna","input":"hi","prompt_cache_options":{"mode":1}}`,
			resolveReject: true,
		},
		{
			name:          "non-string ttl",
			path:          "/v1/chat/completions",
			body:          `{"model":"gpt-5.6-luna","messages":[{"role":"user","content":"hi"}],"prompt_cache_options":{"ttl":30}}`,
			resolveReject: true,
		},
		{
			name: "extra option",
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-luna","input":"hi","prompt_cache_options":{"mode":"explicit","future":true}}`,
			want: "supports only mode and ttl",
		},
		{
			name: "unknown option mode",
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-luna","input":"hi","prompt_cache_options":{"mode":"future"}}`,
			want: "mode must be implicit or explicit",
		},
		{
			name: "unsupported option ttl",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.6-luna","messages":[{"role":"user","content":"hi"}],"prompt_cache_options":{"ttl":"2h"}}`,
			want: "ttl must be 30m",
		},
		{
			name: "explicit controls on implicit-only model",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi","prompt_cache_options":{"mode":"explicit"}}`,
			want: "explicit prompt caching is not supported",
		},
		{
			name: "unknown retention",
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-luna","input":"hi","prompt_cache_retention":"forever"}`,
			want: "retention must be in_memory or 24h",
		},
		{
			name: "breakpoint wrong block",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.6-luna","messages":[{"role":"user","prompt_cache_breakpoint":{"mode":"explicit"},"content":"hi"}]}`,
			want: "messages[0].prompt_cache_breakpoint is not supported",
		},
		{
			name: "unknown breakpoint mode",
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-luna","input":[{"role":"user","content":[{"type":"input_text","text":"hi","prompt_cache_breakpoint":{"mode":"future"}}]}]}`,
			want: "breakpoint.mode must be explicit",
		},
		{
			name:          "breakpoint non-string mode",
			path:          "/v1/responses",
			body:          `{"model":"gpt-5.6-luna","input":[{"role":"user","content":[{"type":"input_text","text":"hi","prompt_cache_breakpoint":{"mode":1}}]}]}`,
			resolveReject: true,
		},
		{
			name: "too many breakpoints",
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-luna","input":[{"role":"user","content":[{"type":"input_text","text":"one","prompt_cache_breakpoint":{"mode":"explicit"}},{"type":"input_text","text":"two","prompt_cache_breakpoint":{"mode":"explicit"}},{"type":"input_text","text":"three","prompt_cache_breakpoint":{"mode":"explicit"}},{"type":"input_text","text":"four","prompt_cache_breakpoint":{"mode":"explicit"}},{"type":"input_text","text":"five","prompt_cache_breakpoint":{"mode":"explicit"}}]}],"prompt_cache_options":{"mode":"explicit"}}`,
			want: "at most four prompt blocks",
		},
		{
			name: "anthropic breakpoint",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-5","messages":[{"role":"user","content":[{"type":"text","text":"hi","prompt_cache_breakpoint":{"mode":"explicit"}}]}]}`,
			want: "only supported for OpenAI deployments",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tc.path,
				Body:   []byte(tc.body),
			})
			if tc.resolveReject {
				if err == nil {
					t.Fatal("request schema accepted an unrepresentable cache shape")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			err = state.Adapter.ValidateRequest(state)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}

	t.Run("cache key on uncached deployment", func(t *testing.T) {
		resolution, err := catalog.ResolveRequest(catalog.RequestInput{
			Method: "POST",
			Path:   "/v1/chat/completions",
			Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"prompt_cache_key":"tenant-a"}`),
		})
		if err != nil {
			t.Fatalf("ResolveRequest returned error: %v", err)
		}
		resolution.Deployment.Capabilities.ImplicitPromptCaching = false
		state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
		err = state.Adapter.ValidateRequest(state)
		if err == nil || !strings.Contains(err.Error(), "prompt caching is not supported") {
			t.Fatalf("expected the deployment capability gate to reject the cache key, got %v", err)
		}
	})
}

func TestAnthropicSamplingParametersReachProviderRequestUnchanged(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"temperature":1.1,"top_p":1.2,"top_k":0,"stop_sequences":["END"],"context_management":{"edits":[{"type":"compact_20260112","instructions":"keep a compact summary"}]}}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","temperature":1.1,"top_p":1.2,"top_k":0,"stop_sequences":["END"],"context_management":{"edits":[{"type":"compact_20260112","instructions":"keep a compact summary"}]}}`,
		},
		{
			name: "adaptive chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-7","messages":[{"role":"user","content":"hi"}],"temperature":1.1,"top_p":1.2,"top_k":0,"stop_sequences":["END"],"context_management":{"edits":[{"type":"compact_20260112","instructions":"keep a compact summary"}]}}`,
		},
		{
			name: "adaptive responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-opus-4-7","input":"hi","temperature":1.1,"top_p":1.2,"top_k":0,"stop_sequences":["END"],"context_management":{"edits":[{"type":"compact_20260112","instructions":"keep a compact summary"}]}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tc.path,
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			switch tc.path {
			case "/v1/chat/completions":
				if bifrostReq.ChatRequest.Params.TopK == nil || *bifrostReq.ChatRequest.Params.TopK != 0 {
					t.Fatalf("expected Bifrost chat top_k=0, got %#v", bifrostReq.ChatRequest.Params.TopK)
				}
				if !slices.Equal(bifrostReq.ChatRequest.Params.Stop, []string{"END"}) {
					t.Fatalf("expected Bifrost chat stop_sequences alias to set stop, got %#v", bifrostReq.ChatRequest.Params.Stop)
				}
				if len(bifrostReq.ChatRequest.Params.ContextManagement) == 0 {
					t.Fatalf("expected Bifrost chat context_management to be retained")
				}
				wireReq, err := anthropicprovider.ToAnthropicChatRequest(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), bifrostReq.ChatRequest)
				if err != nil {
					t.Fatalf("ToAnthropicChatRequest returned error: %v", err)
				}
				if wireReq.TopK == nil || *wireReq.TopK != 0 {
					t.Fatalf("expected Anthropic chat top_k=0, got %#v", wireReq.TopK)
				}
				if wireReq.Temperature == nil || *wireReq.Temperature != 1.1 || wireReq.TopP == nil || *wireReq.TopP != 1.2 {
					t.Fatalf("expected both provider-owned sampling values on the wire, got temperature=%#v top_p=%#v", wireReq.Temperature, wireReq.TopP)
				}
				if !slices.Equal(wireReq.StopSequences, []string{"END"}) {
					t.Fatalf("expected Anthropic chat stop_sequences, got %#v", wireReq.StopSequences)
				}
				if wireReq.ContextManagement == nil || len(wireReq.ContextManagement.Edits) != 1 {
					t.Fatalf("expected Anthropic chat context_management, got %#v", wireReq.ContextManagement)
				}
			case "/v1/responses":
				if bifrostReq.ResponsesRequest.Params.ExtraParams["top_k"] != 0 {
					t.Fatalf("expected Responses top_k=0 provider extra, got %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
				}
				if got, _ := bifrostReq.ResponsesRequest.Params.ExtraParams["stop"].([]string); !slices.Equal(got, []string{"END"}) {
					t.Fatalf("expected Responses stop provider extra, got %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
				}
				if _, ok := bifrostReq.ResponsesRequest.Params.ExtraParams["context_management"]; !ok {
					t.Fatalf("expected Responses context_management provider extra, got %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
				}
				wire, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
					schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
					bifrostReq.ResponsesRequest,
					anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
				)
				if bifrostErr != nil {
					t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
				}
				var wireBody map[string]any
				if err := json.Unmarshal(wire, &wireBody); err != nil {
					t.Fatalf("failed to unmarshal Anthropic responses wire body: %v\nbody=%s", err, string(wire))
				}
				if wireBody["top_k"] != float64(0) {
					t.Fatalf("expected Anthropic responses top_k=0, got %#v", wireBody["top_k"])
				}
				if wireBody["temperature"] != 1.1 || wireBody["top_p"] != 1.2 {
					t.Fatalf("expected both provider-owned sampling values on the wire, got temperature=%#v top_p=%#v", wireBody["temperature"], wireBody["top_p"])
				}
				if stops, ok := wireBody["stop_sequences"].([]any); !ok || len(stops) != 1 || stops[0] != "END" {
					t.Fatalf("expected Anthropic responses stop_sequences, got %#v", wireBody["stop_sequences"])
				}
				contextManagement, _ := wireBody["context_management"].(map[string]any)
				edits, _ := contextManagement["edits"].([]any)
				if len(edits) != 1 {
					t.Fatalf("expected Anthropic responses context_management edit, got %#v", contextManagement)
				}
			}
		})
	}
}

func TestAnthropicTaskBudgetReachesProviderRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-7","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16,"task_budget":{"type":"tokens","total":20000,"remaining":19000}}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-opus-4-7","input":"hi","max_output_tokens":16,"task_budget":{"type":"tokens","total":20000,"remaining":19000}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tc.path,
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			switch tc.path {
			case "/v1/chat/completions":
				if bifrostReq.ChatRequest.Params.TaskBudget == nil ||
					bifrostReq.ChatRequest.Params.TaskBudget.Type != "tokens" ||
					bifrostReq.ChatRequest.Params.TaskBudget.Total != 20000 ||
					bifrostReq.ChatRequest.Params.TaskBudget.Remaining == nil ||
					*bifrostReq.ChatRequest.Params.TaskBudget.Remaining != 19000 {
					t.Fatalf("unexpected Bifrost chat task_budget: %#v", bifrostReq.ChatRequest.Params.TaskBudget)
				}
				wireReq, err := anthropicprovider.ToAnthropicChatRequest(
					schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
					bifrostReq.ChatRequest,
				)
				if err != nil {
					t.Fatalf("ToAnthropicChatRequest returned error: %v", err)
				}
				if wireReq.OutputConfig == nil || wireReq.OutputConfig.TaskBudget == nil ||
					wireReq.OutputConfig.TaskBudget.Total != 20000 || wireReq.OutputConfig.TaskBudget.Remaining == nil ||
					*wireReq.OutputConfig.TaskBudget.Remaining != 19000 {
					t.Fatalf("unexpected Anthropic chat output_config.task_budget: %#v", wireReq.OutputConfig)
				}
			case "/v1/responses":
				if _, ok := bifrostReq.ResponsesRequest.Params.ExtraParams["task_budget"]; !ok {
					t.Fatalf("task_budget was lost from Responses provider extras: %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
				}
				wire, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
					schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
					bifrostReq.ResponsesRequest,
					anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
				)
				if bifrostErr != nil {
					t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
				}
				var wireBody map[string]any
				if err := json.Unmarshal(wire, &wireBody); err != nil {
					t.Fatalf("failed to unmarshal Anthropic Responses wire body: %v", err)
				}
				outputConfig, _ := wireBody["output_config"].(map[string]any)
				taskBudget, _ := outputConfig["task_budget"].(map[string]any)
				if taskBudget["type"] != "tokens" || taskBudget["total"] != float64(20000) || taskBudget["remaining"] != float64(19000) {
					t.Fatalf("unexpected Anthropic Responses output_config.task_budget: %#v", outputConfig)
				}
			}
		})
	}
}

func TestAnthropicChatMCPToolsetFailsBeforeProviderRequest(t *testing.T) {
	body := `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"mcp_toolset","mcp_server_name":"remote"}]}`
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)})
	if err == nil {
		state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
		err = state.Adapter.ValidateRequest(state)
	}
	if err == nil || !strings.Contains(err.Error(), "provider execution cannot be bounded") {
		t.Fatalf("expected MCP toolset rejection, got %v", err)
	}
}

func TestResponsesHostedToolsInjectEffectiveCapBeforeHold(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		provider schemas.ModelProvider
		meterKey string
	}{
		{
			name:     "openai top-level max_tool_calls",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto"}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "openai required hosted tool",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"required"}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "openai versioned allowed tool_choice",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_2025_03_11"}],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"web_search_preview_2025_03_11"}]}}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "openai stable version",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_2025_03_11"}],"tool_choice":"auto"}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "anthropic per-tool max_uses",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"auto"}`,
			provider: schemas.Anthropic,
			meterKey: meterAnthropicWebSearchCalls,
		},
		{
			name:     "anthropic required hosted tool",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"required"}`,
			provider: schemas.Anthropic,
			meterKey: meterAnthropicWebSearchCalls,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			if bifrostReq.ResponsesRequest == nil {
				t.Fatalf("expected responses request, got %#v", bifrostReq)
			}
			switch tc.provider {
			case schemas.OpenAI:
				if bifrostReq.ResponsesRequest.Params.MaxToolCalls == nil || *bifrostReq.ResponsesRequest.Params.MaxToolCalls != defaultResponsesHostedToolCalls {
					t.Fatalf("expected OpenAI max_tool_calls=%d, got %#v", defaultResponsesHostedToolCalls, bifrostReq.ResponsesRequest.Params.MaxToolCalls)
				}
			case schemas.Anthropic:
				if len(bifrostReq.ResponsesRequest.Params.Tools) != 1 ||
					bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch == nil ||
					bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch.MaxUses == nil ||
					*bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch.MaxUses != defaultResponsesHostedToolCalls {
					t.Fatalf("expected Anthropic web_search max_uses=%d, got %#v", defaultResponsesHostedToolCalls, bifrostReq.ResponsesRequest.Params.Tools)
				}
				wire, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
					schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
					bifrostReq.ResponsesRequest,
					anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
				)
				if bifrostErr != nil {
					t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
				}
				if !strings.Contains(string(wire), `"max_uses":50`) {
					t.Fatalf("expected Anthropic provider body to contain injected max_uses=50, got %s", string(wire))
				}
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			meter := findMeterEstimate(state.Hold.Meters, tc.meterKey)
			if meter == nil || meter.Quantity != "50" || !meter.HoldRequired {
				t.Fatalf("expected hold meter %s quantity 50, got %#v in %#v", tc.meterKey, meter, state.Hold.Meters)
			}
		})
	}
}

func TestAnthropicResponsesExplicitMaxToolCallsBecomesMaxUses(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_tool_calls":3,"tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"auto"}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if len(bifrostReq.ResponsesRequest.Params.Tools) != 1 ||
		bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch == nil ||
		bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch.MaxUses == nil ||
		*bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch.MaxUses != 3 {
		t.Fatalf("expected max_tool_calls=3 to become Anthropic max_uses=3, got %#v", bifrostReq.ResponsesRequest.Params.Tools)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	meter := findMeterEstimate(state.Hold.Meters, meterAnthropicWebSearchCalls)
	if meter == nil || meter.Quantity != "3" || !meter.HoldRequired {
		t.Fatalf("expected Anthropic hold meter quantity 3, got %#v in %#v", meter, state.Hold.Meters)
	}
}

func TestAnthropicResponsesWebFetchOmittedCapInjectsMaxUsesAndTokenHold(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","input":"Fetch https://example.com and summarize it.","cache_control":{"type":"ephemeral","ttl":"1h"},"tools":[{"type":"web_fetch_20260309","name":"web_fetch","max_content_tokens":1000}],"max_output_tokens":64}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if len(bifrostReq.ResponsesRequest.Params.Tools) != 1 ||
		bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebFetch == nil ||
		bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebFetch.MaxUses == nil ||
		*bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebFetch.MaxUses != defaultResponsesHostedToolCalls {
		t.Fatalf("expected omitted max_tool_calls to inject Anthropic web_fetch max_uses=%d, got %#v", defaultResponsesHostedToolCalls, bifrostReq.ResponsesRequest.Params.Tools)
	}
	wire, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
		schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
		bifrostReq.ResponsesRequest,
		anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
	)
	if bifrostErr != nil {
		t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
	}
	if !strings.Contains(string(wire), `"max_uses":50`) {
		t.Fatalf("expected Anthropic provider body to contain injected max_uses=50, got %s", string(wire))
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	if findMeterEstimate(state.Hold.Meters, meterAnthropicWebSearchCalls) != nil {
		t.Fatalf("web_fetch must not reserve Anthropic web-search call meters, got %#v", state.Hold.Meters)
	}
	req := anthropicAdapterContextForState(state)
	expectedFetchInputTokens := 1000 * defaultResponsesHostedToolCalls
	if got := anthropicHostedContentHoldTokens(req); got != expectedFetchInputTokens {
		t.Fatalf("expected web_fetch content headroom %d, got %d", expectedFetchInputTokens, got)
	}
	iterations := anthropicSamplingIterationLimit(req)
	expectedInputTokens := (req.InputTokenLimit + anthropicToolSystemPromptHoldTokens(req.Deployment.Model, req.ToolTypes) + expectedFetchInputTokens) * iterations
	cacheWriteMeter := findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens)
	if cacheWriteMeter == nil || cacheWriteMeter.Quantity != strconv.Itoa(expectedInputTokens) {
		t.Fatalf("expected one combined web_fetch 1h cache-write hold quantity %d, got %#v", expectedInputTokens, state.Hold.Meters)
	}
	if findMeterEstimate(state.Hold.Meters, billing.MeterInputTokens) != nil {
		t.Fatalf("ordinary input must not duplicate the higher cache-write hold, got %#v", state.Hold.Meters)
	}
	assertMeterQuantity(t, state.Hold.Meters, billing.MeterOutputTokens, strconv.Itoa(req.OutputTokenLimit*iterations))
	state.Signals = &StandardSignals{
		Prompt:       resolution.InputTokenLimit() + 1000*defaultResponsesHostedToolCalls,
		Completion:   resolution.OutputTokenLimit(),
		CacheWrite1h: resolution.InputTokenLimit() + 1000*defaultResponsesHostedToolCalls,
		WebSearch:    defaultResponsesHostedToolCalls,
	}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls) != nil {
		t.Fatalf("web_fetch final price must not include Anthropic web-search call meters, got %#v", state.FinalMeters)
	}
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover token-priced Anthropic web_fetch final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
}

func TestResponsesHostedToolsDoNotInjectCapWhenToolChoicePrecludesHostedCalls(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		provider schemas.ModelProvider
		meterKey string
	}{
		{
			name:     "openai",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"none"}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "anthropic",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"none"}`,
			provider: schemas.Anthropic,
			meterKey: meterAnthropicWebSearchCalls,
		},
		{
			name:     "openai selected function",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"},{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"}}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "anthropic selected function",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"},{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"}}`,
			provider: schemas.Anthropic,
			meterKey: meterAnthropicWebSearchCalls,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			switch tc.provider {
			case schemas.OpenAI:
				if bifrostReq.ResponsesRequest.Params.MaxToolCalls != nil {
					t.Fatalf("expected OpenAI max_tool_calls to remain omitted, got %#v", bifrostReq.ResponsesRequest.Params.MaxToolCalls)
				}
			case schemas.Anthropic:
				webSearchTool := (*schemas.ResponsesTool)(nil)
				for i := range bifrostReq.ResponsesRequest.Params.Tools {
					if bifrostReq.ResponsesRequest.Params.Tools[i].ResponsesToolWebSearch != nil {
						webSearchTool = &bifrostReq.ResponsesRequest.Params.Tools[i]
					}
				}
				if webSearchTool == nil || webSearchTool.ResponsesToolWebSearch.MaxUses != nil {
					t.Fatalf("expected Anthropic max_uses to remain omitted, got %#v", bifrostReq.ResponsesRequest.Params.Tools)
				}
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			if meter := findMeterEstimate(state.Hold.Meters, tc.meterKey); meter != nil {
				t.Fatalf("expected no hosted-tool hold meter for tool_choice none, got %#v in %#v", meter, state.Hold.Meters)
			}
			state.Signals = &StandardSignals{Prompt: 1, WebSearch: 1}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatalf("CalculateUpstreamCost returned error: %v", err)
			}
			if meter := findMeterEstimate(state.FinalMeters, tc.meterKey); meter != nil {
				t.Fatalf("expected no hosted-tool final meter when tool_choice precludes hosted calls, got %#v in %#v", meter, state.FinalMeters)
			}
		})
	}
}

func TestAnthropicResponsesWebFetchToolChoiceNoneDoesNotReserveContentHeadroom(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body: []byte(`{
			"model":"anthropic/claude-sonnet-4-6",
			"input":"Summarize https://example.com/article.",
			"tools":[{"type":"web_fetch_20260309","name":"web_fetch","max_content_tokens":1000}],
			"tool_choice":"none",
			"max_tool_calls":2,
			"max_output_tokens":64
		}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	if meter := findMeterEstimateQuantity(state.Hold.Meters, billing.MeterInputTokens, "2000"); meter != nil {
		t.Fatalf("tool_choice none must not reserve web_fetch content headroom, got %#v in %#v", meter, state.Hold.Meters)
	}
}

func TestResponsesToolChoiceRequiresNamedFunctionSelectors(t *testing.T) {
	for _, item := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "function selector missing name",
			body: `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"},{"type":"function","name":"lookup"}],"tool_choice":{"type":"function"}}`,
			want: "tool_choice must name a function tool",
		},
		{
			name: "custom selector missing name",
			body: `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"},{"type":"custom","name":"lookup"}],"tool_choice":{"type":"custom"}}`,
			want: "tool_choice must name a custom tool",
		},
		{
			name: "allowed function missing name",
			body: `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"},{"type":"function","name":"lookup"}],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"function"}]}}`,
			want: "tool_choice.allowed_tools function entries require name",
		},
		{
			name: "allowed custom missing name",
			body: `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"},{"type":"custom","name":"lookup"}],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"custom"}]}}`,
			want: "tool_choice.allowed_tools custom entries require name",
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			err = state.Adapter.ValidateRequest(state)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("expected %q error, got %v", item.want, err)
			}
		})
	}
}

func TestResponsesOmittedHostedToolCapCoversMaximumAllowedUsage(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		meterKey string
	}{
		{
			name:     "openai",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto"}`,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "openai required",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"required"}`,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "anthropic",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"auto"}`,
			meterKey: meterAnthropicWebSearchCalls,
		},
		{
			name:     "anthropic required",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"required"}`,
			meterKey: meterAnthropicWebSearchCalls,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			holdMeter := findMeterEstimate(state.Hold.Meters, tc.meterKey)
			if holdMeter == nil || holdMeter.Quantity != "50" || !holdMeter.HoldRequired {
				t.Fatalf("expected omitted cap to reserve 50 hosted calls, got %#v in %#v", holdMeter, state.Hold.Meters)
			}

			state.Signals = &StandardSignals{Prompt: 1, WebSearch: defaultResponsesHostedToolCalls}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatalf("CalculateUpstreamCost returned error: %v", err)
			}
			finalMeter := findMeterEstimate(state.FinalMeters, tc.meterKey)
			if finalMeter == nil || finalMeter.Quantity != "50" || finalMeter.HoldRequired {
				t.Fatalf("expected final hosted calls at the authorized maximum, got %#v in %#v", finalMeter, state.FinalMeters)
			}
			if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
				t.Fatalf("hold must cover omitted-cap final hosted-tool charge: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
			}
		})
	}
}

func TestResponsesPolicyForwardsAnthropicCacheControl(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body: []byte(`{
			"model":"anthropic/claude-sonnet-4-6",
			"input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral","ttl":"5m"}}]}],
			"cache_control":{"type":"ephemeral","ttl":"1h"},
			"tools":[{"type":"function","name":"lookup","cache_control":{"type":"ephemeral"}}]
		}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if bifrostReq.ResponsesRequest.Params.ExtraParams == nil || bifrostReq.ResponsesRequest.Params.ExtraParams["cache_control"] == nil {
		t.Fatalf("expected top-level cache_control to be forwarded through ExtraParams, got %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
	}
	if len(bifrostReq.ResponsesRequest.Input) != 1 ||
		bifrostReq.ResponsesRequest.Input[0].Content == nil ||
		len(bifrostReq.ResponsesRequest.Input[0].Content.ContentBlocks) != 1 ||
		bifrostReq.ResponsesRequest.Input[0].Content.ContentBlocks[0].CacheControl == nil {
		t.Fatalf("expected input content block cache_control to survive conversion, got %#v", bifrostReq.ResponsesRequest.Input)
	}
	if len(bifrostReq.ResponsesRequest.Params.Tools) != 1 || bifrostReq.ResponsesRequest.Params.Tools[0].CacheControl == nil {
		t.Fatalf("expected tool cache_control to survive conversion, got %#v", bifrostReq.ResponsesRequest.Params.Tools)
	}
}

func TestResponsesPolicySanitizesMetadataBeforeUpstream(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","metadata":{"tenant":"test"}}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if bifrostReq.ResponsesRequest.Params.Metadata != nil {
		t.Fatalf("expected metadata to be sanitized before upstream, got %#v", bifrostReq.ResponsesRequest.Params.Metadata)
	}
}

func TestResponsesPolicyMaxToolCallsScalesWebSearchHold(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"max_tool_calls":3}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	found := false
	for _, meter := range state.Hold.Meters {
		if meter.MeterKey == MeterOpenAIResponsesWebSearchPreviewCalls {
			found = true
			if meter.Quantity != "3" || !meter.HoldRequired {
				t.Fatalf("expected web search hold quantity 3, got %#v", meter)
			}
		}
	}
	if !found {
		t.Fatalf("expected web search preview hold meter in %#v", state.Hold.Meters)
	}
}

func TestOpenAIResponsesCapsHostedToolUsageAtMaxToolCalls(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"max_tool_calls":1}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	state.Signals = &StandardSignals{Prompt: 1, WebSearch: 3}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 3 {
		t.Fatalf("expected telemetry to retain three observed calls, got %d", calls)
	}
	searchMeter := findMeterEstimate(state.FinalMeters, MeterOpenAIResponsesWebSearchPreviewCalls)
	if searchMeter == nil {
		t.Fatalf("expected final web search preview meter in %#v", state.FinalMeters)
	}
	if searchMeter.Quantity != "1" || searchMeter.HoldRequired {
		t.Fatalf("expected final pricing to cap web search calls to the authorized quantity, got %#v", searchMeter)
	}
	if state.BifrostError != nil || state.UpstreamCostUSDAtoms == billing.ZeroChargeUSDAtoms || !finalMeterQuantitiesWithinHold(state.Hold.Meters, state.FinalMeters) {
		t.Fatalf("bounded hosted-tool usage did not settle normally: %#v", state)
	}
}

func TestOpenAIResponsesCapsExcessNonPreviewSearchContent(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search"}],"max_tool_calls":1}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	mutatedPricing := copyPricing(resolution.Deployment.Pricing)
	mutatedPricing[billing.MeterInputTokens] = map[string]string{billing.RatePerMillionTokens: "1000000"}
	mutatedPricing[MeterOpenAIResponsesWebSearchCalls] = map[string]string{billing.RatePerThousandCalls: "10000000000000000000"}
	resolution.Deployment.Upstream.Model = "gpt-4o-mini"
	resolution.Deployment.Pricing = mutatedPricing

	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	state.Signals = &StandardSignals{Prompt: 1, WebSearch: 3}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}

	inputMeter := findMeterEstimate(state.FinalMeters, billing.MeterInputTokens)
	if inputMeter == nil || inputMeter.Quantity != "8124" || inputMeter.HoldRequired {
		t.Fatalf("expected final fixed search content to stay within the authorized input quantity, got %#v in %#v", inputMeter, state.FinalMeters)
	}
	searchMeter := findMeterEstimate(state.FinalMeters, MeterOpenAIResponsesWebSearchCalls)
	if searchMeter == nil || searchMeter.Quantity != "1" || searchMeter.HoldRequired {
		t.Fatalf("expected final non-preview search meter to stay within the authorized call quantity, got %#v in %#v", searchMeter, state.FinalMeters)
	}
	pricing := pricingForState(state)
	assertPricingBagEntry(t, pricing, billing.MeterInputTokens, billing.RatePerMillionTokens, "8124", inputMeter.AmountUSDAtoms)
	assertPricingBagEntry(t, pricing, MeterOpenAIResponsesWebSearchCalls, billing.RatePerThousandCalls, "1", searchMeter.AmountUSDAtoms)
	if state.BifrostError != nil || state.UpstreamCostUSDAtoms == billing.ZeroChargeUSDAtoms || !finalMeterQuantitiesWithinHold(state.Hold.Meters, state.FinalMeters) {
		t.Fatalf("bounded fixed-content web search usage did not settle normally: %#v", state)
	}
}

func TestResponsesIngestionTracksActualWebSearchCalls(t *testing.T) {
	adapter := OpenAIAdapter{}
	numSearchQueries := 2
	state := &State{}
	resp := &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{NumSearchQueries: &numSearchQueries},
		},
	}}
	if err := adapter.IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	signals, ok := state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 2 {
		t.Fatalf("expected two web search calls from usage, got %#v", state.Signals)
	}

	webSearchType := schemas.ResponsesMessageTypeWebSearchCall
	state = &State{}
	resp = &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{
			{Type: &webSearchType},
			{Type: &webSearchType},
			{Type: schemas.Ptr(schemas.ResponsesMessageTypeMessage)},
		},
	}}
	if err := adapter.IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 2 {
		t.Fatalf("expected two web search calls from output items, got %#v", state.Signals)
	}

	numSearchQueries = 2
	state = &State{}
	resp = &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{NumSearchQueries: &numSearchQueries},
		},
		Output: []schemas.ResponsesMessage{
			{Type: &webSearchType},
			{Type: &webSearchType},
		},
	}}
	if err := adapter.IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse usage plus anonymous output returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 2 {
		t.Fatalf("expected usage count to avoid anonymous output double-counting, got %#v", state.Signals)
	}

	numSearchQueries = 1
	firstItemID := "ws_1"
	secondItemID := "ws_2"
	state = &State{}
	resp = &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{NumSearchQueries: &numSearchQueries},
		},
		Output: []schemas.ResponsesMessage{
			{ID: &firstItemID, Type: &webSearchType},
			{ID: &secondItemID, Type: &webSearchType},
		},
	}}
	if err := adapter.IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse usage plus identified output returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 2 {
		t.Fatalf("expected identified output calls to preserve conservative count when usage is lower, got %#v", state.Signals)
	}

	itemID := "ws_1"
	state = &State{}
	for _, eventType := range []schemas.ResponsesStreamResponseType{
		schemas.ResponsesStreamResponseTypeWebSearchCallInProgress,
		schemas.ResponsesStreamResponseTypeWebSearchCallSearching,
	} {
		if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
			BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
				Type:   eventType,
				ItemID: &itemID,
			},
		}); err != nil {
			t.Fatalf("IngestChunk non-billable search event returned error: %v", err)
		}
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected in-progress/searching events not to count as billable search calls, got %d", calls)
	}

	completedStatus := "completed"
	webFetchType := schemas.ResponsesMessageTypeWebFetchCall
	state = &State{}
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &webFetchType, Status: &completedStatus}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse completed web fetch returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected completed web fetch not to count as billable search call, got %d", calls)
	}

	state = &State{}
	if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type:   schemas.ResponsesStreamResponseTypeWebFetchCallCompleted,
			ItemID: &itemID,
			Item:   &schemas.ResponsesMessage{ID: &itemID, Type: &webFetchType, Status: &completedStatus},
		},
	}); err != nil {
		t.Fatalf("IngestChunk completed web fetch returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected completed web fetch stream event not to count as billable search call, got %d", calls)
	}

	codeInterpreterType := schemas.ResponsesMessageTypeCodeInterpreterCall
	state = &State{}
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &codeInterpreterType, Status: &completedStatus}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse completed code execution returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected auto-injected code execution not to count as billable search call, got %d", calls)
	}

	failedStatus := "failed"
	state = &State{}
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &webSearchType, Status: &failedStatus}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse failed web search returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected failed output web search not to count as billable search call, got %d", calls)
	}

	inProgressStatus := "in_progress"
	state = &State{}
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &webSearchType, Status: &inProgressStatus}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse in-progress web search returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected in-progress output web search not to count as billable search call, got %d", calls)
	}

	state = &State{}
	if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type:   schemas.ResponsesStreamResponseTypeOutputItemDone,
			ItemID: &itemID,
			Item:   &schemas.ResponsesMessage{ID: &itemID, Type: &webSearchType, Status: &completedStatus},
		},
	}); err != nil {
		t.Fatalf("IngestChunk output item done returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 1 {
		t.Fatalf("expected completed output_item.done to count as one billable search call, got %d", calls)
	}

	state = &State{}
	if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeWebSearchCallCompleted,
		},
	}); err != nil {
		t.Fatalf("IngestChunk returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 1 {
		t.Fatalf("expected one web search call from stream event, got %#v", state.Signals)
	}

	state = &State{}
	if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type:   schemas.ResponsesStreamResponseTypeOutputItemAdded,
			ItemID: &itemID,
			Item:   &schemas.ResponsesMessage{ID: &itemID, Type: &webSearchType},
		},
	}); err != nil {
		t.Fatalf("IngestChunk output item returned error: %v", err)
	}
	if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type:   schemas.ResponsesStreamResponseTypeWebSearchCallCompleted,
			ItemID: &itemID,
		},
	}); err != nil {
		t.Fatalf("IngestChunk completed returned error: %v", err)
	}
	numSearchQueries = 1
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{NumSearchQueries: &numSearchQueries},
		},
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &webSearchType}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse after stream returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 1 {
		t.Fatalf("expected stream/output/usage web search id to count once, got %#v", state.Signals)
	}

	state = &State{}
	for i := 0; i < 2; i++ {
		if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
			BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
				Type:   schemas.ResponsesStreamResponseTypeWebSearchCallCompleted,
				ItemID: &itemID,
			},
		}); err != nil {
			t.Fatalf("IngestChunk duplicate returned error: %v", err)
		}
	}
	resp = &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &webSearchType}},
	}}
	if err := adapter.IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse duplicate returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 1 {
		t.Fatalf("expected duplicate stream/output web search id to count once, got %#v", state.Signals)
	}

	state = &State{}
	for i := 0; i < 2; i++ {
		if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
			BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeWebSearchCallCompleted,
				SequenceNumber: 7,
			},
		}); err != nil {
			t.Fatalf("IngestChunk duplicate sequence returned error: %v", err)
		}
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 1 {
		t.Fatalf("expected duplicate stream sequence to count once, got %#v", state.Signals)
	}
}

func TestAnthropicResponsesWebSearchPricingUsesObservedCalls(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","input":"hi","cache_control":{"type":"ephemeral","ttl":"1h"},"tools":[{"type":"web_search_20250305","name":"web_search"}],"max_tool_calls":3}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if !containsString(resolution.ToolTypes(), string(schemas.ResponsesToolTypeWebSearch)) {
		t.Fatalf("expected normalized web_search tool type, got %#v", resolution.ToolTypes())
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	foundHold := false
	for _, meter := range state.Hold.Meters {
		if meter.MeterKey == meterAnthropicWebSearchCalls {
			foundHold = true
			if meter.Quantity != "3" || !meter.HoldRequired {
				t.Fatalf("expected Anthropic web search hold quantity 3, got %#v", meter)
			}
		}
	}
	if !foundHold {
		t.Fatalf("expected Anthropic web search hold meter in %#v", state.Hold.Meters)
	}
	req := anthropicAdapterContextForState(state)
	searchContentHeadroom := anthropicHostedContentHoldTokens(req)
	iterations := anthropicSamplingIterationLimit(req)
	expectedInputTokens := (req.InputTokenLimit + anthropicToolSystemPromptHoldTokens(req.Deployment.Model, req.ToolTypes) + searchContentHeadroom) * iterations
	cacheWriteMeter := findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens)
	if searchContentHeadroom > 0 && (cacheWriteMeter == nil || cacheWriteMeter.Quantity != strconv.Itoa(expectedInputTokens)) {
		t.Fatalf("expected one combined Anthropic web search 1h cache-write hold quantity %d, got %#v", expectedInputTokens, state.Hold.Meters)
	}
	if findMeterEstimate(state.Hold.Meters, billing.MeterInputTokens) != nil {
		t.Fatalf("ordinary input must not duplicate the higher cache-write hold, got %#v", state.Hold.Meters)
	}
	assertMeterQuantity(t, state.Hold.Meters, billing.MeterOutputTokens, strconv.Itoa(req.OutputTokenLimit*iterations))

	numSearchQueries := 2
	providerResponse := validUnaryResponsesProviderResponse("resp_search")
	providerResponse.Usage = &schemas.ResponsesResponseUsage{
		InputTokens:         1,
		TotalTokens:         1,
		OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{NumSearchQueries: &numSearchQueries},
	}
	if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: providerResponse}, nil); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	searchMeter := findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls)
	if searchMeter == nil || searchMeter.Quantity != "2" || searchMeter.AmountUSDAtoms != "20000000000000000" {
		t.Fatalf("expected Anthropic web search settlement for 2 calls, got %#v", state.FinalMeters)
	}
}

func TestAnthropicResponsesWebFetchIsCappedAndTokenPriced(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body: []byte(`{
			"model":"anthropic/claude-sonnet-4-6",
			"input":"Summarize https://example.com/article in one sentence.",
			"tools":[{
				"type":"web_fetch_20260309",
				"name":"web_fetch",
				"max_content_tokens":1000,
				"filters":{"allowed_domains":["example.com"]}
			}],
			"max_tool_calls":4,
			"max_output_tokens":64
		}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if !containsString(resolution.ToolTypes(), string(schemas.ResponsesToolTypeWebFetch)) {
		t.Fatalf("expected normalized web_fetch tool type, got %#v", resolution.ToolTypes())
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	if findMeterEstimate(state.Hold.Meters, meterAnthropicWebSearchCalls) != nil {
		t.Fatalf("web_fetch must not reserve Anthropic web-search call meters, got %#v", state.Hold.Meters)
	}

	bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	bifrostReq, err := resolution.ToBifrost(bifrostCtx)
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	wire, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
		bifrostCtx,
		bifrostReq.ResponsesRequest,
		anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
	)
	if bifrostErr != nil {
		t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
	}
	var wireBody struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(wire, &wireBody); err != nil {
		t.Fatalf("failed to unmarshal Anthropic Responses request body: %v\n%s", err, wire)
	}
	if len(wireBody.Tools) != 1 {
		t.Fatalf("expected one Anthropic web_fetch tool, got %s", wire)
	}
	tool := wireBody.Tools[0]
	allowedDomains, _ := tool["allowed_domains"].([]any)
	if tool["type"] != "web_fetch_20260309" ||
		tool["name"] != "web_fetch" ||
		tool["max_uses"] != float64(4) ||
		tool["max_content_tokens"] != float64(1000) ||
		len(allowedDomains) != 1 ||
		allowedDomains[0] != "example.com" {
		t.Fatalf("unexpected Anthropic web_fetch wire tool: %s", wire)
	}

	state.Signals = &StandardSignals{Prompt: 1200, Completion: 64, WebSearch: 99}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls) != nil {
		t.Fatalf("web_fetch final price must not include Anthropic web-search call meters, got %#v", state.FinalMeters)
	}
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover token-priced Anthropic web_fetch final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
}

func TestAnthropicCompactionHoldCoversEveryBoundedSamplingIteration(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantIterations  int
		wantHostedCalls string
	}{
		{
			name:           "clear-only context editing does not add sampling",
			body:           `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_output_tokens":64,"context_management":{"edits":[{"type":"clear_tool_uses_20250919"}]}}`,
			wantIterations: 1,
		},
		{
			name:           "compaction can add one sampling step",
			body:           `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_output_tokens":64,"context_management":{"edits":[{"type":"compact_20260112"}]}}`,
			wantIterations: 2,
		},
		{
			name:            "compaction can run before every hosted-tool sampling step",
			body:            `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_output_tokens":64,"context_management":{"edits":[{"type":"compact_20260112"}]},"tools":[{"type":"web_search_20260318","name":"web_search"}],"max_tool_calls":2}`,
			wantIterations:  6,
			wantHostedCalls: "2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(tc.body)})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			req := anthropicAdapterContextForState(state)
			if got := anthropicSamplingIterationLimit(req); got != tc.wantIterations {
				t.Fatalf("sampling iteration limit = %d, want %d", got, tc.wantIterations)
			}
			inputPerIteration := req.InputTokenLimit + anthropicToolSystemPromptHoldTokens(req.Deployment.Model, req.ToolTypes) + anthropicHostedContentHoldTokens(req)
			assertMeterQuantity(t, state.Hold.Meters, billing.MeterInputTokens, strconv.Itoa(inputPerIteration*tc.wantIterations))
			assertMeterQuantity(t, state.Hold.Meters, billing.MeterOutputTokens, strconv.Itoa(req.OutputTokenLimit*tc.wantIterations))
			searchMeter := findMeterEstimate(state.Hold.Meters, meterAnthropicWebSearchCalls)
			if tc.wantHostedCalls == "" {
				if searchMeter != nil {
					t.Fatalf("unexpected hosted-tool call hold: %#v", searchMeter)
				}
			} else if searchMeter == nil || searchMeter.Quantity != tc.wantHostedCalls {
				t.Fatalf("hosted-tool calls must not be multiplied by sampling iterations: %#v", state.Hold.Meters)
			}
		})
	}
}

func TestAnthropicResponsesCapsHostedToolUsageAtMaxToolCalls(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"max_tool_calls":1}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	state.Signals = &StandardSignals{Prompt: 1, WebSearch: 3}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 3 {
		t.Fatalf("expected telemetry to retain three observed calls, got %d", calls)
	}
	searchMeter := findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls)
	if searchMeter == nil {
		t.Fatalf("expected final Anthropic web search meter in %#v", state.FinalMeters)
	}
	if searchMeter.Quantity != "1" || searchMeter.HoldRequired {
		t.Fatalf("expected final pricing to cap Anthropic web search calls to the authorized quantity, got %#v", searchMeter)
	}
	if state.BifrostError != nil || state.UpstreamCostUSDAtoms == billing.ZeroChargeUSDAtoms || !finalMeterQuantitiesWithinHold(state.Hold.Meters, state.FinalMeters) {
		t.Fatalf("bounded Anthropic hosted-tool usage did not settle normally: %#v", state)
	}
}

func TestAnthropicStackedPricingModifiersHoldCoversUpstreamCost(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body: []byte(`{
			"model":"anthropic/anthropic-claude-opus-4-8-fast-us",
			"input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral","ttl":"1h"}}]}],
			"cache_control":{"type":"ephemeral","ttl":"1h"},
			"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":2}],
			"max_output_tokens":64,
			"service_tier":"standard_only"
		}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.ID != "anthropic-claude-opus-4-8-fast-us" {
		t.Fatalf("expected fast standard-only US deployment, got %s", resolution.Deployment.ID)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	holdCache := findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens)
	if holdCache == nil {
		t.Fatalf("expected 1h cache-write hold meter, got %#v", state.Hold.Meters)
	}
	holdSearch := findMeterEstimate(state.Hold.Meters, meterAnthropicWebSearchCalls)
	if holdSearch == nil || holdSearch.Quantity != "2" || !holdSearch.HoldRequired {
		t.Fatalf("expected capped Anthropic web-search hold meter for two calls, got %#v in %#v", holdSearch, state.Hold.Meters)
	}

	state.Signals = &StandardSignals{
		Prompt:       resolution.InputTokenLimit(),
		Completion:   resolution.OutputTokenLimit(),
		CacheWrite1h: resolution.InputTokenLimit() / 2,
		WebSearch:    2,
		ActualSpeed:  "fast",
	}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover stacked Anthropic final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
	finalCache := findMeterEstimate(state.FinalMeters, billing.MeterCacheWrite1hInputTokens)
	if finalCache == nil {
		t.Fatalf("expected 1h cache-write final meter, got %#v", state.FinalMeters)
	}
	finalSearch := findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls)
	if finalSearch == nil || finalSearch.Quantity != "2" || finalSearch.HoldRequired {
		t.Fatalf("expected final Anthropic web-search meter for two authorized calls, got %#v in %#v", finalSearch, state.FinalMeters)
	}
	pricing := pricingForState(state)
	assertPricingBagEntry(t, pricing, billing.MeterCacheWrite1hInputTokens, billing.RatePerMillionTokens, finalCache.Quantity, finalCache.AmountUSDAtoms)
	assertPricingBagEntry(t, pricing, meterAnthropicWebSearchCalls, billing.RatePerThousandCalls, "2", finalSearch.AmountUSDAtoms)
	if actualWebSearchCalls(state) != 2 {
		t.Fatalf("expected telemetry to retain the two authorized observed calls, got %#v", state.Signals)
	}
}

func TestAnthropicCalculateUpstreamCostUsesCacheWriteMeters(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Deployment: catalog.Deployment{Pricing: catalog.Pricing{
				billing.MeterInputTokens:             {billing.RatePerMillionTokens: "1000000"},
				billing.MeterCachedInputTokens:       {billing.RatePerMillionTokens: "100000"},
				billing.MeterCacheWrite5mInputTokens: {billing.RatePerMillionTokens: "1250000"},
				billing.MeterCacheWrite1hInputTokens: {billing.RatePerMillionTokens: "2000000"},
				billing.MeterOutputTokens:            {billing.RatePerMillionTokens: "3000000"},
			}},
		},
		Signals: &StandardSignals{
			Prompt:       1000,
			Completion:   500,
			Cached:       100,
			CacheWrite5m: 200,
			CacheWrite1h: 300,
		},
	}
	if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms != "2760" {
		t.Fatalf("expected cache-aware final price 2760, got %s", state.UpstreamCostUSDAtoms)
	}
	assertMeterQuantity(t, state.FinalMeters, billing.MeterInputTokens, "400")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCachedInputTokens, "100")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCacheWrite5mInputTokens, "200")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCacheWrite1hInputTokens, "300")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterOutputTokens, "500")
}

func TestResponsesIngestionPreservesCacheWriteMeters(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Deployment: catalog.Deployment{Pricing: catalog.Pricing{
				billing.MeterInputTokens:             {billing.RatePerMillionTokens: "1000000"},
				billing.MeterCachedInputTokens:       {billing.RatePerMillionTokens: "100000"},
				billing.MeterCacheWrite5mInputTokens: {billing.RatePerMillionTokens: "1250000"},
				billing.MeterCacheWrite1hInputTokens: {billing.RatePerMillionTokens: "2000000"},
				billing.MeterOutputTokens:            {billing.RatePerMillionTokens: "3000000"},
			}},
		},
	}
	resp := &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			InputTokens:  1000,
			OutputTokens: 500,
			TotalTokens:  1500,
			InputTokensDetails: &schemas.ResponsesResponseInputTokens{
				CachedReadTokens:  100,
				CachedWriteTokens: 500,
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: 200,
					CachedWriteTokens1h: 300,
				},
			},
		},
	}}
	if err := (DefaultAdapter{}).IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms != "2760" {
		t.Fatalf("expected cache-aware final price 2760, got %s", state.UpstreamCostUSDAtoms)
	}
	assertMeterQuantity(t, state.FinalMeters, billing.MeterInputTokens, "400")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCachedInputTokens, "100")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCacheWrite5mInputTokens, "200")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCacheWrite1hInputTokens, "300")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterOutputTokens, "500")
}

func findMeterEstimate(meters []catalog.MeterEstimate, key string) *catalog.MeterEstimate {
	for i := range meters {
		if meters[i].MeterKey == key {
			return &meters[i]
		}
	}
	return nil
}

func findMeterEstimateQuantity(meters []catalog.MeterEstimate, key string, quantity string) *catalog.MeterEstimate {
	for i := range meters {
		if meters[i].MeterKey == key && meters[i].Quantity == quantity {
			return &meters[i]
		}
	}
	return nil
}

func countMeterEstimates(meters []catalog.MeterEstimate, key string) int {
	count := 0
	for _, meter := range meters {
		if meter.MeterKey == key {
			count++
		}
	}
	return count
}

func assertMeterQuantity(t *testing.T, meters []catalog.MeterEstimate, key string, quantity string) {
	t.Helper()
	meter := findMeterEstimate(meters, key)
	if meter == nil {
		t.Fatalf("expected meter %s in %#v", key, meters)
	}
	if meter.Quantity != quantity {
		t.Fatalf("expected meter %s quantity %s, got %#v", key, quantity, meter)
	}
}

func copyPricing(pricing catalog.Pricing) catalog.Pricing {
	copied := make(catalog.Pricing, len(pricing))
	for meterKey, rates := range pricing {
		rateCopy := make(map[string]string, len(rates))
		for rateKey, rate := range rates {
			rateCopy[rateKey] = rate
		}
		copied[meterKey] = rateCopy
	}
	return copied
}

func validateResolvedChat(t *testing.T, body string) error {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(body),
	})
	if err != nil {
		return err
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	return state.Adapter.ValidateRequest(state)
}

func validateResolvedResponses(t *testing.T, body string) error {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(body),
	})
	if err != nil {
		return err
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	return state.Adapter.ValidateRequest(state)
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
