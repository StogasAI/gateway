package stogas

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files that tests compare against")

// claudeCodeRequest is a request that Claude Code 2.1.330 sent to a local endpoint that refuses the
// anthropic-beta values that the route refuses, as the last request of a conversation that ran to
// its end, so each is one that Claude Code sends after its recovery. Claude Code's own texts, the
// machine's paths and the account are replaced.
type claudeCodeRequest struct {
	Name          string          `json:"name"`
	AnthropicBeta string          `json:"anthropic_beta"`
	Body          json.RawMessage `json:"body"`
}

// claudeCodeDeployments are the test catalog's deployments of each recorded model, on each Claude
// hosting that the catalog holds the model on.
var claudeCodeDeployments = map[string][]string{
	"claude-opus-4-5":   {"anthropic-claude-opus-4-5", "aws-claude-opus-4-5-anthropic-hosted"},
	"claude-haiku-4-5":  {"anthropic-claude-haiku-4-5", "google-cloud-claude-haiku-4-5-anthropic-hosted"},
	"claude-opus-4-6":   {"anthropic-claude-opus-4-6"},
	"claude-sonnet-4-6": {"anthropic-claude-sonnet-4-6"},
	"claude-opus-5-5":   {"anthropic-claude-opus-5-5", "azure-claude-opus-5-5", "azure-claude-opus-5-5-anthropic-hosted"},
}

// Each request that Claude Code sends reaches every Claude hosting with its fields as sent, apart
// from the changes that testdata/claude-code/hostings.golden lists: what the deployment sets, what
// the hosting's API writes another way, and what the gateway leaves out. go test -update rewrites
// the file after a change that the review of its diff accepts.
func TestClaudeCodeRequestsReachEveryClaudeHosting(t *testing.T) {
	file, err := os.Open(filepath.Join("testdata", "claude-code", "requests.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var report strings.Builder
	lines := bufio.NewScanner(file)
	lines.Buffer(nil, 1<<20)
	for lines.Scan() {
		var record claudeCodeRequest
		if err := json.Unmarshal(lines.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		var client map[string]any
		if err := json.Unmarshal(record.Body, &client); err != nil {
			t.Fatal(err)
		}
		deployments := claudeCodeDeployments[client["model"].(string)]
		if record.Name == "agent" {
			// The other hostings of AWS and Google Cloud, which the test catalog holds Claude Fable
			// 5.1 on.
			deployments = append(slices.Clone(deployments), "aws-claude-fable-5-1", "aws-claude-fable-5-1-anthropic-hosted",
				"google-cloud-claude-fable-5-1", "google-cloud-claude-fable-5-1-anthropic-hosted")
		}
		delete(client, "model")
		for _, deploymentID := range deployments {
			fmt.Fprintf(&report, "== %s on %s\n", record.Name, deploymentID)
			hosting, notes := claudeCodeHostingBody(t, record, deploymentID)
			for _, note := range notes {
				report.WriteString(note + "\n")
			}
			var differences []string
			jsonDifferences("", client, hosting, &differences)
			for _, difference := range collapseDifferences(differences) {
				report.WriteString(difference + "\n")
			}
		}
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "claude-code", "hostings.golden")
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(report.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got := report.String(); got != string(want) {
		gotLines, wantLines := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for index := range max(len(gotLines), len(wantLines)) {
			var gotLine, wantLine string
			if index < len(gotLines) {
				gotLine = gotLines[index]
			}
			if index < len(wantLines) {
				wantLine = wantLines[index]
			}
			if gotLine != wantLine {
				t.Fatalf("hostings differ from %s at line %d:\n got %s\nwant %s", golden, index+1, gotLine, wantLine)
			}
		}
	}
}

// claudeCodeHostingBody runs a recorded request through the Messages route on the deployment and
// returns the body that the hosting gets, with a note of the anthropic-beta values that it gets.
func claudeCodeHostingBody(t *testing.T, record claudeCodeRequest, deploymentID string) (map[string]any, []string) {
	t.Helper()
	var notes []string
	betas, err := catalog.MessagesBetas([]string{record.AnthropicBeta})
	if err != nil {
		t.Fatalf("%s: %v", record.Name, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(record.Body, &fields); err != nil {
		t.Fatal(err)
	}
	fields["model"] = json.RawMessage(strconv.Quote(deploymentID))
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/messages", Body: body, AnthropicBeta: betas})
	if err != nil {
		t.Fatalf("%s on %s: %v", record.Name, deploymentID, err)
	}
	if resolution.Deployment.ID != deploymentID {
		t.Fatalf("%s resolved %s, want %s", record.Name, resolution.Deployment.ID, deploymentID)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("%s on %s: %v", record.Name, deploymentID, err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("%s on %s: %v", record.Name, deploymentID, err)
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
	request, err := resolution.ToBifrost(ctx)
	if err != nil {
		t.Fatalf("%s on %s: %v", record.Name, deploymentID, err)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatalf("%s on %s: %v", record.Name, deploymentID, err)
	}
	if headers, ok := ctx.Value(schemas.BifrostContextKeyExtraHeaders).(map[string][]string); ok {
		if carried := headers[anthropicprovider.AnthropicBetaHeader]; len(carried) > 0 {
			notes = append(notes, "anthropic-beta "+strings.Join(carried, ","))
		}
	}
	var hosting map[string]any
	decoder := json.NewDecoder(bytes.NewReader(preparedProviderBody(t, ctx, request.ResponsesRequest)))
	decoder.UseNumber()
	if err := decoder.Decode(&hosting); err != nil {
		t.Fatal(err)
	}
	return hosting, notes
}

// jsonDifferences lists where got differs from want, each at its path: a key that got leaves out
// or adds, a list of another length and a value that changed.
func jsonDifferences(path string, want, got any, out *[]string) {
	at := func(key string) string {
		if path == "" {
			return key
		}
		return path + "." + key
	}
	switch want := want.(type) {
	case map[string]any:
		got, ok := got.(map[string]any)
		if !ok {
			break
		}
		keys := slices.Sorted(maps.Keys(want))
		for key := range got {
			if _, ok := want[key]; !ok {
				keys = append(keys, key)
			}
		}
		slices.Sort(keys)
		for _, key := range slices.Compact(keys) {
			wantValue, inWant := want[key]
			gotValue, inGot := got[key]
			switch {
			case !inGot:
				*out = append(*out, at(key)+": left out "+shortJSON(wantValue))
			case !inWant:
				*out = append(*out, at(key)+": added "+shortJSON(gotValue))
			default:
				jsonDifferences(at(key), wantValue, gotValue, out)
			}
		}
		return
	case []any:
		got, ok := got.([]any)
		if !ok || len(got) != len(want) {
			break
		}
		for index := range want {
			jsonDifferences(at(strconv.Itoa(index)), want[index], got[index], out)
		}
		return
	}
	if !reflect.DeepEqual(normalJSON(want), normalJSON(got)) {
		*out = append(*out, path+": "+shortJSON(want)+" became "+shortJSON(got))
	}
}

// normalJSON reads numbers as the same value whichever way they were decoded.
func normalJSON(value any) any {
	if number, ok := value.(json.Number); ok {
		if parsed, err := number.Float64(); err == nil {
			return parsed
		}
	}
	return value
}

// collapseDifferences writes a difference that recurs at several indexes of lists once, with * for
// each index and the count, so that a field that every tool gets takes one line.
func collapseDifferences(differences []string) []string {
	index := regexp.MustCompile(`\.\d+(\.|$)`)
	general := func(difference string) string {
		path, rest, _ := strings.Cut(difference, ": ")
		return index.ReplaceAllString(path, ".*$1") + ": " + rest
	}
	counts := map[string]int{}
	for _, difference := range differences {
		counts[general(difference)]++
	}
	var collapsed []string
	for _, difference := range differences {
		switch key := general(difference); counts[key] {
		case 0:
		case 1:
			collapsed = append(collapsed, difference)
		default:
			collapsed = append(collapsed, fmt.Sprintf("%s (%d times)", key, counts[key]))
			counts[key] = 0
		}
	}
	return collapsed
}

func shortJSON(value any) string {
	encoded, _ := json.Marshal(value)
	if len(encoded) > 160 {
		return string(encoded[:157]) + "..."
	}
	return string(encoded)
}
