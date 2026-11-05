package catalog

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// testCatalog is the catalog that the gateway's tests read, which catalogtest installs for the
// other packages.
//
//go:embed catalogtest/generated
var testCatalog embed.FS

func readTestCatalog() ([]byte, map[string][]byte, error) {
	files, err := fs.Sub(testCatalog, "catalogtest/generated")
	if err != nil {
		return nil, nil, err
	}
	return ReadBuild(files)
}

// testFiles is the test catalog's root and every part that it names, by SHA-256 in hex.
func testFiles(tb testing.TB) ([]byte, map[string][]byte) {
	tb.Helper()
	root, parts, err := readTestCatalog()
	if err != nil {
		tb.Fatal(err)
	}
	return root, parts
}

// testSnapshot reads the test catalog with every record, as a gateway reads its fallback.
func testSnapshot(tb testing.TB) *snapshot {
	tb.Helper()
	root, parts := testFiles(tb)
	snap, err := snapshotFromFiles(root, parts, Identity{}, time.Time{})
	if err != nil {
		tb.Fatalf("parse the test catalog: %v", err)
	}
	return snap
}

// testCatalogJSON is the test catalog as the gateway reads it, with every record, as one
// document: the graph, each dated state's changes and the selectors that have retired. Tests
// change it and read it with snapshotFromCatalogBytes.
var testCatalogJSON = func() []byte {
	root, parts, err := readTestCatalog()
	if err != nil {
		panic(err)
	}
	files, err := partFiles(root)
	if err != nil {
		panic(err)
	}
	compiled, err := assemble(root, files, parts, time.Time{})
	if err != nil {
		panic(err)
	}
	data, err := json.Marshal(compiled)
	if err != nil {
		panic(err)
	}
	return data
}()

// TestMain makes the test catalog the active catalog, as a gateway reads its fallback.
func TestMain(m *testing.M) {
	root, parts, err := readTestCatalog()
	if err != nil {
		panic(err)
	}
	snap, err := snapshotFromFiles(root, parts, Identity{}, time.Time{})
	if err != nil {
		panic(err)
	}
	active.Store(snap)
	os.Exit(m.Run())
}

// useFallback makes the fallback the active catalog until the test ends, for a test that checks
// the gateway against every record that the gateway can serve.
func useFallback(tb testing.TB) *snapshot {
	tb.Helper()
	snap, err := loadSnapshot()
	if err != nil {
		tb.Fatalf("load the fallback: %v", err)
	}
	prior := active.Swap(snap)
	tb.Cleanup(func() { active.Store(prior) })
	return snap
}

func snapshotFromCatalogBytes(data []byte) (*snapshot, error) {
	var compiled compiledCatalog
	if err := decodeStrict(data, &compiled, sharedJSON[Pricing]()); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	return snapshotFromCompiled(compiled)
}

// testRelease is a release's root and parts as JSON values. A test changes them and then writes
// them, which names each part in the root by its new digest and size.
type testRelease struct {
	root  map[string]any
	parts []map[string]any
}

func testCatalogRelease(tb testing.TB) testRelease {
	tb.Helper()
	root, parts := testFiles(tb)
	var release testRelease
	if err := json.Unmarshal(root, &release.root); err != nil {
		tb.Fatal(err)
	}
	for _, file := range release.root["parts"].([]any) {
		var part map[string]any
		if err := json.Unmarshal(parts[file.(map[string]any)["sha256"].(string)], &part); err != nil {
			tb.Fatal(err)
		}
		release.parts = append(release.parts, part)
	}
	return release
}

func (r testRelease) summary(kind, id string) map[string]any {
	return r.root["summaries"].(map[string]any)[kind].(map[string]any)[id].(map[string]any)
}

// record is the record that the summary of a model, route or deployment places in a part.
func (r testRelease) record(kind, id string) map[string]any {
	part := r.parts[int(r.summary(kind, id)["part"].(float64))]
	return part["graph"].(map[string]any)[kind].(map[string]any)[id].(map[string]any)
}

func (r testRelease) files(tb testing.TB) ([]byte, map[string][]byte) {
	tb.Helper()
	parts := make(map[string][]byte, len(r.parts))
	for index, part := range r.parts {
		data, err := json.Marshal(part)
		if err != nil {
			tb.Fatal(err)
		}
		sum := sha256.Sum256(data)
		file := r.root["parts"].([]any)[index].(map[string]any)
		file["sha256"], file["size"] = hex.EncodeToString(sum[:]), len(data)
		parts[file["sha256"].(string)] = data
	}
	root, err := json.Marshal(r.root)
	if err != nil {
		tb.Fatal(err)
	}
	return root, parts
}

// The test catalog's dated part holds the records that retire, the last of them on 2128-03-11,
// so it leaves at 12:00 UTC on 2128-03-12.
var datedPartLeaves = time.Date(2128, time.March, 12, 12, 0, 0, 0, time.UTC)

func TestReleaseLeavesRecordsOutOnceTheyRetire(t *testing.T) {
	root, parts := testFiles(t)
	files, err := partFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	// Parts of what Stogas does not serve come last and are never in effect.
	served := slices.DeleteFunc(slices.Clone(files), func(file PartFile) bool { return file.StogasUnsupported })
	if len(served) == len(files) || !files[len(files)-1].StogasUnsupported {
		t.Fatal("the test catalog's last part does not list what Stogas does not serve")
	}
	dated := served[len(served)-1]
	if dated.Through == nil || *dated.Through != "2128-03-11" {
		t.Fatalf("the test catalog's last part that Stogas serves is not the dated one: %#v", dated)
	}
	before := datedPartLeaves.Add(-time.Nanosecond)
	if inEffect, err := PartsInEffect(root, before); err != nil || len(inEffect) != len(served) {
		t.Fatalf("parts in effect before the dated part leaves: %v, %v", inEffect, err)
	}
	if inEffect, err := PartsInEffect(root, datedPartLeaves); err != nil || len(inEffect) != len(served)-1 ||
		inEffect[len(inEffect)-1].SHA256 == dated.SHA256 {
		t.Fatalf("parts in effect once the dated part leaves: %v, %v", inEffect, err)
	}

	// Until then, the part's records that have not retired serve, and the others name the day
	// that they retired.
	snap, err := snapshotFromFiles(root, parts, Identity{}, before)
	if err != nil {
		t.Fatal(err)
	}
	if deployment, ok := snap.graph.Deployments["azure-gpt-6-luna"]; !ok || *deployment.RetirementDate != "2128-03-11" {
		t.Fatalf("a deployment that retires on 2128-03-11 left before it retired: %#v", deployment)
	}
	for selector, date := range map[string]string{
		"deepseek-v4-flash-0423":       "2128-02-20",
		"azure-deepseek-v4-flash-0423": "2128-02-20",
		"azure-gpt-5.6-luna":           "2128-01-11",
	} {
		if _, served := snap.graph.Deployments[selector]; served {
			t.Fatalf("retired %s is still in the graph", selector)
		}
		if _, err := snap.parseModelSelection(selector); err != modelRetired(date) {
			t.Fatalf("%s: %v, want it retired on %s", selector, err, date)
		}
	}
	if _, ok := snap.graph.Models["deepseek-v4-flash-0423"]; ok {
		t.Fatal("a model whose deployments retired is still in the graph")
	}

	// Once the part leaves, the release loads without it, and every one of its records names
	// the day that it retired.
	held := maps.Clone(parts)
	delete(held, dated.SHA256)
	if _, err := snapshotFromFiles(root, held, Identity{}, before); err == nil || !strings.Contains(err.Error(), "in effect but missing") {
		t.Fatalf("a release without a part in effect loaded: %v", err)
	}
	snap, err = snapshotFromFiles(root, held, Identity{}, datedPartLeaves)
	if err != nil {
		t.Fatal(err)
	}
	for id, deployment := range snap.graph.Deployments {
		if deployment.RetirementDate != nil {
			t.Fatalf("deployment %s of the dated part is in the graph", id)
		}
	}
	if _, err := snap.parseModelSelection("azure-gpt-6-luna"); err != modelRetired("2128-03-11") {
		t.Fatalf("azure-gpt-6-luna: %v, want it retired on 2128-03-11", err)
	}
	if _, ok := snap.parts[dated.SHA256]; ok || len(snap.parts) != len(held) {
		t.Fatal("the release holds a part that it did not come with")
	}
}

// A model field that names what has retired gets model_retired with the day on which it retired,
// for every kind of term and their combinations, whether the day ended while the release served or
// before it loaded. What still serves somewhere does not.
func TestRetiredSelectionsNameTheirDayWheneverTheyRetired(t *testing.T) {
	root, parts := testFiles(t)
	noon := func(year int, month time.Month, day int) time.Time {
		return time.Date(year, month, day, 12, 0, 0, 0, time.UTC)
	}
	type check struct {
		field string
		want  variant
		// date is the day that the field names as retired once the instant passes; empty when
		// something that it selects still serves.
		date string
	}
	for _, retirement := range []struct {
		ends   time.Time
		route  Route
		checks []check
	}{{
		// gpt-oss, its one model and both of its Azure deployments retire on 2127-09-15.
		ends: noon(2127, time.September, 16), route: RouteChat,
		checks: []check{
			{field: "gpt-oss", date: "2127-09-15"},
			{field: "group:gpt-oss", date: "2127-09-15"},
			{field: "gpt-oss-120b", date: "2127-09-15"},
			{field: "openai/gpt-oss-120b", date: "2127-09-15"},
			{field: "azure-gpt-oss-120b-us", date: "2127-09-15"},
			{field: "provider:azure gpt-oss", date: "2127-09-15"},
		},
	}, {
		// Azure's Claude Opus 5.5 retires on 2127-09-18, and Anthropic's goes on.
		ends: noon(2127, time.September, 19), route: RouteChat,
		checks: []check{
			{field: "provider:azure claude-opus-5-5", date: "2127-09-18"},
			{field: "route:azure-anthropic-messages claude-opus-5-5", date: "2127-09-18"},
			{field: "author:anthropic provider:azure"},
			{field: "azure-claude-opus-5-5-us", date: "2127-09-18"},
			{field: "claude-opus-5-5"},
			{field: "group:claude-opus provider:anthropic"},
		},
	}, {
		// Azure's Fast deployments retire before its Standard ones, so a Fast request for the
		// model finds no Fast deployment on Azure, but the model has not retired there.
		ends: noon(2127, time.January, 16), route: RouteChat,
		checks: []check{
			{field: "azure-claude-opus-5-5-fast", date: "2127-01-15"},
			{field: "provider:azure claude-opus-5-5", want: variant{tier: TierFast}},
		},
	}, {
		// A route retires before the deployments that another route serves.
		ends: noon(2128, time.March, 12), route: RouteResponses,
		checks: []check{
			{field: "route:azure-responses", date: "2128-03-11"},
			{field: "route:azure-responses gpt-6-luna", date: "2128-03-11"},
			// Every Azure deployment of OpenAI's models has retired by then.
			{field: "author:openai provider:azure", date: "2128-03-11"},
			{field: "provider:azure gpt-6", date: "2128-03-11"},
		},
	}} {
		loaded := map[string]time.Time{"before": retirement.ends.Add(-time.Hour), "at": retirement.ends}
		for when, at := range loaded {
			held := parts
			if when == "at" {
				// Once a part's records have all retired, a release comes without it.
				files, err := PartsInEffect(root, at)
				if err != nil {
					t.Fatal(err)
				}
				held = make(map[string][]byte, len(files))
				for _, file := range files {
					held[file.SHA256] = parts[file.SHA256]
				}
			}
			snap, err := snapshotFromFiles(root, held, Identity{}, at)
			if err != nil {
				t.Fatalf("load %s %s: %v", when, retirement.ends, err)
			}
			active.Store(snap)
			for _, check := range retirement.checks {
				if when == "before" {
					_, err := routingSelectionsForRequest(retirement.ends.Add(-time.Nanosecond), retirement.route, check.field, check.want, nil, nil)
					if apiErr, ok := err.(APIError); ok && apiErr.Code == "model_retired" {
						t.Fatalf("%q retired before %s: %v", check.field, retirement.ends, err)
					}
				}
				_, err := routingSelectionsForRequest(retirement.ends, retirement.route, check.field, check.want, nil, nil)
				apiErr, retired := err.(APIError)
				retired = retired && apiErr.Code == "model_retired"
				switch {
				case check.date == "" && retired:
					t.Fatalf("loaded %s %s: %q retired although some of it serves: %v", when, retirement.ends, check.field, err)
				case check.date != "" && err != modelRetired(check.date):
					t.Fatalf("loaded %s %s: %q: %v, want it retired on %s", when, retirement.ends, check.field, err, check.date)
				}
			}
		}
	}
	loadTestCatalog(t)
}

// The test catalog's one deployment that Stogas does not serve, through its one route of the same.
const (
	unsupportedDeployment = "openai-gpt-5.5-2026-04-23-batch"
	unsupportedReason     = "The gateway answers each request as it arrives and has no batch API."
)

// A model field that names only what Stogas does not serve gets model_unavailable with Stogas's
// reason, while a model that Stogas serves elsewhere goes on. The gateway never reads the part
// that holds these records, so a release loads without it.
func TestUnsupportedSelectionsGiveTheReason(t *testing.T) {
	root, parts := testFiles(t)
	files, err := partFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	held := maps.Clone(parts)
	for _, file := range files {
		if file.StogasUnsupported {
			delete(held, file.SHA256)
		}
	}
	if len(held) == len(parts) {
		t.Fatal("the test catalog has no part of what Stogas does not serve")
	}
	for when, loaded := range map[string]map[string][]byte{"with every part": parts, "without the unserved part": held} {
		snap, err := snapshotFromFiles(root, loaded, Identity{}, time.Time{})
		if err != nil {
			t.Fatalf("load %s: %v", when, err)
		}
		if _, ok := snap.graph.Deployments[unsupportedDeployment]; ok {
			t.Fatalf("loaded %s: a deployment that Stogas does not serve is in the graph", when)
		}
		active.Store(snap)
		for field, unsupported := range map[string]bool{
			unsupportedDeployment:                       true,
			"deployment:" + unsupportedDeployment:       true,
			"route:openai-batch":                        true,
			"route:openai-batch gpt-5.5-2026-04-23":     true,
			"provider:openai route:openai-batch":        true,
			"gpt-5.5-2026-04-23":                        false,
			"provider:openai gpt-5.5-2026-04-23":        false,
			"route:openai-responses gpt-5.5-2026-04-23": false,
		} {
			_, err := routingSelectionsForRequest(time.Now(), RouteResponses, field, variant{}, nil, nil)
			if got := err == modelUnsupported(unsupportedReason); got != unsupported {
				t.Fatalf("loaded %s: %q: %v, want Stogas's reason: %t", when, field, err, unsupported)
			}
		}
	}

	// A term that retired goes first, whatever the order: Azure's gpt-oss deployments retire on
	// 2127-09-15.
	retired := time.Date(2127, time.September, 16, 12, 0, 0, 0, time.UTC)
	snap, err := snapshotFromFiles(root, held, Identity{}, retired)
	if err != nil {
		t.Fatal(err)
	}
	active.Store(snap)
	for _, field := range []string{"route:openai-batch azure-gpt-oss-120b-us", "azure-gpt-oss-120b-us route:openai-batch"} {
		if _, err := routingSelectionsForRequest(retired, RouteResponses, field, variant{}, nil, nil); err != modelRetired("2127-09-15") {
			t.Fatalf("%q: %v, want it retired on 2127-09-15", field, err)
		}
	}
	loadTestCatalog(t)
}

// A selection whose paths have all retired or are not served names the day on which the last
// one retired; one whose paths are all not served gives the reason of the first path by
// deployment and route; one with a path that serves gets neither.
func TestUnservedSelectionNamesRetirementBeforeReason(t *testing.T) {
	retired, now := "2127-01-15", time.Date(2128, time.January, 1, 0, 0, 0, 0, time.UTC)
	path := func(deployment, route, reason string, date *string) servedPath {
		return servedPath{model: "m", deployment: deployment, route: route, unsupported: reason, retirementDate: date}
	}
	for _, test := range []struct {
		paths []servedPath
		want  error
	}{
		{[]servedPath{path("b", "r", "Reason B.", nil), path("a", "s", "Reason A2.", nil), path("a", "r", "Reason A.", nil)}, modelUnsupported("Reason A.")},
		{[]servedPath{path("a", "r", "Reason A.", nil), path("c", "r", "", &retired)}, modelRetired(retired)},
		{[]servedPath{path("a", "r", "Reason A.", nil), path("c", "r", "", &retired), path("d", "r", "", nil)}, nil},
		{[]servedPath{path("a", "r", "Reason A.", nil), path("d", "r", "", nil)}, nil},
	} {
		snap := &snapshot{index: &selectorIndex{paths: test.paths}}
		if err := snap.unservedSelection(modelSelection{model: "m"}, now); err != test.want {
			t.Fatalf("%+v: %v, want %v", test.paths, err, test.want)
		}
		if err := snap.unservedSelection(modelSelection{model: "other"}, now); err != nil {
			t.Fatalf("a selection of no path: %v", err)
		}
	}
}

// A deployment that two routes serve goes on through the one that stays once the other retires,
// as the catalog build dates it, and the release still loads.
func TestDeploymentOutlivesOneOfItsRoutes(t *testing.T) {
	release := testCatalogRelease(t)
	const retiring, staying = "openai-chat-completions", "openai-responses"
	deploymentID := ""
	for id, raw := range release.root["summaries"].(map[string]any)["deployments"].(map[string]any) {
		routes, _ := release.record("deployments", id)["routes"].(map[string]any)
		if raw.(map[string]any)["retirementDate"] == nil && routes[retiring] != nil && routes[staying] != nil {
			deploymentID = id
			break
		}
	}
	if deploymentID == "" {
		t.Fatalf("no live deployment is served by both %s and %s", retiring, staying)
	}
	// The build dates the route, and each deployment that only the route serves.
	date := "2127-06-01"
	release.summary("routes", retiring)["retirementDate"] = date
	release.record("routes", retiring)["retirementDate"] = date
	for id, raw := range release.root["summaries"].(map[string]any)["deployments"].(map[string]any) {
		routes, _ := release.record("deployments", id)["routes"].(map[string]any)
		if _, only := routes[retiring]; only && len(routes) == 1 && raw.(map[string]any)["retirementDate"] == nil {
			raw.(map[string]any)["retirementDate"] = date
			release.record("deployments", id)["retirementDate"] = date
		}
	}
	root, parts := release.files(t)
	after := time.Date(2127, time.June, 2, 12, 0, 0, 0, time.UTC)
	snap, err := snapshotFromFiles(root, parts, Identity{}, after)
	if err != nil {
		t.Fatalf("the release did not load once one route of %s retired: %v", deploymentID, err)
	}
	if _, ok := snap.graph.Routes[retiring]; ok {
		t.Fatalf("retired route %s is still in the graph", retiring)
	}
	route, ok := snap.graph.Routes[staying]
	if !ok || !slices.Contains(route.DeploymentIDs, deploymentID) {
		t.Fatalf("%s no longer serves %s", staying, deploymentID)
	}
	if _, ok := snap.deploymentFromCompiledAt(deploymentID, route, after); !ok {
		t.Fatalf("%s does not serve through %s", deploymentID, staying)
	}
}

func TestRoutesServeUntilTheirDateHasEndedEverywhere(t *testing.T) {
	loadTestCatalog(t)
	snap := activeState()
	routes := snap.routes(schemas.OpenAI, RouteResponses)
	if len(routes) == 0 {
		t.Fatal("the OpenAI Responses route is missing")
	}
	route := routes[0]
	now := time.Now()
	deploymentID := ""
	for _, id := range route.DeploymentIDs {
		if deploymentAvailableAt(snap.graph.Deployments[id], now) {
			deploymentID = id
			break
		}
	}
	if _, ok := snap.deploymentFromCompiledAt(deploymentID, route, now); !ok {
		t.Fatalf("%s did not serve through %s", deploymentID, route.ID)
	}
	// The route's date has ended everywhere two days later.
	route.RetirementDate = stringPointer(now.AddDate(0, 0, -2).Format(time.DateOnly))
	if _, ok := snap.deploymentFromCompiledAt(deploymentID, route, now); ok {
		t.Fatalf("%s served through a retired route", deploymentID)
	}
	if servesAt(snap.graph.Deployments[deploymentID], route, now) {
		t.Fatalf("a retired route served %s", deploymentID)
	}
	route.RetirementDate = stringPointer(now.AddDate(0, 0, 1).Format(time.DateOnly))
	if _, ok := snap.deploymentFromCompiledAt(deploymentID, route, now); !ok {
		t.Fatal("a route stopped serving before its date")
	}

	deployment := &compiledDeployment{}
	route = compiledRoute{RetirementDate: stringPointer("2026-08-01")}
	ends := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	for at, serves := range map[time.Time]bool{
		ends.Add(-time.Nanosecond): true,
		ends:                       false,
	} {
		if servesAt(deployment, route, at) != serves {
			t.Fatalf("at %s, serves = %t", at, !serves)
		}
	}
	if !servesAt(deployment, compiledRoute{}, ends.AddDate(100, 0, 0)) {
		t.Fatal("a route without a retirement date retired")
	}
}

func TestDeploymentsServeUntilTheirDateHasEndedEverywhere(t *testing.T) {
	deployment := &compiledDeployment{RetirementDate: stringPointer("2026-08-01")}
	ends := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	for at, available := range map[time.Time]bool{
		time.Date(2026, time.August, 1, 23, 59, 59, 0, time.FixedZone("UTC-12", -12*60*60)): true,
		ends.Add(-time.Nanosecond): true,
		ends:                       false,
		ends.In(time.FixedZone("UTC+14", 14*60*60)): false,
	} {
		if deploymentAvailableAt(deployment, at) != available {
			t.Fatalf("at %s, available = %t", at, !available)
		}
	}
	if !deploymentAvailableAt(&compiledDeployment{}, ends.AddDate(100, 0, 0)) {
		t.Fatal("a deployment without a retirement date retired")
	}
}

func TestPartFilesCheckWhatARootNames(t *testing.T) {
	name := func(n int) string { return fmt.Sprintf("%064x", n) }
	part := func(n, size int, through string) string {
		return `{"sha256":"` + name(n) + `","size":` + strconv.Itoa(size) + `,"through":` + through + `}`
	}
	parts := func(count, size int) string {
		listed := make([]string, count)
		for n := range count {
			listed[n] = part(n+1, size, "null")
		}
		return strings.Join(listed, ",")
	}
	root := func(parts string) []byte {
		return []byte(`{"schema":"stogas.catalog.v11","parts":[` + parts + `]}`)
	}
	listed, err := partFiles(root(part(1, 1, "null") + "," + part(2, 3, `"2028-02-29"`)))
	if want := []PartFile{{name(1), 1, nil, false}, {name(2), 3, stringPointer("2028-02-29"), false}}; err != nil || !reflect.DeepEqual(listed, want) {
		t.Fatalf("listed %v, want %v: %v", listed, want, err)
	}
	const mebibyte = 1024 * 1024
	for problem, test := range map[string]struct {
		root    []byte
		message string
	}{
		"another schema":      {[]byte(`{"schema":"stogas.catalog.v8","parts":[]}`), "unsupported"},
		"no root":             {nil, "size is outside"},
		"a large root":        {append(root(""), bytes.Repeat([]byte(" "), rootSizeLimit)...), "size is outside"},
		"an uppercase digest": {root(`{"sha256":"` + strings.Repeat("A", 64) + `","size":1,"through":null}`), "invalid part"},
		"a short digest":      {root(`{"sha256":"` + strings.Repeat("a", 63) + `","size":1,"through":null}`), "invalid part"},
		"an empty part":       {root(part(1, 0, "null")), "invalid part"},
		"a large part":        {root(part(1, mebibyte+1, "null")), "invalid part"},
		"a repeated part":     {root(part(1, 1, "null") + "," + part(1, 1, "null")), "invalid part"},
		"an impossible date":  {root(part(1, 1, `"2027-02-29"`)), "invalid part"},
		"a time for a date":   {root(part(1, 1, `"2027-02-28T00:00:00Z"`)), "invalid part"},
		"a large catalog":     {root(parts(128, mebibyte)), "exceeds"},
	} {
		if _, err := partFiles(test.root); err == nil || !strings.Contains(err.Error(), test.message) {
			t.Fatalf("a root with %s was accepted: %v", problem, err)
		}
	}
}

func TestReleaseRefusesFilesThatDifferFromTheRoot(t *testing.T) {
	const deployment = "azure-gpt-6-luna"
	for problem, test := range map[string]struct {
		change  func(testRelease)
		message string
	}{
		"a record in another part": {func(r testRelease) {
			r.summary("deployments", "anthropic-claude-fable-5")["part"] = 1
		}, "places elsewhere"},
		"a missing record": {func(r testRelease) {
			delete(r.parts[2]["graph"].(map[string]any)["deployments"].(map[string]any), deployment)
		}, "omits a record"},
		"a summary without a part": {func(r testRelease) {
			r.summary("models", "deepseek-v4-flash-0423")["part"] = len(r.parts)
		}, "names no part"},
		"a record that retires after its part": {func(r testRelease) {
			r.summary("deployments", deployment)["retirementDate"] = "2128-03-12"
			r.record("deployments", deployment)["retirementDate"] = "2128-03-12"
		}, "retires after its part"},
		"a record that never retires in a dated part": {func(r testRelease) {
			r.summary("routes", "azure-responses")["retirementDate"] = nil
		}, "retires after its part"},
		"a deployment whose date differs from its summary": {func(r testRelease) {
			r.record("deployments", deployment)["retirementDate"] = "2128-03-10"
		}, "another date than its summary"},
		"a summary of what Stogas serves that gives a reason why it does not": {func(r testRelease) {
			r.summary("models", "deepseek-v4-flash-0423")["stogasUnsupported"] = "Stogas does not serve it."
		}, "differ on whether Stogas serves it"},
		"a summary of what Stogas does not serve without the reason": {func(r testRelease) {
			delete(r.summary("deployments", unsupportedDeployment), "stogasUnsupported")
		}, "differ on whether Stogas serves it"},
		"a group in the graph that Stogas does not serve": {func(r testRelease) {
			r.summary("groups", "gpt-5.5")["stogasUnsupported"] = "Stogas does not serve it."
		}, "but Stogas does not serve it"},
		"a change that the root does not list": {func(r testRelease) {
			r.parts[0]["schedule"] = []any{map[string]any{"start": "2027-01-01T00:00:00Z", "graph": map[string]any{}}}
		}, "does not list"},
		"another part schema": {func(r testRelease) {
			r.parts[1]["schema"] = "stogas.catalog.part.v8"
		}, "unsupported"},
		"an unknown record field": {func(r testRelease) {
			r.record("deployments", deployment)["notes"] = "unread"
		}, "unknown"},
		"an unknown root member": {func(r testRelease) {
			r.root["archive"] = nil
		}, "unknown"},
		"a part holding authors": {func(r testRelease) {
			r.parts[0]["graph"].(map[string]any)["authors"] = map[string]any{}
		}, "unknown"},
	} {
		t.Run(problem, func(t *testing.T) {
			release := testCatalogRelease(t)
			test.change(release)
			root, parts := release.files(t)
			if _, err := snapshotFromFiles(root, parts, Identity{}, time.Time{}); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error = %v, want %q", err, test.message)
			}
		})
	}

	root, parts := testCatalogRelease(t).files(t)
	if _, err := snapshotFromFiles(root, parts, Identity{}, time.Time{}); err != nil {
		t.Fatalf("the rewritten test catalog was refused: %v", err)
	}
	for problem, change := range map[string]func(map[string][]byte){
		"a changed part": func(parts map[string][]byte) {
			for name, data := range parts {
				parts[name] = append(bytes.Clone(data[:len(data)-1]), ' ')
				return
			}
		},
		"a part that the root does not name": func(parts map[string][]byte) {
			parts[strings.Repeat("0", 64)] = []byte(`{}`)
		},
	} {
		changed := maps.Clone(parts)
		change(changed)
		if _, err := snapshotFromFiles(root, changed, Identity{}, time.Time{}); err == nil || !strings.Contains(err.Error(), "the root") {
			t.Fatalf("a release with %s loaded: %v", problem, err)
		}
	}
	if _, err := snapshotFromFiles(root, parts, Identity{Sequence: 1, Digest: "sha256:" + strings.Repeat("0", 64)}, time.Time{}); err == nil ||
		!strings.Contains(err.Error(), "does not match the signed release") {
		t.Fatalf("a root under another digest loaded: %v", err)
	}
}

func TestActiveCatalogServesTheRootWithItsRelease(t *testing.T) {
	prior := active.Load()
	t.Cleanup(func() { active.Store(prior) })
	root, parts := testFiles(t)
	sum := sha256.Sum256(root)
	identity := Identity{Sequence: 7, Digest: "sha256:" + hex.EncodeToString(sum[:])}
	if err := InstallApproved(root, parts, identity, time.Now()); err != nil {
		t.Fatal(err)
	}
	served, ok := ActiveCatalog()
	if !ok {
		t.Fatal("the active catalog is unavailable")
	}
	var got, want map[string]any
	if err := json.Unmarshal(served, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(root, &want); err != nil {
		t.Fatal(err)
	}
	want["digest"], want["sequence"] = identity.Digest, float64(identity.Sequence)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("the served root differs from the root with its release")
	}
	for name, data := range parts {
		if held, ok := ActiveCatalogPart(name); !ok || !bytes.Equal(held, data) {
			t.Fatalf("part %s is not served", name)
		}
	}
	if _, ok := ActiveCatalogPart(strings.Repeat("0", 64)); ok {
		t.Fatal("a part that the release did not come with was served")
	}
}
