package billing

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// authorizationArgumentsRecord holds one authorization of each kind, as the gateway sends it to
// authorize_gateway_holds and, field by field, to authorize_gateway_hold, and what the gateway
// needs the hold to return. A release keeps sending these arguments and reading holds this way
// until it stops, so the database's functions must suit the record of every release that still
// runs; they are tested against each release's copy of this file. Its identifiers name rows that
// such a test replaces with its own.
const authorizationArgumentsRecord = "testdata/authorization-arguments.json"

type authorizationArgumentsFile struct {
	// Identifiers maps each kind of row to the value that stands for it in the authorizations.
	Identifiers    map[string]string                  `json:"identifiers"`
	Authorizations map[string]*authorizationArguments `json:"authorizations"`
	// Holds says, for each kind, what the gateway needs from a hold that the database made.
	Holds map[string]recordedHold `json:"holds"`
}

// recordedHold is what the gateway needs from a hold of one kind.
type recordedHold struct {
	// Binding names each key of upstream_byok_binding, as a dotted path, without which the gateway
	// refuses the hold, with its JSON type or, when the gateway compares it, its value. Null when
	// the gateway takes the hold only without a binding.
	Binding map[string]recordedValue `json:"binding"`
}

type recordedValue struct {
	Type   string `json:"type,omitempty"`
	Equals any    `json:"equals,omitempty"`
}

const (
	recordedKeyID         = "00000000-0000-7000-8000-00000000000a"
	recordedHashedKey     = "recorded-hashed-key"
	recordedByokID        = "00000000-0000-7000-8000-00000000000b"
	recordedEncryptionKey = "0000000000000000000000000000000000000000000000000000000000000c0c"
	recordedActorUserID   = "recorded-actor-user"
	recordedSessionID     = "recorded-session"
	recordedRequestID     = "00000000-0000-7000-8000-00000000000d"
	recordedHoldID        = "00000000-0000-7000-8000-00000000000e"
	recordedPolicyID      = "recorded-policy"
	recordedNodeID        = "recorded-node-000000000000000000000000000000000000000000000000000000000000000f"
)

var recordedIdentifiers = map[string]string{
	"keyId":           recordedKeyID,
	"hashedKey":       recordedHashedKey,
	"byokId":          recordedByokID,
	"encryptionKeyId": recordedEncryptionKey,
	"actorUserId":     recordedActorUserID,
	"sessionId":       recordedSessionID,
	"requestId":       recordedRequestID,
	"holdId":          recordedHoldID,
	"policyId":        recordedPolicyID,
	"nodeId":          recordedNodeID,
}

func recordedAuthorizations(t *testing.T) map[string]*authorizationArguments {
	t.Helper()
	started := time.Date(2026, 1, 2, 3, 4, 5, 678901000, time.UTC)
	versions := PolicyVersions{{Scope: policy.KeyScope, ID: recordedPolicyID, Revision: 1}}
	base := func(mode string, byokID string) *authorizationArguments {
		cached, err := json.Marshal(cachedByok{Mode: mode, ID: nullableString(byokID)})
		if err != nil {
			t.Fatal(err)
		}
		keyID, hashedKey, nodeID := recordedKeyID, recordedHashedKey, recordedNodeID
		return &authorizationArguments{
			HashedKey:                &hashedKey,
			KeyID:                    &keyID,
			RequestID:                recordedRequestID,
			HoldID:                   recordedHoldID,
			ProviderKey:              "chutes",
			ProductKey:               "gpt-4o-mini",
			EstimatedUpstreamCostUSD: "0.01",
			ExpiresAt:                started.Add(15 * time.Minute),
			HoldParamsHash:           createHoldParamsHash("chutes", "gpt-4o-mini", ""),
			AuthorizeBefore:          started.Add(authorizeTimeout),
			ReservedTokens:           1000,
			ActiveUntil:              started.Add(15*time.Minute - holdSettlementExpiryBuffer + time.Minute),
			CredentialsGeneration:    1,
			CachedByok:               cached,
			PolicyVersions:           &versions,
			ActiveRules:              []matchedRule{},
			InputTextBytes:           100,
			NodeID:                   &nodeID,
		}
	}
	withTarget := func(arguments *authorizationArguments, target UpstreamTarget) *authorizationArguments {
		encoded, err := json.Marshal(target)
		if err != nil {
			t.Fatal(err)
		}
		arguments.ProviderKey, arguments.ProductKey = "azure", "gpt-5.6-sol"
		arguments.UpstreamTarget = encoded
		arguments.HoldParamsHash = createHoldParamsHash("azure", "gpt-5.6-sol", string(encoded))
		return arguments
	}
	azure := UpstreamTarget{
		DeploymentType: "global_standard",
		Hosting:        "azure",
		Model:          "gpt-5.6-sol",
		ModelFormat:    "OpenAI",
		ModelVersion:   "2026-07-09",
	}
	inPlaces := azure
	inPlaces.ProcessingLocations, inPlaces.StorageLocations = []string{"US"}, []string{"US"}
	inPlaces.VersionUnreported = true

	stored := base("stored", recordedByokID)
	stored.ProviderKey, stored.ProductKey = "openai", "gpt-4o-mini"
	stored.HoldParamsHash = createHoldParamsHash("openai", "gpt-4o-mini", "")
	encrypted := base("encrypted", recordedByokID)
	encrypted.ProviderKey, encrypted.ProductKey = "openai", "gpt-4o-mini"
	encrypted.HoldParamsHash = createHoldParamsHash("openai", "gpt-4o-mini", "")
	encryptionKeyID := recordedEncryptionKey
	encrypted.EncryptionKeyID = &encryptionKeyID
	azureEncrypted := withTarget(base("encrypted", recordedByokID), azure)
	azureEncrypted.EncryptionKeyID = &encryptionKeyID
	withRule := base("managed", "")
	withRule.ActiveRules = []matchedRule{{Scope: policy.KeyScope, ID: recordedPolicyID, Rule: "recorded-rule"}}
	dashboard := base("managed", "")
	actor, session := recordedActorUserID, recordedSessionID
	dashboard.HashedKey, dashboard.DashboardActorUserID, dashboard.DashboardSessionID = nil, &actor, &session
	return map[string]*authorizationArguments{
		"managed":           base("managed", ""),
		"stored":            stored,
		"encrypted":         encrypted,
		"azure stored":      withTarget(base("stored", recordedByokID), azure),
		"azure in places":   withTarget(base("stored", recordedByokID), inPlaces),
		"azure encrypted":   azureEncrypted,
		"matched rule":      withRule,
		"dashboard session": dashboard,
	}
}

// The record changes only with the arguments that the gateway sends. Set
// STOGAS_RECORD_DATABASE_ARGUMENTS=1 to write it after such a change; every database that a
// release still uses must then accept both the earlier record and the new one.
func TestAuthorizationArgumentsMatchTheirRecord(t *testing.T) {
	authorizations := recordedAuthorizations(t)
	encoded, err := json.MarshalIndent(authorizationArgumentsFile{
		Identifiers:    recordedIdentifiers,
		Authorizations: authorizations,
		Holds:          recordedHolds(t, authorizations),
	}, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if os.Getenv("STOGAS_RECORD_DATABASE_ARGUMENTS") == "1" {
		if err := os.MkdirAll(filepath.Dir(authorizationArgumentsRecord), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(authorizationArgumentsRecord, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	recorded, err := os.ReadFile(authorizationArgumentsRecord)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recorded, encoded) {
		t.Fatalf("%s does not match the arguments that authorizations send; record them again with STOGAS_RECORD_DATABASE_ARGUMENTS=1", authorizationArgumentsRecord)
	}
}

// Each authorization reaches both functions with the same values.
func TestRecordedAuthorizationsAreWhatBothFunctionsReceive(t *testing.T) {
	for name, arguments := range recordedAuthorizations(t) {
		encoded, err := json.Marshal(arguments)
		if err != nil {
			t.Fatal(err)
		}
		var member map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &member); err != nil {
			t.Fatal(err)
		}
		values := arguments.values(nil, nil)
		// The batch member names every argument but the two that only a single authorization takes.
		if len(member) != len(values)-2 {
			t.Fatalf("%s: batch member has %d keys for %d arguments", name, len(member), len(values)-2)
		}
		for key, want := range map[string]string{"upstream_target": string(arguments.UpstreamTarget), "cached_byok": string(arguments.CachedByok)} {
			if want == "" {
				want = "null"
			}
			if string(member[key]) != want {
				t.Fatalf("%s: batch %s = %s, single = %s", name, key, member[key], want)
			}
		}
	}
}

// recordedHolds finds what the gateway needs from each kind of hold by asking the method that
// takes the hold's binding: whether it takes a hold without one, and otherwise which keys of a
// complete binding it cannot do without and which of their values it compares.
func recordedHolds(t *testing.T, authorizations map[string]*authorizationArguments) map[string]recordedHold {
	t.Helper()
	holds := map[string]recordedHold{}
	complete := completeAzureBinding(t)
	for name, arguments := range authorizations {
		var cached cachedByok
		if err := json.Unmarshal(arguments.CachedByok, &cached); err != nil {
			t.Fatal(err)
		}
		takes := func(binding map[string]any) bool {
			if binding == nil {
				return (&Authorization{}).takeBinding(cached.Mode, arguments.ProviderKey, nil)
			}
			encoded, err := json.Marshal(binding)
			if err != nil {
				t.Fatal(err)
			}
			raw := string(encoded)
			return (&Authorization{}).takeBinding(cached.Mode, arguments.ProviderKey, &raw)
		}
		if takes(nil) {
			if takes(complete) {
				t.Fatalf("%s: the gateway takes a hold both with and without a binding", name)
			}
			holds[name] = recordedHold{}
			continue
		}
		if !takes(complete) {
			t.Fatalf("%s: the gateway takes no complete binding; set the values that it compares in completeAzureBinding", name)
		}
		needs := map[string]recordedValue{}
		for _, path := range leafPaths(complete, "") {
			if takes(withPath(complete, path, nil, true)) {
				continue
			}
			value := pathValue(complete, path)
			if takes(withPath(complete, path, otherValue(value), false)) {
				needs[path] = recordedValue{Type: jsonType(value)}
			} else {
				needs[path] = recordedValue{Equals: value}
			}
		}
		holds[name] = recordedHold{Binding: needs}
	}
	return holds
}

// completeAzureBinding is a binding with every key that the gateway knows set, and the values
// that it compares.
func completeAzureBinding(t *testing.T) map[string]any {
	t.Helper()
	bound := azureBoundBinding{Schema: "stogas.azure-binding.v1"}
	fillZero(reflect.ValueOf(&bound).Elem())
	encoded, err := json.Marshal(bound)
	if err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err := json.Unmarshal(encoded, &binding); err != nil {
		t.Fatal(err)
	}
	return binding
}

// fillZero sets every zero field to a value of its kind.
func fillZero(value reflect.Value) {
	if value.Type() == reflect.TypeOf(time.Time{}) {
		if value.IsZero() {
			value.Set(reflect.ValueOf(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)))
		}
		return
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		fillZero(value.Elem())
	case reflect.Struct:
		for i := range value.NumField() {
			if value.Type().Field(i).IsExported() {
				fillZero(value.Field(i))
			}
		}
	case reflect.String:
		if value.String() == "" {
			value.SetString("recorded")
		}
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if value.Int() == 0 {
			value.SetInt(1)
		}
	case reflect.Float32, reflect.Float64:
		if value.Float() == 0 {
			value.SetFloat(1)
		}
	case reflect.Slice:
		if value.Len() == 0 {
			value.Set(reflect.MakeSlice(value.Type(), 1, 1))
			fillZero(value.Index(0))
		}
	}
}

func leafPaths(value map[string]any, prefix string) []string {
	var paths []string
	for key, child := range value {
		if object, ok := child.(map[string]any); ok {
			paths = append(paths, leafPaths(object, prefix+key+".")...)
		} else {
			paths = append(paths, prefix+key)
		}
	}
	slices.Sort(paths)
	return paths
}

func pathValue(value map[string]any, path string) any {
	keys := strings.Split(path, ".")
	for _, key := range keys[:len(keys)-1] {
		value = value[key].(map[string]any)
	}
	return value[keys[len(keys)-1]]
}

// withPath copies value with the key at path set to replacement, or removed.
func withPath(value map[string]any, path string, replacement any, remove bool) map[string]any {
	key, rest, nested := strings.Cut(path, ".")
	copied := make(map[string]any, len(value))
	for k, v := range value {
		copied[k] = v
	}
	switch {
	case nested:
		copied[key] = withPath(value[key].(map[string]any), rest, replacement, remove)
	case remove:
		delete(copied, key)
	default:
		copied[key] = replacement
	}
	return copied
}

// otherValue is another value of the same JSON type, and another time for a time.
func otherValue(value any) any {
	switch typed := value.(type) {
	case string:
		if moment, err := time.Parse(time.RFC3339Nano, typed); err == nil {
			return moment.Add(time.Hour).Format(time.RFC3339Nano)
		}
		return typed + "-other"
	case bool:
		return !typed
	case float64:
		return typed + 1
	}
	return value
}

// jsonType names the JSON type of a value, and "time" for a string that the gateway reads as one.
func jsonType(value any) string {
	switch typed := value.(type) {
	case string:
		if _, err := time.Parse(time.RFC3339Nano, typed); err == nil {
			return "time"
		}
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "null"
}
