package billing

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// authorizationArgumentsRecord holds one authorization of each kind, as the gateway sends it to
// authorize_gateway_holds and, field by field, to authorize_gateway_hold. A release keeps sending
// these until it stops, so the database's functions must accept the record of every release that
// still runs; they are tested against each release's copy of this file. Its identifiers name rows
// that such a test replaces with its own.
const authorizationArgumentsRecord = "testdata/authorization-arguments.json"

type authorizationArgumentsFile struct {
	// Identifiers maps each kind of row to the value that stands for it in the authorizations.
	Identifiers    map[string]string                  `json:"identifiers"`
	Authorizations map[string]*authorizationArguments `json:"authorizations"`
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
		"matched rule":      withRule,
		"dashboard session": dashboard,
	}
}

// The record changes only with the arguments that the gateway sends. Set
// STOGAS_RECORD_DATABASE_ARGUMENTS=1 to write it after such a change; every database that a
// release still uses must then accept both the earlier record and the new one.
func TestAuthorizationArgumentsMatchTheirRecord(t *testing.T) {
	encoded, err := json.MarshalIndent(authorizationArgumentsFile{Identifiers: recordedIdentifiers, Authorizations: recordedAuthorizations(t)}, "", "\t")
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
