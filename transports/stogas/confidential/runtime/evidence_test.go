package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	verifier "github.com/StogasAI/verifier/go"
)

type bootEvidenceFixture struct {
	Root        verifier.TrustRoot `json:"root"`
	Bundle      json.RawMessage    `json:"bundle"`
	Boot        fixtureBoot        `json:"boot"`
	Inclusion   json.RawMessage    `json:"inclusion"`
	Now         int64              `json:"verified_at_ms"`
	RotatedKeys json.RawMessage    `json:"rotated_keys"`
}

// fixtureBoot is a real logged boot whose report commits the fixture's seeded keys.
type fixtureBoot struct {
	GatewayReleaseID     string `json:"gateway_release_id"`
	HardwarePolicySHA256 string `json:"hardware_policy_sha256"`
	Report               string `json:"report"`
	ReportData           struct {
		Environment           string `json:"environment"`
		HPKEPublicKey         string `json:"hpke_public_key"`
		RegistrationChallenge string `json:"registration_challenge"`
		Schema                string `json:"schema"`
		SigningPublicKey      string `json:"signing_public_key"`
		TLSSPKISHA256         string `json:"tls_spki_sha256"`
	} `json:"report_data"`
	Schema string `json:"schema"`
}

// document returns the exact logged bytes: sorted keys of ASCII-only fields and a newline.
func (boot fixtureBoot) document(t *testing.T) []byte {
	t.Helper()
	encoded, err := json.Marshal(boot)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func evidenceFixture(t *testing.T) bootEvidenceFixture {
	t.Helper()
	encoded, err := os.ReadFile("testdata/boot-evidence-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture bootEvidenceFixture
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func fixtureEvidence(t *testing.T, fixture bootEvidenceFixture, origins ...string) *currentEvidence {
	t.Helper()
	core, err := verifier.NewEvidence(verifier.EvidenceOptions{Environment: "staging", Root: &fixture.Root})
	if err != nil {
		t.Fatal(err)
	}
	e := &currentEvidence{verifier: core, client: &http.Client{}, now: func() time.Time { return time.UnixMilli(fixture.Now) }}
	for _, origin := range origins {
		e.origins = append(e.origins, evidenceOrigin{url: origin})
	}
	t.Cleanup(e.close)
	return e
}

func fixtureAppraisal(t *testing.T, fixture bootEvidenceFixture) func(*verifier.EvidenceSnapshot, evidenceSummary) error {
	t.Helper()
	document := fixture.Boot.document(t)
	return func(snapshot *verifier.EvidenceSnapshot, summary evidenceSummary) error {
		identity, err := snapshot.VerifyLoggedBootAt(document, fixture.Inclusion, time.UnixMilli(fixture.Now))
		if err != nil {
			return err
		}
		if identity.GatewayReleaseID != fixture.Boot.GatewayReleaseID || identity.NodeID == "" {
			return errors.New("wrong boot identity")
		}
		if _, ok := summary.catalog(identity.GatewayReleaseID); !ok {
			return errors.New("no compatible catalog")
		}
		return nil
	}
}

func TestEvidenceRecoveryAndOriginScopedConditionalReads(t *testing.T) {
	fixture := evidenceFixture(t)
	var conditional []string
	var conditionalMu sync.Mutex
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conditionalMu.Lock()
		conditional = append(conditional, r.Header.Get("If-None-Match"))
		conditionalMu.Unlock()
		w.Header().Set("ETag", `"primary"`)
		if r.Header.Get("If-None-Match") == `"primary"` {
			w.WriteHeader(304)
			return
		}
		_, _ = w.Write(fixture.Bundle)
	}))
	defer primary.Close()
	var replicaReads atomic.Int32
	replica := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replicaReads.Add(1)
		if r.Header.Get("If-None-Match") != "" {
			t.Error("primary ETag leaked to replica")
		}
		w.Header().Set("ETag", `"replica"`)
		_, _ = w.Write(fixture.Bundle)
	}))
	defer replica.Close()
	e := fixtureEvidence(t, fixture, primary.URL, replica.URL)
	appraise := fixtureAppraisal(t, fixture)
	checks := 0
	err := e.refresh(t.Context(), func(snapshot *verifier.EvidenceSnapshot, summary evidenceSummary) error {
		checks++
		if checks == 1 {
			return errors.New("required evidence is not yet at this origin")
		}
		return appraise(snapshot, summary)
	})
	if err != nil || replicaReads.Load() != 1 {
		t.Fatalf("valid but unresolved primary did not try replica: %v", err)
	}
	if err := e.refresh(t.Context(), appraise); err != nil {
		t.Fatal(err)
	}
	if err := e.refresh(t.Context(), appraise); err != nil {
		t.Fatal(err)
	}
	conditionalMu.Lock()
	defer conditionalMu.Unlock()
	if len(conditional) != 3 || conditional[0] != "" || conditional[1] != "" || conditional[2] != `"primary"` {
		t.Fatalf("conditional reads used the wrong retained representation: %q", conditional)
	}
}

func TestEvidenceBadDeliveryPreservesSnapshotWithoutExtendingValidity(t *testing.T) {
	fixture := evidenceFixture(t)
	var delivery atomic.Value
	delivery.Store(fixture.Bundle)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(delivery.Load().(json.RawMessage)) }))
	defer server.Close()
	e := fixtureEvidence(t, fixture, server.URL)
	appraise := fixtureAppraisal(t, fixture)
	if err := e.refresh(t.Context(), appraise); err != nil {
		t.Fatal(err)
	}
	snapshot := e.snapshot
	delivery.Store(json.RawMessage(`{"broken":true}`))
	if err := e.refresh(t.Context(), appraise); err == nil || e.snapshot != snapshot {
		t.Fatal("bad delivery replaced accepted evidence")
	}
	if err := appraise(snapshot, e.summary); err != nil {
		t.Fatal(err)
	}
	document := fixture.Boot.document(t)
	identity, err := snapshot.VerifyLoggedBootAt(document, fixture.Inclusion, time.UnixMilli(fixture.Now))
	if err != nil {
		t.Fatal(err)
	}
	_, err = snapshot.VerifyLoggedBootAt(document, fixture.Inclusion, time.UnixMilli(identity.ValidUntilUnixMS+1))
	if err == nil {
		t.Fatal("retained snapshot extended collateral validity")
	}
}

func TestEvidenceFetchBoundsAndCancellation(t *testing.T) {
	fixture := evidenceFixture(t)
	for _, name := range []string{"unsolicited304", "oversized", "cancel"} {
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				switch name {
				case "unsolicited304":
					w.WriteHeader(304)
				case "oversized":
					_, _ = w.Write(bytes.Repeat([]byte{' '}, evidenceBodyLimit+1))
				case "cancel":
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			e := fixtureEvidence(t, fixture, server.URL)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if name == "cancel" {
				go func() { <-started; cancel() }()
			}
			if err := e.refresh(ctx, fixtureAppraisal(t, fixture)); err == nil || e.snapshot != nil {
				t.Fatal("invalid delivery installed evidence")
			}
		})
	}
}

func TestEvidenceRetirementAppliesBeforeReplicaRecoveryDespiteIncompleteDelivery(t *testing.T) {
	fixture := evidenceFixture(t)
	var candidate map[string]json.RawMessage
	if err := json.Unmarshal(fixture.Bundle, &candidate); err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(candidate["body"], &body); err != nil {
		t.Fatal(err)
	}
	body["keys"] = fixture.RotatedKeys
	// The root validly retires the old key, but the rest of this delivery still
	// uses that key. Candidate installation fails; its retirement must remain.
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bodyBytes)
	candidate["body"] = bodyBytes
	candidate["body_sha256"], err = json.Marshal(hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	var delivery atomic.Value
	delivery.Store(fixture.Bundle)
	var rejected atomic.Bool
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(delivery.Load().(json.RawMessage)) }))
	defer primary.Close()
	replica := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !rejected.Load() {
			t.Error("replica contacted before learned retirement closed admission")
		}
		_, _ = w.Write(fixture.Bundle)
	}))
	defer replica.Close()
	e := fixtureEvidence(t, fixture, primary.URL, replica.URL)
	appraisal := fixtureAppraisal(t, fixture)
	if err := e.refresh(t.Context(), appraisal); err != nil {
		t.Fatal(err)
	}
	previous := e.snapshot
	delivery.Store(json.RawMessage(bytes))
	if err := e.refresh(t.Context(), func(snapshot *verifier.EvidenceSnapshot, summary evidenceSummary) error {
		err := appraisal(snapshot, summary)
		if err != nil {
			rejected.Store(true)
		}
		return err
	}); err == nil {
		t.Fatal("retired key remained accepted")
	}
	if !rejected.Load() || e.snapshot != previous {
		t.Fatal("incomplete retirement delivery did not retain and reject old snapshot")
	}
	if err := appraisal(previous, e.summary); err == nil {
		t.Fatal("lagging replica restored retired trust")
	}
}
