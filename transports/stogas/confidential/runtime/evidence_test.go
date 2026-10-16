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
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	verifier "github.com/StogasAI/stogas/go"
)

type bootEvidenceFixture struct {
	Root   verifier.TrustRoot `json:"root"`
	Bundle json.RawMessage    `json:"bundle"`
	// RotatedBundle makes a new online key active and retires the boot's key;
	// PrunedBundle then omits it.
	RotatedBundle json.RawMessage `json:"rotated_bundle"`
	PrunedBundle  json.RawMessage `json:"pruned_bundle"`
	// Expiring holds a copy of the first key manifest that expires while the
	// AMD collateral is still valid, verified at its own time.
	Expiring struct {
		Bundle json.RawMessage `json:"bundle"`
		Now    int64           `json:"verified_at_ms"`
	} `json:"expiring"`
	Boot      fixtureBoot     `json:"boot"`
	Inclusion json.RawMessage `json:"inclusion"`
	Now       int64           `json:"verified_at_ms"`
}

// fixtureBoot is a real logged boot whose report commits the fixture's seeded keys.
type fixtureBoot struct {
	GatewayReleaseID string `json:"gateway_release_id"`
	Report           string `json:"report"`
	ReportData       struct {
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
	e := &currentEvidence{verifier: core, client: &http.Client{}, now: func() time.Time { return time.UnixMilli(fixture.Now) }, synchronized: func() bool { return true }}
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
		if len(summary.catalogs(identity.GatewayReleaseID)) == 0 {
			return errors.New("no compatible catalog")
		}
		return nil
	}
}

func TestEvidenceReadsOriginsInOrderWithOriginScopedConditionalReads(t *testing.T) {
	fixture := evidenceFixture(t)
	var mu sync.Mutex
	conditional := map[string][]string{}
	var primaryDown atomic.Bool
	origin := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			conditional[name] = append(conditional[name], r.Header.Get("If-None-Match"))
			mu.Unlock()
			if name == "primary" && primaryDown.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			etag := `"` + name + `"`
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(304)
				return
			}
			_, _ = w.Write(fixture.Bundle)
		}))
	}
	primary, replica := origin("primary"), origin("replica")
	defer primary.Close()
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
	if err != nil {
		t.Fatalf("replica did not resolve an unresolved primary: %v", err)
	}
	snapshot := e.snapshot
	if err := e.refresh(t.Context(), appraise); err != nil {
		t.Fatal(err)
	}
	primaryDown.Store(true)
	if err := e.refresh(t.Context(), appraise); err != nil {
		t.Fatalf("replica did not replace an unavailable primary: %v", err)
	}
	if e.snapshot != snapshot {
		t.Fatal("identical bytes from another origin replaced the snapshot")
	}
	mu.Lock()
	defer mu.Unlock()
	// The replica is read only when the primary's answer fails or is not approved.
	if !slices.Equal(conditional["primary"], []string{"", `"primary"`, `"primary"`}) ||
		!slices.Equal(conditional["replica"], []string{"", `"replica"`}) {
		t.Fatalf("reads used the wrong origin or retained representation: %q", conditional)
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

func TestEvidenceRetirementOutlivesLaggingCopies(t *testing.T) {
	fixture := evidenceFixture(t)
	var candidate map[string]json.RawMessage
	if err := json.Unmarshal(fixture.Bundle, &candidate); err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(candidate["body"], &body); err != nil {
		t.Fatal(err)
	}
	var rotated struct {
		Body struct {
			Keys json.RawMessage `json:"keys"`
		} `json:"body"`
	}
	if err := json.Unmarshal(fixture.RotatedBundle, &rotated); err != nil {
		t.Fatal(err)
	}
	body["keys"] = rotated.Body.Keys
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
	retirement, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	// The replica is read only when the primary fails. Either way, a lagging copy
	// read afterwards must not restore the retired key.
	for _, retiring := range []int{0, 1} {
		t.Run([]string{"primary", "replica after primary failure"}[retiring], func(t *testing.T) {
			var deliveries [2]atomic.Value
			deliveries[0].Store(fixture.Bundle)
			deliveries[1].Store(fixture.Bundle)
			var rejected, retired atomic.Bool
			var servers [2]*httptest.Server
			for i := range servers {
				servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					// A retirement on the primary closes admission before the replica answers.
					if i == 1 && retiring == 0 && retired.Load() && !rejected.Load() {
						t.Error("replica contacted before learned retirement closed admission")
					}
					if i == 0 && retiring == 1 && retired.Load() {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					_, _ = w.Write(deliveries[i].Load().(json.RawMessage))
				}))
				defer servers[i].Close()
			}
			e := fixtureEvidence(t, fixture, servers[0].URL, servers[1].URL)
			appraisal := fixtureAppraisal(t, fixture)
			if err := e.refresh(t.Context(), appraisal); err != nil {
				t.Fatal(err)
			}
			previous := e.snapshot
			deliveries[retiring].Store(json.RawMessage(retirement))
			retired.Store(true)
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
			deliveries[retiring].Store(fixture.Bundle)
			retired.Store(false)
			if err := e.refresh(t.Context(), appraisal); err == nil {
				t.Fatal("lagging origin restored retired trust")
			}
		})
	}
}
