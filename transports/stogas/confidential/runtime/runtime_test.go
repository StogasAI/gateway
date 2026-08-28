package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
)

func lastCertificateError(loop *ControlLoop) error {
	loop.mu.RLock()
	defer loop.mu.RUnlock()
	return loop.lastCertificateError
}

func TestStartDisabledIsNoop(t *testing.T) {
	runtime, err := Start(context.Background(), stogas.ConfidentialConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if runtime != nil {
		t.Fatalf("disabled confidential runtime should be nil, got %#v", runtime)
	}
}

func TestControlDiagnosticsTrackFailureAndRecovery(t *testing.T) {
	loop := &ControlLoop{}
	startedAt := time.Now().UTC().Add(-25 * time.Millisecond)
	loop.recordHeartbeatAttempt(startedAt, context.DeadlineExceeded)

	failed := loop.Diagnostics()
	if failed.ConsecutiveFailures != 1 ||
		failed.LastAttemptAt == nil ||
		failed.LastFailureAt == nil ||
		failed.LastSuccessAt != nil ||
		failed.LastDurationMS < 0 ||
		failed.LastFailureClass != "deadline_exceeded" {
		t.Fatalf("unexpected failed heartbeat diagnostics: %#v", failed)
	}

	loop.recordHeartbeatAttempt(time.Now().UTC(), nil)
	recovered := loop.Diagnostics()
	if recovered.ConsecutiveFailures != 0 ||
		recovered.LastSuccessAt == nil ||
		recovered.LastFailureAt == nil ||
		recovered.LastFailureClass != "" {
		t.Fatalf("unexpected recovered heartbeat diagnostics: %#v", recovered)
	}
}

func TestScheduledHeartbeatRetriesOneTransientFailureImmediately(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		if call == 2 {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		writeHeartbeatResponse(t, w, strings.Repeat("9", 64), "")
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(90 * 24 * time.Hour)
	config.ControlAllowHTTP = true
	config.ControlURL = server.URL
	config.HeartbeatInterval = time.Hour
	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	if err := runtime.Control.sendScheduledHeartbeat(context.Background()); err != nil {
		t.Fatalf("scheduled heartbeat did not recover on its bounded retry: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected initial heartbeat plus failed attempt and retry, got %d calls", calls.Load())
	}
	diagnostics := runtime.Control.Diagnostics()
	if diagnostics.ConsecutiveFailures != 0 || diagnostics.LastFailureAt == nil {
		t.Fatalf("expected recovered diagnostics to retain the transient failure: %#v", diagnostics)
	}
}

func TestAuthoritativeHeartbeatRejectionRevokesAdmissionImmediately(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			writeHeartbeatResponse(t, w, strings.Repeat("9", 64), "")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Rejected confidential gateway heartbeat","reason":"release revoked"}`))
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(90 * 24 * time.Hour)
	config.ControlAllowHTTP = true
	config.ControlURL = server.URL
	config.HeartbeatInterval = time.Hour
	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	if err := runtime.Control.sendHeartbeat(context.Background()); err == nil {
		t.Fatal("expected authoritative heartbeat rejection")
	}
	result := runtime.Control.Readiness()
	if !hasReason(result.Reasons, "control admission lease is absent or expired") {
		t.Fatalf("authoritative rejection retained admission: %#v", result)
	}
	if got := runtime.Control.Diagnostics().LastFailureClass; got != "control_rejected" {
		t.Fatalf("failure class = %q, want control_rejected", got)
	}
}

func TestTransientControlFailureRetainsExistingAdmission(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			writeHeartbeatResponse(t, w, strings.Repeat("9", 64), "")
			return
		}
		http.Error(w, "temporary failure", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(90 * 24 * time.Hour)
	config.ControlAllowHTTP = true
	config.ControlURL = server.URL
	config.HeartbeatInterval = time.Hour
	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	if err := runtime.Control.sendHeartbeat(context.Background()); err == nil {
		t.Fatal("expected transient heartbeat failure")
	}
	result := runtime.Control.Readiness()
	if hasReason(result.Reasons, "control admission lease is absent or expired") {
		t.Fatalf("transient Control failure revoked admission: %#v", result)
	}
	if got := runtime.Control.Diagnostics().LastFailureClass; got != "transport" {
		t.Fatalf("failure class = %q, want transport", got)
	}
}

func TestStartLocalMockBuildsQuoteManagerAndProofService(t *testing.T) {
	config := testConfig("mock")
	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if runtime.Identity == nil || runtime.Quotes == nil || runtime.Proofs == nil {
		t.Fatalf("runtime did not initialize confidential components: %#v", runtime)
	}
	if !runtime.EntropyReady {
		t.Fatal("runtime did not mark entropy ready after startup probe")
	}
	snapshot, err := runtime.Quotes.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Payload.TLSSPKISHA256 != runtime.Identity.TLSSPKISHA256 ||
		snapshot.Payload.HPKEPublicKey != runtime.Identity.HPKEPublicKey ||
		snapshot.Payload.Ed25519PublicKey != runtime.Identity.Ed25519PublicKey ||
		!containsString(snapshot.Payload.AcceptedCertSHA256, config.ActiveCertSHA256) {
		t.Fatalf("quote payload did not bind runtime identity/config: %#v", snapshot.Payload)
	}
	activeCatalog, ok := catalog.ActiveIdentity()
	if !ok {
		t.Fatal("active catalog identity is unavailable")
	}
	if len(snapshot.Quote) == 0 {
		t.Fatal("expected initial mock quote")
	}
	output, err := runtime.Proofs.Build(context.Background(), proofhttp.Input{
		RequestBody:  []byte(`{"request":true}`),
		ResponseBody: []byte(`{"response":true}`),
		Metadata: proof.Metadata{
			RequestID: "req_1",
			CreatedAt: "2026-08-24T12:34:56.789Z",
			NodeID:    deriveCandidateNodeID(runtime.Identity),
			Catalog: proof.Catalog{
				Digest:       activeCatalog.Digest,
				Sequence:     activeCatalog.Sequence,
				SelectionIDs: []string{"author:test", "model:test", "deployment:test", "route:test", "provider:test"},
			},
			Pricing: proof.Pricing{
				Meters:            map[string]proof.Meter{},
				TotalCostUSDAtoms: "0",
			},
			Timing: proof.Timing{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.JSON) == 0 {
		t.Fatalf("proof did not use the current attested signing identity: %#v", output)
	}
	if !proof.Verify(runtime.Identity.Ed25519PublicKeyRaw, proof.PayloadFromObject(output.Object), output.Object.Proof.Signature) {
		t.Fatal("proof signature was not produced by runtime identity")
	}
}

func TestStartWithoutConfiguredCertificateQuotesProvisionalCertificate(t *testing.T) {
	config := testConfig("mock")
	config.ActiveCertSHA256 = ""
	config.AcceptedCertSHA256 = nil
	config.CertExpiresAt = time.Time{}

	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	certState := runtime.Certs.State()
	if len(certState.ActiveCertSHA256) != 64 || len(certState.AcceptedCertSHA256) != 0 {
		t.Fatalf("runtime did not create a provisional certificate state: %#v", certState)
	}
	tlsCert, ok := runtime.Certs.ActiveTLSCertificate()
	if !ok || len(tlsCert.Certificate) != 1 || identity.CertSHA256Hex(tlsCert.Certificate[0]) != certState.ActiveCertSHA256 {
		t.Fatalf("runtime did not keep provisional certificate in memory: %#v", tlsCert)
	}
	snapshot, err := runtime.Quotes.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Payload.AcceptedCertSHA256) != 0 {
		t.Fatalf("quote must not publish the provisional certificate hash: %#v", snapshot.Payload)
	}
	if snapshot.Payload.AcceptedCertSHA256 == nil {
		t.Fatal("quote must encode the empty accepted certificate set as an array")
	}
}

func TestStartFailsClosedWhenEntropyIsUnavailable(t *testing.T) {
	_, err := start(context.Background(), testConfig("mock"), func(context.Context, time.Duration) error {
		return errors.New("entropy unavailable")
	})
	if err == nil || !strings.Contains(err.Error(), "confidential entropy readiness failed") {
		t.Fatalf("expected entropy startup failure, got %v", err)
	}
}

func TestStartSEVSNPFailsClosedWithoutHardwareQuoteDevice(t *testing.T) {
	_, err := Start(context.Background(), testConfig("sev-snp"))
	if err == nil || !strings.Contains(err.Error(), "initial confidential quote refresh failed") {
		t.Fatalf("expected sev-snp startup to fail closed without hardware quote device, got %v", err)
	}
}

func TestStartSendsInitialHeartbeatAndTracksAdmissionLease(t *testing.T) {
	heartbeatCh := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if r.URL.Path != "/api/fleet/heartbeat" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		heartbeatCh <- body
		writeHeartbeatResponse(t, w, strings.Repeat("9", 64), "")
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(90 * 24 * time.Hour)
	config.ControlAllowHTTP = true
	config.ControlURL = server.URL
	config.HeartbeatInterval = time.Hour

	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	select {
	case body := <-heartbeatCh:
		if _, ok := body["chip_id"]; ok {
			t.Fatalf("heartbeat must not send host-derived chip_id: %#v", body)
		}
		if _, ok := body["region"]; ok {
			t.Fatalf("heartbeat must not send host-derived region: %#v", body)
		}
		if _, ok := body["quote"].(string); !ok {
			t.Fatalf("heartbeat did not include full quote: %#v", body)
		}
	case <-time.After(time.Second):
		t.Fatal("initial heartbeat was not sent")
	}

	if runtime.Control.NodeID() != strings.Repeat("9", 64) {
		t.Fatalf("node ID not recorded: %q", runtime.Control.NodeID())
	}
	runtime.Control.mu.RLock()
	readyUntil := runtime.Control.admissionReadyUntil
	runtime.Control.mu.RUnlock()
	if readyUntil.IsZero() {
		t.Fatal("initial heartbeat admission lease was not recorded")
	}
	if result := runtime.Control.readinessResultAt(readyUntil.Add(-time.Second)); hasReason(result.Reasons, "control admission lease is absent or expired") {
		t.Fatalf("successful startup heartbeat should admit readiness: %#v", result)
	}
	runtime.Control.recordHeartbeatError(errors.New("transient control failure"))
	if result := runtime.Control.readinessResultAt(readyUntil.Add(-time.Nanosecond)); hasReason(result.Reasons, "control admission lease is absent or expired") {
		t.Fatalf("one transient heartbeat failure should retain admission: %#v", result)
	}
	if result := runtime.Control.readinessResultAt(readyUntil); !hasReason(result.Reasons, "control admission lease is absent or expired") {
		t.Fatalf("expired admission lease should fail readiness: %#v", result)
	}

	runtime.Control.entropyReady = false
	result := runtime.Control.readinessResult()
	if !hasReason(result.Reasons, "entropy is not ready") {
		t.Fatalf("readiness did not include entropy failure: %#v", result)
	}
}

func TestLocalReadinessExpiresBeforeControlRejectsStaleQuoteEvidence(t *testing.T) {
	config := testConfig("mock")
	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	snapshot, err := runtime.Quotes.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	loop := newControlLoop(
		config,
		runtime.Identity,
		runtime.Certs,
		runtime.Quotes,
		runtime.Secrets,
		true,
	)
	if state := loop.localReadinessStateAt(snapshot.GeneratedAt.Add(localQuoteReadyWindow)); !state.QuoteForwardSafe {
		t.Fatalf("quote should remain locally forward-safe through the configured window: %#v", state)
	}
	if state := loop.localReadinessStateAt(snapshot.GeneratedAt.Add(localQuoteReadyWindow + time.Nanosecond)); state.QuoteForwardSafe {
		t.Fatalf("stale quote remained locally forward-safe: %#v", state)
	}
}

func TestRuntimeDependencyProbeFailsLocalReadiness(t *testing.T) {
	config := testConfig("mock")
	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	loop := newControlLoop(
		config,
		runtime.Identity,
		runtime.Certs,
		runtime.Quotes,
		runtime.Secrets,
		true,
	)
	loop.runtimeDependencyProbe = func(context.Context) error {
		return errors.New("database unavailable")
	}
	result := loop.localReadinessResultAt(time.Now())
	if !hasReason(result.Reasons, "runtime dependencies are unhealthy") {
		t.Fatalf("database probe failure did not fail local readiness: %#v", result)
	}
}

func TestQuoteFailureClassNeverExposesErrorText(t *testing.T) {
	if got := quoteFailureClass(errors.New("secret provider response")); got != "quote_refresh_failed" {
		t.Fatalf("quote failure class = %q, want quote_refresh_failed", got)
	}
	if got := quoteFailureClass(context.DeadlineExceeded); got != "deadline_exceeded" {
		t.Fatalf("quote deadline class = %q, want deadline_exceeded", got)
	}
}

func TestControlShutdownInstructionFailsReadinessAndSignalsOnce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"certificate_instruction":null,"node_id":"` + strings.Repeat("9", 64) + `","ok":true,"ready":false,"ready_until":null,"secrets":null,"shutdown":true}`))
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(90 * 24 * time.Hour)
	config.ControlAllowHTTP = true
	config.ControlURL = server.URL
	config.HeartbeatInterval = time.Hour
	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	select {
	case <-runtime.ShutdownRequested():
	case <-time.After(time.Second):
		t.Fatal("shutdown instruction was not delivered")
	}
	if runtime.Readiness().Ready {
		t.Fatal("draining guest remained ready")
	}
}

func TestControlLoopSubmitsCertificateCSRInstruction(t *testing.T) {
	nodeID := strings.Repeat("9", 64)
	csrCh := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case "/api/fleet/heartbeat":
			writeHeartbeatResponse(t, w, nodeID, `{"action":"request_csr","order_id":"order-1","dns_names":["Gateway.Stogas.AI","gateway.stogas.ai"],"common_name":"gateway.stogas.ai"}`)
		case "/api/fleet/cert/csr":
			csrCh <- body
			_, _ = w.Write([]byte(`{"node_id":"` + nodeID + `","ok":true,"order_id":"order-1"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(90 * 24 * time.Hour)
	config.ControlAllowHTTP = true
	config.ControlURL = server.URL
	config.HeartbeatInterval = time.Hour

	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	select {
	case body := <-csrCh:
		if body["node_id"] != nodeID ||
			body["order_id"] != "order-1" {
			t.Fatalf("unexpected CSR submission body: %#v", body)
		}
		for _, removed := range []string{"common_name", "dns_names", "tls_spki_sha256"} {
			if _, ok := body[removed]; ok {
				t.Fatalf("CSR submission included client-claimed %s: %#v", removed, body)
			}
		}
		if signature, ok := body["signature"].(string); !ok || signature == "" {
			t.Fatalf("CSR submission did not include node authorization: %#v", body)
		}
		csrEncoded, _ := body["csr_der"].(string)
		csrDER, err := base64.RawURLEncoding.DecodeString(csrEncoded)
		if err != nil {
			t.Fatalf("CSR was not base64url: %v", err)
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatal(err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("CSR signature did not verify: %v", err)
		}
		spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if identity.SHA256Hex(spki) != runtime.Identity.TLSSPKISHA256 {
			t.Fatal("CSR did not use the runtime TLS key")
		}
	case <-time.After(time.Second):
		t.Fatal("certificate CSR was not submitted")
	}
}

func TestControlLoopInstallCertificateInstructionRefreshesQuoteAndReheartbeats(t *testing.T) {
	rootCertificate, rootKey, certificateRoots := runtimeTestCertificateAuthority(t)
	nodeID := strings.Repeat("9", 64)
	var mu sync.Mutex
	var instruction string
	var heartbeatBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/fleet/heartbeat" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		heartbeatBodies = append(heartbeatBodies, body)
		nextInstruction := instruction
		instruction = ""
		mu.Unlock()
		writeHeartbeatResponse(t, w, nodeID, nextInstruction)
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(30 * 24 * time.Hour)
	config.ControlAllowHTTP = true
	config.ControlURL = server.URL
	config.HeartbeatInterval = time.Hour

	runtime, err := start(
		context.Background(),
		config,
		waitForSystemEntropy,
		startOptions{certificateRoots: certificateRoots},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	newExpiry := time.Now().UTC().Truncate(time.Second).Add(90 * 24 * time.Hour)
	chainPEM, leafDER := signedRuntimeLeaf(t, runtime.Identity, rootCertificate, rootKey, 20, newExpiry)
	newHash := identity.CertSHA256Hex(leafDER)
	instructionJSON, err := json.Marshal(map[string]any{
		"action":          "install_renewed_chain",
		"order_id":        "order-2",
		"cert_chain_pem":  string(chainPEM),
		"dns_names":       []string{"gateway.stogas.ai"},
		"new_cert_sha256": newHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	instruction = string(instructionJSON)
	before := len(heartbeatBodies)
	mu.Unlock()

	if err := runtime.Control.sendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	after := len(heartbeatBodies)
	last := heartbeatBodies[len(heartbeatBodies)-1]
	mu.Unlock()
	if after-before != 2 {
		t.Fatalf("expected instruction heartbeat plus refreshed follow-up heartbeat, got %d", after-before)
	}
	reportData, ok := last["report_data"].(map[string]any)
	if !ok {
		t.Fatalf("follow-up heartbeat missing report_data: %#v", last)
	}
	if last["active_cert_sha256"] != config.ActiveCertSHA256 {
		t.Fatalf("install instruction should not activate the new certificate: %#v", last)
	}
	accepted, ok := reportData["accepted_cert_sha256"].([]any)
	if !ok || !jsonArrayContains(accepted, newHash) {
		t.Fatalf("follow-up heartbeat did not bind the staged certificate hash: %#v", reportData)
	}
	stagedQuote := last["quote"]
	if err := lastCertificateError(runtime.Control); err != nil {
		t.Fatalf("unexpected certificate instruction error: %v", err)
	}

	activateJSON, err := json.Marshal(map[string]string{
		"action":      "activate_staged",
		"order_id":    "order-2",
		"cert_sha256": newHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	instruction = string(activateJSON)
	before = len(heartbeatBodies)
	mu.Unlock()

	if err := runtime.Control.sendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	after = len(heartbeatBodies)
	last = heartbeatBodies[len(heartbeatBodies)-1]
	mu.Unlock()
	if after-before != 2 {
		t.Fatalf("expected activate heartbeat plus immediate follow-up heartbeat, got %d", after-before)
	}
	reportData, ok = last["report_data"].(map[string]any)
	if !ok {
		t.Fatalf("follow-up heartbeat missing report_data after activation: %#v", last)
	}
	if last["active_cert_sha256"] != newHash {
		t.Fatalf("activate instruction did not switch active certificate: %#v", last)
	}
	accepted, ok = reportData["accepted_cert_sha256"].([]any)
	if !ok || !jsonArrayContains(accepted, config.ActiveCertSHA256) || !jsonArrayContains(accepted, newHash) {
		t.Fatalf("activation should preserve old and new accepted hashes: %#v", reportData)
	}
	if last["quote"] != stagedQuote {
		t.Fatalf("activation changed the quote even though report_data was unchanged")
	}

	pruneJSON, err := json.Marshal(map[string]string{
		"action":             "prune_accepted",
		"order_id":           "order-2",
		"active_cert_sha256": newHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	instruction = string(pruneJSON)
	before = len(heartbeatBodies)
	mu.Unlock()

	if err := runtime.Control.sendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	after = len(heartbeatBodies)
	last = heartbeatBodies[len(heartbeatBodies)-1]
	mu.Unlock()
	if after-before != 2 {
		t.Fatalf("expected prune heartbeat plus refreshed follow-up heartbeat, got %d", after-before)
	}
	reportData, ok = last["report_data"].(map[string]any)
	if !ok {
		t.Fatalf("follow-up heartbeat missing report_data after prune: %#v", last)
	}
	accepted, ok = reportData["accepted_cert_sha256"].([]any)
	if !ok || len(accepted) != 1 || accepted[0] != newHash {
		t.Fatalf("prune instruction did not drop old certificate hash: %#v", reportData)
	}
	if err := lastCertificateError(runtime.Control); err != nil {
		t.Fatalf("unexpected certificate instruction error after prune: %v", err)
	}

	directChainPEM, directLeafDER := signedRuntimeLeaf(t, runtime.Identity, rootCertificate, rootKey, 21, newExpiry.Add(24*time.Hour))
	directHash := identity.CertSHA256Hex(directLeafDER)
	directJSON, err := json.Marshal(map[string]any{
		"action":          "install_active_chain",
		"order_id":        "order-3",
		"cert_chain_pem":  string(directChainPEM),
		"dns_names":       []string{"gateway.stogas.ai"},
		"new_cert_sha256": directHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	instruction = string(directJSON)
	before = len(heartbeatBodies)
	mu.Unlock()

	if err := runtime.Control.sendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	after = len(heartbeatBodies)
	last = heartbeatBodies[len(heartbeatBodies)-1]
	mu.Unlock()
	if after-before != 2 {
		t.Fatalf("expected direct install heartbeat plus refreshed follow-up heartbeat, got %d", after-before)
	}
	reportData, ok = last["report_data"].(map[string]any)
	if !ok {
		t.Fatalf("follow-up heartbeat missing report_data after direct install: %#v", last)
	}
	accepted, ok = reportData["accepted_cert_sha256"].([]any)
	if last["active_cert_sha256"] != directHash || !ok || len(accepted) != 1 || accepted[0] != directHash {
		t.Fatalf("direct install should activate and prune to only the public certificate hash: %#v", reportData)
	}
	if err := lastCertificateError(runtime.Control); err != nil {
		t.Fatalf("unexpected certificate instruction error after direct install: %v", err)
	}
}

func TestStartFailsClosedWhenInitialHeartbeatIsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Rejected confidential gateway heartbeat","reason":"unknown chip_id"}`))
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(90 * 24 * time.Hour)
	config.ControlAllowHTTP = true
	config.ControlURL = server.URL
	config.HeartbeatInterval = time.Hour

	_, err := Start(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "initial confidential heartbeat failed") {
		t.Fatalf("expected initial heartbeat failure, got %v", err)
	}
}

func TestDeriveCandidateNodeIDUsesOnlyBootIdentity(t *testing.T) {
	config := testConfig("mock")
	material := &identity.Material{
		TLSSPKISHA256:    strings.Repeat("2", 64),
		HPKEPublicKey:    "aHBrZQ",
		Ed25519PublicKey: "ZWRrZXk",
	}
	first := deriveCandidateNodeID(material)
	if first != "80278d7321aa5ea1320e9a566a0f8b5225f0143c4e3de27f6bb0b12ac14faf81" {
		t.Fatalf("candidate node id differs from the verifier vector: %s", first)
	}
	config.ActiveCertSHA256 = strings.Repeat("4", 64)
	config.AcceptedCertSHA256 = []string{strings.Repeat("4", 64)}
	if renewed := deriveCandidateNodeID(material); renewed != first {
		t.Fatalf("certificate renewal changed node id: %s != %s", renewed, first)
	}

	changedIdentity := *material
	changedIdentity.HPKEPublicKey = "aHBrZTI"
	if next := deriveCandidateNodeID(&changedIdentity); next == first {
		t.Fatal("identity key change should create a different node id")
	}
}

func testConfig(mode string) stogas.ConfidentialConfig {
	return stogas.ConfidentialConfig{
		AcceptedCertSHA256: []string{strings.Repeat("c", 64)},
		ActiveCertSHA256:   strings.Repeat("c", 64),
		AttesterMode:       mode,
		Enabled:            true,
		EntropyTimeout:     time.Second,
		Environment:        "local",
		QuoteRefresh:       time.Hour,
	}
}

func hasReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func runtimeTestCertificateAuthority(t *testing.T) (*x509.Certificate, ed25519.PrivateKey, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Stogas runtime test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return certificate, privateKey, roots
}

func signedRuntimeLeaf(t *testing.T, material *identity.Material, root *x509.Certificate, rootKey ed25519.PrivateKey, serial int64, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "gateway.stogas.ai"},
		DNSNames:              []string{"gateway.stogas.ai"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &material.TLSPrivateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der
}

func writeHeartbeatResponse(t *testing.T, w http.ResponseWriter, nodeID string, certificateInstructionJSON string) {
	t.Helper()
	if certificateInstructionJSON == "" {
		certificateInstructionJSON = "null"
	}
	readyUntil := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)
	_, _ = w.Write([]byte(`{"certificate_instruction":` + certificateInstructionJSON + `,"node_id":"` + nodeID + `","ok":true,"ready":true,"ready_until":"` + readyUntil + `","secrets":null}`))
}

func jsonArrayContains(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
